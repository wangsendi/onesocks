package service

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/engine"
	"onesocks/internal/store"
)

type Options struct {
	DataDir           string
	FetchTimeout      time.Duration
	RefreshInterval   time.Duration
	DrainTimeout      time.Duration
	OutboundInterface string
	Factory           engine.Factory
	Version           string
}

type Manager struct {
	mu          sync.RWMutex
	updates     chan struct{}
	state       store.State
	active      *generation
	diagnostics map[string]*nodeDiagnostics
	latencyURL  string
	ipCheckURL  string
	generations map[*generation]struct{}
	closed      bool
	updating    atomic.Bool
	options     Options
	store       *store.Store
	client      *http.Client
	started     time.Time
	ctx         context.Context
	cancel      context.CancelFunc
	background  sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
}

func New(ctx context.Context, options Options) (_ *Manager, err error) {
	if options.Factory == nil {
		return nil, errors.New("missing engine factory")
	}
	if options.FetchTimeout <= 0 || options.DrainTimeout <= 0 || options.RefreshInterval <= 0 {
		return nil, errors.New("invalid service limits")
	}
	database, err := store.Open(filepath.Join(options.DataDir, store.Filename))
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer func() {
		if err != nil {
			cancel()
			_ = database.Close()
		}
	}()
	m := &Manager{options: options, store: database, started: time.Now(), ctx: ctx, cancel: cancel, updates: make(chan struct{}, 1), generations: make(map[*generation]struct{}), latencyURL: defaultLatencyURL, ipCheckURL: defaultIPCheckURL}
	m.state, err = database.Load(ctx)
	if err != nil {
		return nil, err
	}
	diagnostics, err := database.LoadDiagnostics(ctx)
	if err != nil {
		return nil, fmt.Errorf("restore node diagnostics: %w", err)
	}
	transport := newSubscriptionTransport(options)
	m.client = &http.Client{Transport: transport}
	g, err := m.build(m.state)
	if err != nil {
		return nil, fmt.Errorf("restore runtime failed: %w", err)
	}
	m.active = g
	m.reconcileDiagnostics(g.nodes)
	for id, result := range diagnostics {
		if state := m.diagnostics[id]; state != nil {
			state.latency, state.ipCheck = result.Latency, result.IPCheck
		}
	}
	m.track(g)
	return m, nil
}

// track is called before a generation is published, under the update lock.
func (m *Manager) track(g *generation) {
	m.generations[g] = struct{}{}
	g.onClose = func() {
		m.mu.Lock()
		delete(m.generations, g)
		m.mu.Unlock()
	}
}

func coded(code, message string) error { return &domain.Error{Code: code, Message: message} }

func (m *Manager) begin(ctx context.Context) error {
	select {
	case m.updates <- struct{}{}:
	case <-ctx.Done():
		return coded("canceled", "request canceled")
	case <-m.ctx.Done():
		return coded("closed", "service closed")
	}
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		<-m.updates
		return coded("closed", "service closed")
	}
	m.updating.Store(true)
	return nil
}
func (m *Manager) end() { m.updating.Store(false); <-m.updates }

func (m *Manager) current() store.State {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := m.state
	s.Subscriptions = slices.Clone(s.Subscriptions)
	return s
}

func find(s store.State, id string) int {
	return slices.IndexFunc(s.Subscriptions, func(sub store.Subscription) bool { return sub.ID == id })
}

func (m *Manager) commit(ctx context.Context, s store.State, changedID string) error {
	if ctx.Err() != nil || m.ctx.Err() != nil {
		return coded("canceled", "request canceled")
	}
	g, err := m.build(s)
	if err != nil {
		return coded("engine_failed", "could not construct subscription outbounds: "+err.Error())
	}
	if ctx.Err() != nil || m.ctx.Err() != nil {
		g.close()
		return coded("canceled", "request canceled")
	}
	s.Generation++
	if i := find(s, changedID); i >= 0 {
		err = m.store.Put(ctx, s.Generation, s.Subscriptions[i])
	} else {
		err = m.store.Delete(ctx, s.Generation, changedID)
	}
	if err != nil {
		g.close()
		return coded("storage_failed", "could not persist subscription state: "+err.Error())
	}
	m.mu.Lock()
	old := m.active
	m.track(g)
	m.reconcileDiagnostics(g.nodes)
	m.active = g
	m.state = s
	m.mu.Unlock()
	old.retire(m.options.DrainTimeout)
	return nil
}

func (m *Manager) build(s store.State) (*generation, error) {
	ctx, cancel := context.WithCancel(m.ctx)
	g := &generation{ctx: ctx, cancel: cancel, aliases: map[string]string{}, connections: map[*trackedConn]struct{}{}, done: make(chan struct{}), nodes: []domain.NodeInfo{}}
	nodes := []engine.Node{}
	alias := func(name, id string) {
		if name == "" || len(name) > 255 {
			return
		}
		if old, ok := g.aliases[name]; ok && old != id {
			g.aliases[name] = ""
		} else if !ok {
			g.aliases[name] = id
		}
	}
	for _, sub := range s.Subscriptions {
		for _, spec := range sub.Nodes {
			var outbound struct {
				Type string `json:"type"`
			}
			if err := json.Unmarshal(spec.Outbound, &outbound); err != nil {
				cancel()
				return nil, err
			}
			id := domain.NodeID(sub.ID, spec.Name)
			name := sub.Name + "-" + spec.Name
			alias(name, id)
			nodes = append(nodes, engine.Node{ID: id, Outbound: spec.Outbound})
			g.nodes = append(g.nodes, domain.NodeInfo{ID: id, Username: id, Name: name, Protocol: outbound.Type, SubscriptionID: sub.ID, Health: "unknown", Outbound: spec.Outbound})
		}
	}
	// Machine IDs take precedence over display aliases.
	for _, node := range g.nodes {
		g.aliases[node.ID] = node.ID
	}
	slices.SortFunc(g.nodes, func(a, b domain.NodeInfo) int { return cmp.Compare(a.Name, b.Name) })
	if len(nodes) > 0 {
		var err error
		g.engine, err = m.options.Factory(ctx, nodes)
		if err != nil {
			cancel()
			return nil, err
		}
	}
	return g, nil
}

func (m *Manager) Acquire(username string) (domain.Lease, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return nil, coded("closed", "service closed")
	}
	id, ok := m.active.aliases[username]
	if !ok || id == "" {
		return nil, coded("not_found", "unknown or ambiguous node username")
	}
	return m.active.acquire(id)
}

func (m *Manager) Nodes(subscriptionID string) domain.NodeList {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := domain.NodeList{Items: []domain.NodeInfo{}, Generation: m.state.Generation}
	for _, n := range m.active.nodes {
		if subscriptionID == "" || n.SubscriptionID == subscriptionID {
			list.Items = append(list.Items, m.nodeInfo(n))
		}
	}
	return list
}

func (m *Manager) Status() domain.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return domain.Status{Version: m.options.Version, UptimeSeconds: int64(time.Since(m.started).Seconds()), NodeCount: len(m.active.nodes), SubscriptionCount: len(m.state.Subscriptions), Generation: m.state.Generation, Ready: !m.closed && len(m.active.nodes) > 0, Updating: m.updating.Load()}
}

func (m *Manager) Close() error {
	m.closeOnce.Do(func() {
		m.mu.Lock()
		m.closed = true
		m.mu.Unlock()
		m.cancel()
		m.updates <- struct{}{}
		m.mu.Lock()
		generations := make([]*generation, 0, len(m.generations))
		for g := range m.generations {
			generations = append(generations, g)
		}
		m.mu.Unlock()
		<-m.updates
		m.background.Wait()
		m.client.CloseIdleConnections()
		for _, g := range generations {
			g.retire(m.options.DrainTimeout)
		}
		for _, g := range generations {
			<-g.done
		}
		m.closeErr = m.store.Close()
	})
	return m.closeErr
}
