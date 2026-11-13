package service

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/engine"
	"onesocks/internal/parser"
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

func (m *Manager) prepare(sub store.Subscription) (store.Subscription, error) {
	if strings.TrimSpace(sub.Name) == "" {
		return sub, coded("invalid_input", "subscription name must not be empty")
	}
	// Normalize labels for deduplication when possible, but let the HTTP client
	// attempt the URL and report any unsupported or malformed URL as fetch_failed.
	if u, err := url.Parse(sub.URL); err == nil {
		u.Fragment, u.RawFragment = "", ""
		sub.URL = u.String()
	}
	if sub.RefreshInterval == "" {
		sub.RefreshInterval = m.options.RefreshInterval.String()
	}
	if d, err := time.ParseDuration(sub.RefreshInterval); err != nil || d <= 0 {
		return sub, coded("invalid_input", "refresh_interval must be a positive duration")
	}
	return sub, nil
}

func checkConflict(s store.State, sub store.Subscription) error {
	for _, other := range s.Subscriptions {
		if other.ID != sub.ID && (other.Name == sub.Name || other.URL == sub.URL) {
			return coded("conflict", "subscription name or URL already exists")
		}
	}
	return nil
}

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
	s.Subscriptions = append([]store.Subscription(nil), s.Subscriptions...)
	return s
}

func find(s store.State, id string) int {
	for i := range s.Subscriptions {
		if s.Subscriptions[i].ID == id {
			return i
		}
	}
	return -1
}

func (m *Manager) Create(ctx context.Context, in domain.SubscriptionInput) (domain.MutationResult, error) {
	var id [10]byte
	if _, err := rand.Read(id[:]); err != nil {
		return domain.MutationResult{}, coded("storage_failed", "could not allocate subscription ID")
	}
	if in.Name == "" {
		in.Name = "subscription-" + hex.EncodeToString(id[:4])
	}
	sub, err := m.prepare(store.Subscription{ID: "s_" + hex.EncodeToString(id[:]), Name: in.Name, URL: in.URL, RefreshInterval: in.RefreshInterval})
	if err != nil {
		return domain.MutationResult{}, err
	}
	if err := m.begin(ctx); err != nil {
		return domain.MutationResult{}, err
	}
	defer m.end()
	s := m.current()
	if err := checkConflict(s, sub); err != nil {
		return domain.MutationResult{}, err
	}
	warnings, err := m.fetch(ctx, &sub)
	if err != nil {
		return domain.MutationResult{}, err
	}
	s.Subscriptions = append(s.Subscriptions, sub)
	if err = m.commit(ctx, s, sub.ID); err != nil {
		return domain.MutationResult{}, err
	}
	return domain.MutationResult{Subscription: info(sub), Generation: s.Generation + 1, Warnings: warnings}, nil
}

func (m *Manager) Update(ctx context.Context, id string, p domain.SubscriptionPatch) (domain.MutationResult, error) {
	if err := m.begin(ctx); err != nil {
		return domain.MutationResult{}, err
	}
	defer m.end()
	s := m.current()
	i := find(s, id)
	if i < 0 {
		return domain.MutationResult{}, coded("not_found", "subscription not found")
	}
	sub := s.Subscriptions[i]
	if p.Name != nil {
		sub.Name = *p.Name
	}
	if p.URL != nil {
		sub.URL = *p.URL
	}
	if p.RefreshInterval != nil {
		sub.RefreshInterval = *p.RefreshInterval
	}
	sub, err := m.prepare(sub)
	if err != nil {
		return domain.MutationResult{}, err
	}
	if err := checkConflict(s, sub); err != nil {
		return domain.MutationResult{}, err
	}
	var warnings []string
	if sub.URL != s.Subscriptions[i].URL {
		warnings, err = m.fetch(ctx, &sub)
		if err != nil {
			return domain.MutationResult{}, err
		}
	}
	s.Subscriptions[i] = sub
	if err := m.commit(ctx, s, id); err != nil {
		return domain.MutationResult{}, err
	}
	return domain.MutationResult{Subscription: info(sub), Generation: s.Generation + 1, Warnings: warnings}, nil
}

func (m *Manager) Refresh(ctx context.Context, id string) (domain.MutationResult, error) {
	if err := m.begin(ctx); err != nil {
		return domain.MutationResult{}, err
	}
	defer m.end()
	s := m.current()
	i := find(s, id)
	if i < 0 {
		return domain.MutationResult{}, coded("not_found", "subscription not found")
	}
	sub := s.Subscriptions[i]
	warnings, err := m.fetch(ctx, &sub)
	if err != nil {
		m.recordFailure(s, i, err)
		return domain.MutationResult{}, err
	}
	s.Subscriptions[i] = sub
	if err = m.commit(ctx, s, id); err != nil {
		m.recordFailure(m.current(), i, err)
		return domain.MutationResult{}, err
	}
	return domain.MutationResult{Subscription: info(sub), Generation: s.Generation + 1, Warnings: warnings}, nil
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	if err := m.begin(ctx); err != nil {
		return err
	}
	defer m.end()
	s := m.current()
	i := find(s, id)
	if i < 0 {
		return coded("not_found", "subscription not found")
	}
	s.Subscriptions = append(s.Subscriptions[:i], s.Subscriptions[i+1:]...)
	return m.commit(ctx, s, id)
}

func (m *Manager) fetch(ctx context.Context, sub *store.Subscription) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.options.FetchTimeout)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, coded("fetch_failed", "could not create subscription request: "+err.Error())
	}
	req.Header.Set("User-Agent", "OneSocks/"+m.options.Version)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, coded("fetch_failed", "subscription fetch failed: "+err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, coded("fetch_failed", fmt.Sprintf("subscription returned HTTP %d", resp.StatusCode))
	}
	var reader io.Reader = resp.Body
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "", "identity":
	case "gzip":
		gz, err := gzip.NewReader(reader)
		if err != nil {
			return nil, coded("fetch_failed", "invalid gzip subscription: "+err.Error())
		}
		defer gz.Close()
		reader = gz
	default:
		return nil, coded("fetch_failed", "unsupported subscription content encoding")
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, coded("fetch_failed", "could not read subscription body: "+err.Error())
	}
	result, err := parser.Parse(data)
	if err != nil {
		message := err.Error()
		if len(result.Warnings) > 0 {
			message += "; " + strings.Join(result.Warnings, "; ")
		}
		return nil, coded("parse_failed", message)
	}
	now := time.Now().UTC()
	sub.Nodes = domain.UniqueNodes(result.Nodes)
	sub.LastAttemptAt = &now
	sub.LastSuccessAt = &now
	sub.LastError = ""
	return result.Warnings, nil
}

func (m *Manager) recordFailure(s store.State, i int, err error) {
	now := time.Now().UTC()
	s.Subscriptions[i].LastAttemptAt = &now
	s.Subscriptions[i].LastError = err.Error()
	if err := m.store.RecordFailure(m.ctx, s.Subscriptions[i].ID, now, err.Error()); err != nil {
		slog.Warn("could not persist refresh failure", "subscription_id", s.Subscriptions[i].ID, "error", err)
	}
	m.mu.Lock()
	m.state = s
	m.mu.Unlock()
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
	sort.Slice(g.nodes, func(i, j int) bool { return g.nodes[i].Name < g.nodes[j].Name })
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

func info(sub store.Subscription) domain.SubscriptionInfo {
	return domain.SubscriptionInfo{ID: sub.ID, Name: sub.Name, URL: sub.URL, RefreshInterval: sub.RefreshInterval, LastAttemptAt: sub.LastAttemptAt, LastSuccessAt: sub.LastSuccessAt, LastError: sub.LastError, NodeCount: len(sub.Nodes), Stale: sub.LastError != ""}
}

func (m *Manager) Subscriptions() []domain.SubscriptionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]domain.SubscriptionInfo, 0, len(m.state.Subscriptions))
	for _, s := range m.state.Subscriptions {
		items = append(items, info(s))
	}
	return items
}

func (m *Manager) Status() domain.Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return domain.Status{Version: m.options.Version, UptimeSeconds: int64(time.Since(m.started).Seconds()), NodeCount: len(m.active.nodes), SubscriptionCount: len(m.state.Subscriptions), Generation: m.state.Generation, Ready: !m.closed && len(m.active.nodes) > 0, Updating: m.updating.Load()}
}

// Start refreshes cached subscriptions on startup, then checks due times.
func (m *Manager) Start() {
	m.background.Go(func() {
		m.refreshDue(time.Time{})
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case now := <-ticker.C:
				m.refreshDue(now)
			}
		}
	})
}

// A zero time refreshes every cached subscription on startup.
func (m *Manager) refreshDue(now time.Time) {
	for _, sub := range m.current().Subscriptions {
		interval, err := time.ParseDuration(sub.RefreshInterval)
		if err != nil {
			interval = m.options.RefreshInterval
		}
		if !now.IsZero() && sub.LastAttemptAt != nil && now.Sub(*sub.LastAttemptAt) < interval {
			continue
		}
		if _, err := m.Refresh(m.ctx, sub.ID); err != nil && m.ctx.Err() == nil {
			slog.Warn("subscription refresh failed", "subscription_id", sub.ID, "error", err.Error())
		}
	}
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
