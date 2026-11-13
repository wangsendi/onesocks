package service

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/engine"
	"onesocks/internal/store"
)

type subscriptionFeed struct {
	mu      sync.Mutex
	body    string
	status  int
	entered chan struct{}
	proceed chan struct{}
	server  *httptest.Server
}

func newFeed(t *testing.T, body string) *subscriptionFeed {
	t.Helper()
	f := &subscriptionFeed{body: body, status: http.StatusOK}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		body, status, entered, proceed := f.body, f.status, f.entered, f.proceed
		f.entered, f.proceed = nil, nil
		f.mu.Unlock()
		if entered != nil {
			close(entered)
			select {
			case <-proceed:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *subscriptionFeed) set(body string, status int) {
	f.mu.Lock()
	f.body, f.status = body, status
	f.mu.Unlock()
}

func (f *subscriptionFeed) blockNext() (<-chan struct{}, chan<- struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entered, f.proceed = make(chan struct{}), make(chan struct{})
	return f.entered, f.proceed
}

type fakeFactory struct {
	mu      sync.Mutex
	engines []*fakeEngine
	fail    atomic.Bool
}

func (f *fakeFactory) build(_ context.Context, nodes []engine.Node) (engine.Engine, error) {
	if f.fail.Load() {
		return nil, errors.New("fixture engine construction failed")
	}
	e := &fakeEngine{nodes: map[string]json.RawMessage{}, closed: make(chan struct{})}
	for _, node := range nodes {
		e.nodes[node.ID] = append(json.RawMessage(nil), node.Outbound...)
	}
	f.mu.Lock()
	f.engines = append(f.engines, e)
	f.mu.Unlock()
	return e, nil
}

func (f *fakeFactory) all() []*fakeEngine {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*fakeEngine(nil), f.engines...)
}

type fakeEngine struct {
	mu     sync.Mutex
	nodes  map[string]json.RawMessage
	dials  atomic.Int32
	peers  []net.Conn
	closed chan struct{}
	once   sync.Once
}

func (e *fakeEngine) DialContext(ctx context.Context, id, _, _ string) (net.Conn, error) {
	if _, ok := e.nodes[id]; !ok {
		return nil, errors.New("node not in this generation")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	select {
	case <-e.closed:
		return nil, errors.New("engine closed")
	default:
	}
	client, peer := net.Pipe()
	e.dials.Add(1)
	e.peers = append(e.peers, peer)
	go func() {
		defer peer.Close()
		_, _ = io.Copy(peer, peer)
	}()
	return client, nil
}

func (e *fakeEngine) Close() error {
	e.once.Do(func() {
		e.mu.Lock()
		defer e.mu.Unlock()
		for _, peer := range e.peers {
			_ = peer.Close()
		}
		close(e.closed)
	})
	return nil
}

func document(nodes ...map[string]any) string {
	data, err := json.Marshal(map[string]any{"outbounds": nodes})
	if err != nil {
		panic(err)
	}
	return string(data)
}

func ssNode(name string, port int) map[string]any {
	return map[string]any{"type": "shadowsocks", "tag": name, "server": "127.0.0.1", "server_port": port, "method": "aes-128-gcm", "password": "fixture-password"}
}

func newManager(t *testing.T, dir string, factory *fakeFactory, drain time.Duration) *Manager {
	t.Helper()
	m, err := New(context.Background(), Options{DataDir: dir, Factory: factory.build, FetchTimeout: time.Second, RefreshInterval: time.Hour, DrainTimeout: drain, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := m.Close(); err != nil {
			t.Error(err)
		}
	})
	return m
}

func createSubscription(t *testing.T, m *Manager, name, url string) domain.MutationResult {
	t.Helper()
	result, err := m.Create(context.Background(), domain.SubscriptionInput{Name: name, URL: url})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func nodeIDs(list domain.NodeList) []string {
	ids := make([]string, 0, len(list.Items))
	for _, n := range list.Items {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	return ids
}

func requireErrorCode(t *testing.T, err error, code string) {
	t.Helper()
	var got *domain.Error
	if !errors.As(err, &got) || got.Code != code {
		t.Fatalf("error = %v, want code %s", err, code)
	}
}

func leaseAndDial(t *testing.T, m *Manager, username string) (domain.Lease, net.Conn) {
	t.Helper()
	lease, err := m.Acquire(username)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	conn, err := lease.DialContext(context.Background(), "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	return lease, conn
}

func assertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var data [4]byte
	if _, err := io.ReadFull(conn, data[:]); err != nil || string(data[:]) != "ping" {
		t.Fatalf("echo = %q, error = %v", data, err)
	}
	_ = conn.SetDeadline(time.Time{})
}

func assertClosed(t *testing.T, e *fakeEngine) {
	t.Helper()
	select {
	case <-e.closed:
	case <-time.After(time.Second):
		t.Fatal("engine was not closed")
	}
}

func assertOpen(t *testing.T, e *fakeEngine) {
	t.Helper()
	select {
	case <-e.closed:
		t.Fatal("engine closed while an existing session still holds its lease")
	default:
	}
}

func TestSubscriptionURLFragmentsAreIgnoredForFetchAndIdentity(t *testing.T) {
	requests := make(chan string, 4)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.RequestURI
		_, _ = io.WriteString(w, document(ssNode("香港", 1001)))
	}))
	defer source.Close()
	dir := t.TempDir()
	factory := &fakeFactory{}
	m := newManager(t, dir, factory, time.Second)
	canonical := source.URL + "/sub%23route?token=a%23b%2Fc"
	sub := createSubscription(t, m, "机场A", canonical+"#GLaDOS")
	if got := <-requests; got != "/sub%23route?token=a%23b%2Fc" {
		t.Fatalf("encoded path or query changed: %q", got)
	}
	if got := m.current().Subscriptions[0].URL; got != canonical {
		t.Fatalf("saved URL = %q, want %q", got, canonical)
	}
	ids := nodeIDs(m.Nodes(""))
	_, err := m.Create(context.Background(), domain.SubscriptionInput{Name: "机场B", URL: canonical + "#另一个标签"})
	requireErrorCode(t, err, "conflict")
	labelOnly := canonical + "#Different%20Label"
	if _, err := m.Update(context.Background(), sub.Subscription.ID, domain.SubscriptionPatch{URL: &labelOnly}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-requests:
		t.Fatalf("label-only change triggered another fetch: %s", got)
	default:
	}
	changed := canonical + "&updated=1#GLaDOS"
	if _, err := m.Update(context.Background(), sub.Subscription.ID, domain.SubscriptionPatch{URL: &changed}); err != nil {
		t.Fatal(err)
	}
	if got := <-requests; got != "/sub%23route?token=a%23b%2Fc&updated=1" {
		t.Fatalf("updated fetch URL = %q", got)
	}
	if !reflect.DeepEqual(ids, nodeIDs(m.Nodes(""))) {
		t.Fatal("fragment normalization changed node identity")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	restored := newManager(t, dir, factory, time.Second)
	if got := restored.current().Subscriptions[0].URL; got != canonical+"&updated=1" {
		t.Fatalf("restored URL = %q", got)
	}
}

func TestSubscriptionURLFailuresComeFromFetch(t *testing.T) {
	m := newManager(t, t.TempDir(), &fakeFactory{}, time.Second)
	for _, raw := range []string{"", "/relative#label", "file:///tmp/sub#label", "https:///missing-host#label", "https://example.com/%zz#label"} {
		t.Run(raw, func(t *testing.T) {
			_, err := m.Create(context.Background(), domain.SubscriptionInput{Name: "A", URL: raw})
			requireErrorCode(t, err, "fetch_failed")
			if len(m.Subscriptions()) != 0 || m.Status().Generation != 0 {
				t.Fatal("failed fetch changed the subscription state")
			}
		})
	}
}

func TestLargeSubscriptionPlainAndGzip(t *testing.T) {
	payload := []byte(document(ssNode("large", 1001)) + strings.Repeat(" ", 17<<20))
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	for encoding, body := range map[string][]byte{"identity": payload, "gzip": compressed.Bytes()} {
		t.Run(encoding, func(t *testing.T) {
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", encoding)
				_, _ = w.Write(body)
			}))
			defer source.Close()
			m := newManager(t, t.TempDir(), &fakeFactory{}, time.Second)
			m.options.FetchTimeout = 10 * time.Second
			sub := createSubscription(t, m, "large", source.URL)
			if sub.Subscription.NodeCount != 1 || len(m.Nodes("").Items) != 1 {
				t.Fatal("large subscription did not retain its node")
			}
		})
	}
}

func TestParseFailureReportsSanitizedReason(t *testing.T) {
	feed := newFeed(t, document(map[string]any{"type": "unsupported-fixture", "password": "private-node-password", "tag": "private-node-name", "server": "private-node-server"}))
	m := newManager(t, t.TempDir(), &fakeFactory{}, time.Second)
	_, err := m.Create(context.Background(), domain.SubscriptionInput{Name: "A", URL: feed.server.URL})
	requireErrorCode(t, err, "parse_failed")
	if !strings.Contains(err.Error(), "entry 1") || !strings.Contains(err.Error(), "unsupported outbound protocol") {
		t.Fatalf("missing actionable parser diagnostic: %v", err)
	}
	for _, secret := range []string{"private-node-password", "private-node-name", "private-node-server"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("parse diagnostic leaked subscription data")
		}
	}
}

func TestStableNodeIdentityDeduplicationRenamingAndRestore(t *testing.T) {
	dir := t.TempDir()
	factory := &fakeFactory{}
	a := newFeed(t, document(ssNode("香港", 1000), ssNode("香港别名", 1001), ssNode("日本", 1002), ssNode("香港", 1001)))
	b := newFeed(t, document(ssNode("香港", 1001)))
	m := newManager(t, dir, factory, time.Second)
	first := createSubscription(t, m, "机场A", a.server.URL+"?token=private-token")
	second := createSubscription(t, m, "机场B", b.server.URL)
	before := m.Nodes(first.Subscription.ID)
	if len(before.Items) != 3 || len(m.Nodes("").Items) != 4 || first.Subscription.NodeCount != 3 {
		t.Fatal("same-name nodes were not replaced or different-name nodes were merged")
	}
	hongKongID := domain.NodeID(first.Subscription.ID, "香港")
	if hongKongID == m.Nodes(second.Subscription.ID).Items[0].ID {
		t.Fatal("different subscriptions share a node ID")
	}
	for _, node := range before.Items {
		if node.ID != domain.NodeID(first.Subscription.ID, strings.TrimPrefix(node.Name, "机场A-")) {
			t.Fatalf("runtime ID differs from subscription/name ID: %+v", node)
		}
	}
	var effective struct {
		Port int `json:"server_port"`
	}
	if err := json.Unmarshal(factory.all()[0].nodes[hongKongID], &effective); err != nil || effective.Port != 1001 {
		t.Fatalf("same-name last entry did not win: port=%d, error=%v", effective.Port, err)
	}
	alias, err := m.Acquire("机场A-香港别名")
	if err != nil {
		t.Fatal("different-name node with identical config not retained:", err)
	}
	_ = alias.Close()
	newName := "机场A改名"
	if _, err := m.Update(context.Background(), first.Subscription.ID, domain.SubscriptionPatch{Name: &newName}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nodeIDs(before), nodeIDs(m.Nodes(first.Subscription.ID))) {
		t.Fatal("subscription rename changed node IDs")
	}
	if _, err := m.Acquire("机场A-香港"); err == nil {
		t.Fatal("old display alias survived rename")
	}
	alias, err = m.Acquire("机场A改名-香港")
	if err != nil {
		t.Fatal("subscription rename did not publish the new display alias:", err)
	}
	_ = alias.Close()
	a.set(document(ssNode("日本", 1002), ssNode("香港别名", 1001), ssNode("香港", 1003)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), first.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(nodeIDs(before), nodeIDs(m.Nodes(first.Subscription.ID))) {
		t.Fatal("configuration change or reordering changed IDs")
	}
	engines := factory.all()
	if err := json.Unmarshal(engines[len(engines)-1].nodes[hongKongID], &effective); err != nil || effective.Port != 1003 {
		t.Fatalf("stable ID did not receive the new outbound config: port=%d, error=%v", effective.Port, err)
	}
	a.set(document(ssNode("日本", 1002), ssNode("香港别名", 1001), ssNode("香港改名", 1003)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), first.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Acquire(hongKongID); err == nil {
		t.Fatal("renamed node retained its old machine ID")
	}
	if _, err := m.Acquire("机场A改名-香港"); err == nil {
		t.Fatal("renamed node retained its old display alias")
	}
	alias, err = m.Acquire(domain.NodeID(first.Subscription.ID, "香港改名"))
	if err != nil {
		t.Fatal("renamed node did not receive its new machine ID:", err)
	}
	_ = alias.Close()
	if m.Subscriptions()[0].URL != a.server.URL+"?token=private-token" {
		t.Fatal("subscription URL was changed in the API view")
	}
	want := m.Nodes("")
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	// Restoring state does not need a successful download.
	a.set("", http.StatusServiceUnavailable)
	b.set("", http.StatusServiceUnavailable)
	restored := newManager(t, dir, &fakeFactory{}, time.Second)
	if !reflect.DeepEqual(want, restored.Nodes("")) {
		t.Fatal("restart did not restore IDs, names and generation")
	}
	alias, err = restored.Acquire("机场A改名-香港别名")
	if err != nil {
		t.Fatal("restart did not restore the independent node display alias:", err)
	}
	_ = alias.Close()
	info, err := os.Stat(filepath.Join(dir, store.Filename))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("state credentials file permission = %v, error=%v", info, err)
	}
}

func TestRefreshFailurePreservesRuntimeAndRecordsStaleStatus(t *testing.T) {
	factory := &fakeFactory{}
	f := newFeed(t, document(ssNode("node", 1001)))
	m := newManager(t, t.TempDir(), factory, time.Second)
	sub := createSubscription(t, m, "A", f.server.URL)
	want := m.Nodes("")
	_, conn := leaseAndDial(t, m, want.Items[0].ID)
	for _, tc := range []struct {
		name, body, code string
		status           int
		engineFail       bool
	}{
		{"fetch", "upstream unavailable", "fetch_failed", 503, false},
		{"empty parse", "", "parse_failed", 200, false},
		{"engine", document(ssNode("replacement", 1002)), "engine_failed", 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.set(tc.body, tc.status)
			factory.fail.Store(tc.engineFail)
			_, err := m.Refresh(context.Background(), sub.Subscription.ID)
			requireErrorCode(t, err, tc.code)
			if !reflect.DeepEqual(want, m.Nodes("")) {
				t.Fatal("failed refresh changed active nodes or generation")
			}
			info := m.Subscriptions()[0]
			if !info.Stale || info.LastError == "" || info.LastAttemptAt == nil || info.LastSuccessAt == nil {
				t.Fatal("failed refresh omitted stale/error/timestamp metadata")
			}
			persisted, err := m.store.Load(context.Background())
			if err != nil || persisted.Generation != want.Generation || len(persisted.Subscriptions) != 1 || persisted.Subscriptions[0].LastError != info.LastError {
				t.Fatalf("failure metadata was not persisted independently of the runtime generation: %v", err)
			}
			assertEcho(t, conn)
		})
	}
	factory.fail.Store(false)
	f.set(document(ssNode("replacement", 1002)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), sub.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(nodeIDs(want), nodeIDs(m.Nodes(""))) || m.Subscriptions()[0].Stale {
		t.Fatal("successful replacement did not change identity or clear stale status")
	}
}

func TestExistingSessionsSurviveRefreshAndDelete(t *testing.T) {
	factory := &fakeFactory{}
	f := newFeed(t, document(ssNode("node", 1001)))
	m := newManager(t, t.TempDir(), factory, time.Second)
	sub := createSubscription(t, m, "A", f.server.URL)
	oldID := m.Nodes("").Items[0].ID
	oldLease, oldConn := leaseAndDial(t, m, oldID)
	f.set(document(ssNode("node", 1002)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), sub.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	engines := factory.all()
	assertOpen(t, engines[0])
	assertEcho(t, oldConn)
	newID := m.Nodes("").Items[0].ID
	if oldID != newID {
		t.Fatal("connection config change replaced the name-based node ID")
	}
	newLease, newConn := leaseAndDial(t, m, oldID)
	if engines[0].dials.Load() != 1 || engines[1].dials.Load() != 1 {
		t.Fatal("new session with the same username did not use the new engine")
	}
	if err := m.Delete(context.Background(), sub.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	if len(m.Nodes("").Items) != 0 || len(m.Subscriptions()) != 0 {
		t.Fatal("deleted subscription or nodes remain visible")
	}
	if _, err := m.Acquire(newID); err == nil {
		t.Fatal("deleted node accepted a new session")
	}
	assertEcho(t, oldConn)
	assertEcho(t, newConn)
	_ = oldLease.Close()
	_ = newLease.Close()
	assertClosed(t, engines[0])
	assertClosed(t, engines[1])
}

func TestRetiredGenerationDrainDeadlineClosesConnections(t *testing.T) {
	factory := &fakeFactory{}
	f := newFeed(t, document(ssNode("node", 1001)))
	m := newManager(t, t.TempDir(), factory, 30*time.Millisecond)
	sub := createSubscription(t, m, "A", f.server.URL)
	_, conn := leaseAndDial(t, m, m.Nodes("").Items[0].ID)
	if _, err := m.Refresh(context.Background(), sub.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, factory.all()[0])
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("connection survived drain deadline")
	}
}

func TestStateWriteFailureDiscardsCandidateRuntime(t *testing.T) {
	factory := &fakeFactory{}
	dir := t.TempDir()
	f := newFeed(t, document(ssNode("node", 1001)))
	m := newManager(t, dir, factory, time.Second)
	sub := createSubscription(t, m, "A", f.server.URL)
	want := m.Nodes("")
	// Closing the database deterministically rejects writes without relying on
	// filesystem permissions, which behave differently when tests run as root.
	if err := m.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.set(document(ssNode("replacement", 1002)), http.StatusOK)
	_, err := m.Refresh(context.Background(), sub.Subscription.ID)
	requireErrorCode(t, err, "storage_failed")
	if !reflect.DeepEqual(want, m.Nodes("")) {
		t.Fatal("state write failure published candidate generation")
	}
	engines := factory.all()
	if len(engines) != 2 {
		t.Fatalf("built %d engines, want active plus discarded candidate", len(engines))
	}
	assertOpen(t, engines[0])
	assertClosed(t, engines[1])
}

func TestConcurrentRefreshThenDeleteCannotResurrectSubscription(t *testing.T) {
	factory := &fakeFactory{}
	f := newFeed(t, document(ssNode("node", 1001)))
	m := newManager(t, t.TempDir(), factory, time.Second)
	sub := createSubscription(t, m, "A", f.server.URL)
	entered, proceed := f.blockNext()
	refreshed := make(chan error, 1)
	go func() {
		_, err := m.Refresh(context.Background(), sub.Subscription.ID)
		refreshed <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach subscription fetch")
	}
	deleted := make(chan error, 1)
	go func() { deleted <- m.Delete(context.Background(), sub.Subscription.ID) }()
	close(proceed)
	if err := <-refreshed; err != nil {
		t.Fatal(err)
	}
	if err := <-deleted; err != nil {
		t.Fatal(err)
	}
	if len(m.Nodes("").Items) != 0 || len(m.Subscriptions()) != 0 {
		t.Fatal("refresh resurrected a deleted subscription")
	}
	_, err := m.Refresh(context.Background(), sub.Subscription.ID)
	requireErrorCode(t, err, "not_found")
}

func TestCloseWaitsForAllRetiredGenerations(t *testing.T) {
	factory := &fakeFactory{}
	f := newFeed(t, document(ssNode("node", 1001)))
	m := newManager(t, t.TempDir(), factory, 30*time.Millisecond)
	sub := createSubscription(t, m, "A", f.server.URL)
	_, conn := leaseAndDial(t, m, m.Nodes("").Items[0].ID)
	if _, err := m.Refresh(context.Background(), sub.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	// The active generation has no leases; the old generation still does.
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	for _, e := range factory.all() {
		select {
		case <-e.closed:
		default:
			t.Fatal("Close returned with a live retired engine")
		}
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("Close left a retired generation connection alive")
	}
	if _, err := m.Acquire(m.Nodes("").Items[0].ID); err == nil {
		t.Fatal("closed manager accepted a lease")
	}
	if m.Status().Ready {
		t.Fatal("closed manager reports ready")
	}
}
