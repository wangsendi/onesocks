package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/engine"
)

type probeEngine struct {
	dial func(context.Context, string, string, string) (net.Conn, error)
}

func (e *probeEngine) DialContext(ctx context.Context, id, network, address string) (net.Conn, error) {
	return e.dial(ctx, id, network, address)
}
func (*probeEngine) Close() error { return nil }

func newProbeManager(t *testing.T, dial func(context.Context, string, string, string) (net.Conn, error)) (*Manager, *subscriptionFeed, string) {
	t.Helper()
	feed := newFeed(t, document(ssNode("first", 1001), ssNode("second", 1002)))
	m, err := New(context.Background(), Options{
		DataDir: t.TempDir(), FetchTimeout: time.Second, RefreshInterval: time.Hour, DrainTimeout: time.Second,
		Factory: func(context.Context, []engine.Node) (engine.Engine, error) { return &probeEngine{dial: dial}, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	sub := createSubscription(t, m, "test", feed.server.URL)
	m.latencyURL = "http://latency.fixture.test/latency"
	m.ipCheckURL = "http://iplogs.fixture.test/v1/check"
	return m, feed, sub.Subscription.ID
}

func assertProbeLeaseReleased(t *testing.T, m *Manager) {
	t.Helper()
	m.mu.RLock()
	defer m.mu.RUnlock()
	m.active.mu.Lock()
	defer m.active.mu.Unlock()
	if m.active.refs != 0 || len(m.active.connections) != 0 {
		t.Fatalf("probe left leases/connections open: refs=%d connections=%d", m.active.refs, len(m.active.connections))
	}
}

func TestProbesUseSelectedLeaseAndPreserveFullIPResponse(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.fixture.invalid:9090")
	t.Setenv("HTTPS_PROXY", "http://proxy.fixture.invalid:9090")
	const ipBody = `{ "ip_info": {"ip": "203.0.113.8"}, "mode": "full", "data": {"score": 0.7, "token": "retained"} }`
	var redirects atomic.Int32
	redirect := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirects.Add(1) }))
	defer redirect.Close()
	requests := make(chan *http.Request, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- r.Clone(context.Background())
		if r.URL.Path == "/latency" {
			if r.Method != http.MethodHead {
				t.Errorf("latency method=%s", r.Method)
			}
			w.Header().Set("Location", redirect.URL)
			w.WriteHeader(http.StatusFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || string(body) != "{}" || r.Header.Get("Content-Type") != "application/json" || r.URL.RawQuery != "" {
			t.Errorf("IP request: method=%s body=%q headers=%v query=%q", r.Method, body, r.Header, r.URL.RawQuery)
		}
		_, _ = io.WriteString(w, ipBody)
	}))
	defer server.Close()
	type dial struct{ id, network, address string }
	dials := make(chan dial, 8)
	m, _, _ := newProbeManager(t, func(ctx context.Context, id, network, address string) (net.Conn, error) {
		dials <- dial{id, network, address}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	id := m.Nodes("").Items[1].ID
	latency, err := m.Probe(context.Background(), id, "latency")
	if err != nil || latency.Latency == nil || latency.Latency.Error != "" || latency.Latency.Milliseconds == nil || !latency.Latency.Reused || latency.Latency.Warning != "" || latency.Latency.CheckedAt.IsZero() {
		t.Fatalf("latency=%+v error=%v", latency.Latency, err)
	}
	first, second := <-requests, <-requests
	if first.RemoteAddr != second.RemoteAddr || len(dials) != 1 || redirects.Load() != 0 {
		t.Fatalf("HEAD rounds did not reuse one selected connection or followed redirect: first=%s second=%s dials=%d redirects=%d", first.RemoteAddr, second.RemoteAddr, len(dials), redirects.Load())
	}
	assertProbeLeaseReleased(t, m)
	if _, err := m.Probe(context.Background(), id, "latency"); err != nil {
		t.Fatal(err)
	}
	<-requests
	<-requests
	if len(dials) != 2 {
		t.Fatal("a later latency probe reused an earlier probe connection")
	}
	checked, err := m.Probe(context.Background(), id, "ip-check")
	if err != nil || checked.IPCheck == nil || checked.IPCheck.Error != "" || string(checked.IPCheck.Data) != ipBody || checked.IPCheck.CheckedAt.IsZero() {
		t.Fatalf("IP check=%+v error=%v", checked.IPCheck, err)
	}
	<-requests
	if len(dials) != 3 {
		t.Fatalf("unexpected connection count=%d", len(dials))
	}
	for range 3 {
		call := <-dials
		if call.id != id || call.network != "tcp" || !strings.HasSuffix(call.address, ".fixture.test:80") {
			t.Fatalf("dial bypassed selected lease: %+v", call)
		}
	}
	assertProbeLeaseReleased(t, m)
	checked.IPCheck.Data[0] = 'x'
	*checked.Latency.Milliseconds = -1
	cached := m.Nodes("").Items[1]
	if string(cached.IPCheck.Data) != ipBody || *cached.Latency.Milliseconds < 0 {
		t.Fatal("caller mutated cached diagnostics")
	}
}

func TestProbeDialFailuresAreCachedWithoutDirectFallback(t *testing.T) {
	var direct atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { direct.Add(1) }))
	defer target.Close()
	m, _, _ := newProbeManager(t, func(context.Context, string, string, string) (net.Conn, error) {
		return nil, errors.New("selected proxy is unavailable")
	})
	m.latencyURL, m.ipCheckURL = target.URL, target.URL
	id := m.Nodes("").Items[0].ID
	for _, kind := range []string{"latency", "ip-check"} {
		result, err := m.Probe(context.Background(), id, kind)
		if err != nil {
			t.Fatal(err)
		}
		if kind == "latency" && (result.Latency == nil || result.Latency.Milliseconds != nil || !strings.Contains(result.Latency.Error, "selected proxy is unavailable")) {
			t.Fatalf("latency failure not returned as node data: %+v", result.Latency)
		}
		if kind == "ip-check" && (result.IPCheck == nil || result.IPCheck.Data != nil || !strings.Contains(result.IPCheck.Error, "selected proxy is unavailable")) {
			t.Fatalf("IP failure not returned as node data: %+v", result.IPCheck)
		}
	}
	if direct.Load() != 0 || m.Nodes("").Items[0].IPCheck == nil || m.Nodes("").Items[0].Latency == nil {
		t.Fatal("proxy failure fell back to direct or was not cached")
	}
	_, err := m.Probe(context.Background(), "missing", "latency")
	requireErrorCode(t, err, "not_found")
	_, err = m.Probe(context.Background(), id, "invalid")
	requireErrorCode(t, err, "invalid_input")
	assertProbeLeaseReleased(t, m)
}

func TestLatencyConnectionCloseFallbackAndSecondRoundFailure(t *testing.T) {
	for _, closeFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "connection close fallback", false: "second round fails"}[closeFirst], func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				count := requests.Add(1)
				if count == 1 {
					if closeFirst {
						w.Header().Set("Connection", "close")
					}
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if count == 2 {
					conn, _, _ := w.(http.Hijacker).Hijack()
					_ = conn.Close()
					return
				}
				// A successful automatic retry must not hide the second
				// round's connection failure.
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			m, _, _ := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			})
			result, err := m.Probe(context.Background(), m.Nodes("").Items[0].ID, "latency")
			if err != nil || result.Latency == nil {
				t.Fatalf("probe: %+v %v", result, err)
			}
			if closeFirst {
				if result.Latency.Milliseconds == nil || result.Latency.Reused || result.Latency.Warning == "" || result.Latency.Error != "" || requests.Load() != 1 {
					t.Fatalf("fallback result=%+v requests=%d", result.Latency, requests.Load())
				}
			} else if result.Latency.Error == "" || result.Latency.Milliseconds != nil {
				t.Fatalf("first round was incorrectly used after second failed: %+v", result.Latency)
			}
			assertProbeLeaseReleased(t, m)
		})
	}
}

func TestIPCheckPreservesUpstreamErrorAndRetryAfter(t *testing.T) {
	const body = `{"error":"rate limit exceeded","mode":"fast"}`
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	m, _, _ := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	result, err := m.Probe(context.Background(), m.Nodes("").Items[0].ID, "ip-check")
	if err != nil || result.IPCheck == nil || string(result.IPCheck.Data) != body || !strings.Contains(result.IPCheck.Error, "rate limit exceeded") || !strings.Contains(result.IPCheck.Error, "Retry-After: 60") || requests.Load() != 1 {
		t.Fatalf("upstream error lost or retried: %+v error=%v requests=%d", result.IPCheck, err, requests.Load())
	}
}

func TestIPCheckRejectsInvalidSuccessfulResponses(t *testing.T) {
	for _, body := range []string{`not json`, `{}`, `{"ip_info":{"ip":"invalid"}}`, `{"error":"upstream failed"}`} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			m, _, _ := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			})
			result, err := m.Probe(context.Background(), m.Nodes("").Items[0].ID, "ip-check")
			if err != nil || result.IPCheck == nil || result.IPCheck.Error == "" {
				t.Fatalf("malformed success accepted: %+v error=%v", result.IPCheck, err)
			}
			if body != "not json" && string(result.IPCheck.Data) != body {
				t.Fatal("valid JSON was not preserved despite missing IP")
			}
		})
	}
}

func TestProbeCancellationReleasesConnectionsAndCachesFailure(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
	}))
	defer server.Close()
	defer close(release)
	m, _, _ := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	id := m.Nodes("").Items[0].ID
	go func() { _, err := m.Probe(ctx, id, "ip-check"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter controlled server")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("probe did not respect request cancellation")
	}
	if result := m.Nodes("").Items[0].IPCheck; result == nil || !strings.Contains(result.Error, "context canceled") {
		t.Fatalf("cancellation failure not cached: %+v", result)
	}
	assertProbeLeaseReleased(t, m)
}

func TestProbeCacheTracksOutboundIdentityAndRejectsStaleCompletion(t *testing.T) {
	entered, release := make(chan struct{}, 4), make(chan struct{})
	var block atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if block.Load() {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, `{"ip_info":{"ip":"203.0.113.9"}}`)
	}))
	defer server.Close()
	m, feed, subID := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	id := m.Nodes("").Items[0].ID
	result, err := m.Probe(context.Background(), id, "ip-check")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh(context.Background(), subID); err != nil || !bytes.Equal(m.Nodes("").Items[0].IPCheck.Data, result.IPCheck.Data) {
		t.Fatalf("unchanged refresh lost probe: %v", err)
	}
	block.Store(true)
	done := make(chan error, 1)
	go func() { _, err := m.Probe(context.Background(), id, "ip-check"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter controlled server")
	}
	_, err = m.Probe(context.Background(), id, "ip-check")
	requireErrorCode(t, err, "conflict")
	feed.set(document(ssNode("first", 2001), ssNode("second", 1002)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), subID); err != nil {
		t.Fatal(err)
	}
	if m.Nodes("").Items[0].IPCheck != nil {
		t.Fatal("changed outbound retained old diagnostics")
	}
	// Even changing back to the same JSON must not resurrect the in-flight
	// result from the previous configuration's lifetime.
	feed.set(document(ssNode("first", 1001), ssNode("second", 1002)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), subID); err != nil {
		t.Fatal(err)
	}
	close(release)
	requireErrorCode(t, <-done, "conflict")
	if m.Nodes("").Items[0].IPCheck != nil {
		t.Fatal("stale in-flight probe was attached to a newer node configuration")
	}
	stored, err := m.store.LoadDiagnostics(context.Background())
	if err != nil || stored[id].IPCheck != nil {
		t.Fatalf("stale in-flight probe was persisted: %+v error=%v", stored[id], err)
	}
	block.Store(false)
	if _, err := m.Probe(context.Background(), id, "ip-check"); err != nil {
		t.Fatal(err)
	}
	feed.set(document(ssNode("second", 1002)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), subID); err != nil {
		t.Fatal(err)
	}
	feed.set(document(ssNode("first", 1001), ssNode("second", 1002)), http.StatusOK)
	if _, err := m.Refresh(context.Background(), subID); err != nil || m.Nodes("").Items[0].IPCheck != nil {
		t.Fatalf("removed/re-added node retained diagnostics: %v", err)
	}
	stored, err = m.store.LoadDiagnostics(context.Background())
	if err != nil || stored[id].IPCheck != nil {
		t.Fatalf("removed/re-added node retained stored diagnostics: %+v error=%v", stored[id], err)
	}
}

func TestProbeResultsAndFailuresSurviveManagerRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_, _ = io.WriteString(w, `{"ip_info":{"ip":"203.0.113.8"},"mode":"full","other":{"retained":true}}`)
	}))
	defer server.Close()
	var fail atomic.Bool
	m, feed, subID := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
		if fail.Load() {
			return nil, errors.New("selected proxy is unavailable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	for i, node := range m.Nodes("").Items {
		fail.Store(i == 1)
		for _, kind := range []string{"latency", "ip-check"} {
			if _, err := m.Probe(context.Background(), node.ID, kind); err != nil {
				t.Fatal(err)
			}
		}
	}
	want := m.Nodes("")
	if _, err := m.Refresh(context.Background(), subID); err != nil || !reflect.DeepEqual(want.Items, m.Nodes("").Items) {
		t.Fatalf("refresh lost stored diagnostics: %v", err)
	}
	want = m.Nodes("")
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(context.Background(), m.options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	if got := restarted.Nodes(""); !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostics changed across restart: got=%+v want=%+v", got, want)
	}
	feed.set(document(ssNode("first", 2001), ssNode("second", 2002)), http.StatusOK)
	requested, proceed := feed.blockNext()
	close(proceed)
	restarted.Start()
	select {
	case <-requested:
		t.Fatal("restart refreshed a subscription before its scheduled time")
	case <-time.After(1100 * time.Millisecond):
	}
	if got := restarted.Nodes(""); !reflect.DeepEqual(got, want) {
		t.Fatal("starting the scheduler changed saved nodes or diagnostics")
	}
	sub := restarted.Subscriptions()[0]
	interval, err := time.ParseDuration(sub.RefreshInterval)
	if err != nil {
		t.Fatal(err)
	}
	restarted.refreshDue(sub.LastAttemptAt.Add(interval))
	select {
	case <-requested:
	default:
		t.Fatal("subscription did not refresh when its saved interval elapsed")
	}
	if got := restarted.Nodes(""); got.Generation != want.Generation+1 || domain.EqualOutbound(got.Items[0].Outbound, want.Items[0].Outbound) {
		t.Fatal("scheduled refresh did not publish updated nodes")
	}
}

func TestInFlightProbeSurvivesEquivalentOutboundRefresh(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-release
		_, _ = io.WriteString(w, `{"ip_info":{"ip":"203.0.113.9"}}`)
	}))
	defer server.Close()
	m, _, subID := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	id := m.Nodes("").Items[0].ID
	done := make(chan error, 1)
	go func() { _, err := m.Probe(context.Background(), id, "ip-check"); done <- err }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("probe did not enter controlled server")
	}
	state := m.current()
	state.Subscriptions[0].Nodes = append([]domain.NodeSpec(nil), state.Subscriptions[0].Nodes...)
	state.Subscriptions[0].Nodes[0].Outbound = json.RawMessage(` {"type":"shadowsocks", "server_port":1001, "server":"127.0.0.1", "password":"fixture-password", "method":"aes-128-gcm"} `)
	if err := m.commit(context.Background(), state, subID); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("equivalent configuration invalidated in-flight probe: %v", err)
	}
	stored, err := m.store.LoadDiagnostics(context.Background())
	if err != nil || stored[id].IPCheck == nil || m.Nodes("").Items[0].IPCheck == nil {
		t.Fatalf("equivalent refresh did not retain and persist result: %+v %v", stored[id], err)
	}
}

func TestProbePersistenceFailureIsReturnedWithoutReplacingCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"ip_info":{"ip":"203.0.113.8"}}`)
	}))
	defer server.Close()
	m, _, _ := newProbeManager(t, func(ctx context.Context, _ string, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	})
	id := m.Nodes("").Items[0].ID
	before, err := m.Probe(context.Background(), id, "ip-check")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.Close(); err != nil {
		t.Fatal(err)
	}
	_, err = m.Probe(context.Background(), id, "ip-check")
	requireErrorCode(t, err, "storage_failed")
	if !strings.Contains(err.Error(), "could not persist node probe") || !reflect.DeepEqual(before.IPCheck, m.Nodes("").Items[0].IPCheck) {
		t.Fatalf("write failure was hidden or replaced in-memory result: %v", err)
	}
}
