package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"onesocks/internal/config"
	"onesocks/internal/domain"
)

type fakeService struct {
	createCalls int
	lastInput   domain.SubscriptionInput
	lastPatch   domain.SubscriptionPatch
	lastID      string
	filter      string
	probeKind   string
	err         error
	lastContext context.Context
}

func (f *fakeService) Nodes(id string) domain.NodeList {
	f.filter = id
	return domain.NodeList{Items: []domain.NodeInfo{{ID: "n_1", Username: "n_1", Name: "test", Health: "unknown"}}, Generation: 3}
}
func (f *fakeService) Subscriptions() []domain.SubscriptionInfo { return nil }
func (f *fakeService) Create(ctx context.Context, input domain.SubscriptionInput) (domain.MutationResult, error) {
	f.createCalls++
	f.lastContext = ctx
	f.lastInput = input
	return domain.MutationResult{Subscription: domain.SubscriptionInfo{ID: "s_1", Name: input.Name}}, f.err
}
func (f *fakeService) Update(ctx context.Context, id string, input domain.SubscriptionPatch) (domain.MutationResult, error) {
	f.lastContext = ctx
	f.lastID = id
	f.lastPatch = input
	return domain.MutationResult{}, f.err
}
func (f *fakeService) Refresh(ctx context.Context, id string) (domain.MutationResult, error) {
	f.lastContext = ctx
	f.lastID = id
	return domain.MutationResult{}, f.err
}
func (f *fakeService) Delete(ctx context.Context, id string) error {
	f.lastContext = ctx
	f.lastID = id
	return f.err
}
func (f *fakeService) Status() domain.Status { return domain.Status{Version: "test"} }
func (f *fakeService) Probe(ctx context.Context, id, kind string) (domain.NodeInfo, error) {
	f.lastContext = ctx
	f.lastID = id
	f.probeKind = kind
	return domain.NodeInfo{ID: id, IPCheck: &domain.IPCheckResult{Data: json.RawMessage(`{"ip":"203.0.113.8","full":"retained"}`)}}, f.err
}

func request(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAuthenticationRequiredBeforeMutation(t *testing.T) {
	f := &fakeService{}
	h := New(f, config.Config{APIToken: "secret"})
	for _, auth := range []string{"", "Bearer wrong", "bearer secret", "Basic secret"} {
		w := request(h, http.MethodPost, "/api/subscriptions", `{"name":"x","url":"https://example.com"}`, auth)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("auth %q: status %d", auth, w.Code)
		}
	}
	if f.createCalls != 0 {
		t.Fatal("unauthorized request reached service")
	}
	w := request(h, http.MethodGet, "/api/status", "", "Bearer secret")
	if w.Code != http.StatusOK {
		t.Fatalf("valid token: %d", w.Code)
	}
}

func TestConfigReturnsOriginalValuesWithAPIAuthentication(t *testing.T) {
	for _, token := range []string{"", "admin-token"} {
		cfg := config.Config{SOCKSListen: "127.0.0.1:10801", APIListen: "127.0.0.1:10802", DataDir: "/tmp/onesocks", SOCKSPassword: "p@ss:'\"$x", APIToken: token, OutboundInterface: "eth0"}
		h := New(&fakeService{}, cfg)
		if token != "" {
			w := request(h, http.MethodGet, "/api/config", "", "")
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("unauthenticated config: status %d", w.Code)
			}
		}
		w := request(h, http.MethodGet, "/api/config", "", "Bearer "+token)
		var got config.Config
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || got != cfg {
			t.Fatalf("config values changed: status %d, error %v, body %s", w.Code, err, w.Body.String())
		}
	}
}

func TestNodeProbeRoutesRequireAuthenticationAndReturnUpdatedNode(t *testing.T) {
	for _, kind := range []string{"latency", "ip-check"} {
		f := &fakeService{}
		h := New(f, config.Config{APIToken: "secret"})
		path := "/api/nodes/n_selected/" + kind
		unauthorized := request(h, http.MethodPost, path, "", "Bearer wrong")
		if unauthorized.Code != http.StatusUnauthorized || f.lastContext != nil {
			t.Fatalf("unauthorized %s reached probe service: %d", kind, unauthorized.Code)
		}
		response := request(h, http.MethodPost, path, "", "Bearer secret")
		var node domain.NodeInfo
		if err := json.Unmarshal(response.Body.Bytes(), &node); err != nil || response.Code != http.StatusOK || node.ID != "n_selected" || f.lastID != "n_selected" || f.probeKind != kind || node.IPCheck == nil || string(node.IPCheck.Data) != `{"ip":"203.0.113.8","full":"retained"}` {
			t.Fatalf("probe route %s: status=%d node=%+v error=%v", kind, response.Code, node, err)
		}
		for _, failure := range []struct {
			code   string
			status int
		}{{"not_found", http.StatusNotFound}, {"conflict", http.StatusConflict}, {"invalid_input", http.StatusBadRequest}} {
			f.err = &domain.Error{Code: failure.code, Message: "probe failed"}
			response = request(h, http.MethodPost, path, "", "Bearer secret")
			if response.Code != failure.status || !strings.Contains(response.Body.String(), failure.code) {
				t.Fatalf("probe error %s: status=%d body=%s", failure.code, response.Code, response.Body.String())
			}
		}
	}
}

type batchProbeService struct {
	*fakeService
	probe func(context.Context, string, string) (domain.NodeInfo, error)
}

func (f *batchProbeService) Probe(ctx context.Context, id, kind string) (domain.NodeInfo, error) {
	return f.probe(ctx, id, kind)
}

func TestBatchProbesStartAllAndStreamIndividualResults(t *testing.T) {
	for _, kind := range []string{"latency", "ip-check"} {
		t.Run(kind, func(t *testing.T) {
			const count = 12
			ids := make([]string, count)
			releases := make(map[string]chan struct{}, count)
			for i := range ids {
				ids[i] = fmt.Sprintf("n_%d", i)
				releases[ids[i]] = make(chan struct{})
			}
			started := make(chan string, count)
			service := &batchProbeService{fakeService: &fakeService{}, probe: func(ctx context.Context, id, gotKind string) (domain.NodeInfo, error) {
				if gotKind != kind {
					return domain.NodeInfo{}, errors.New("wrong probe kind")
				}
				started <- id
				select {
				case <-releases[id]:
					if id == ids[3] {
						return domain.NodeInfo{}, &domain.Error{Code: "not_found", Message: "node was removed"}
					}
					return domain.NodeInfo{ID: id}, nil
				case <-ctx.Done():
					return domain.NodeInfo{}, ctx.Err()
				}
			}}
			server := httptest.NewServer(New(service, config.Config{}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 5 * time.Second
			body, err := json.Marshal(map[string]any{"ids": ids, "kind": kind})
			if err != nil {
				t.Fatal(err)
			}
			response, err := client.Post(server.URL+"/api/nodes/probe", "application/json", strings.NewReader(string(body)))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "application/x-ndjson; charset=utf-8" {
				t.Fatalf("batch response: status=%d Content-Type=%q", response.StatusCode, response.Header.Get("Content-Type"))
			}
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			seenStarts := make(map[string]bool, count)
			for range ids {
				select {
				case id := <-started:
					if seenStarts[id] {
						t.Fatalf("node %s started twice", id)
					}
					seenStarts[id] = true
				case <-deadline.C:
					t.Fatalf("only %d/%d probes started before any probe was allowed to finish", len(seenStarts), count)
				}
			}
			decoder := json.NewDecoder(response.Body)
			read := func() probeResult {
				t.Helper()
				var result probeResult
				if err := decoder.Decode(&result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			// These lines must arrive while every other probe remains blocked.
			close(releases[ids[7]])
			first := read()
			if first.ID != ids[7] || first.Node == nil || first.Node.ID != ids[7] || first.Error != nil {
				t.Fatalf("first streamed result: %+v", first)
			}
			close(releases[ids[3]])
			failed := read()
			if failed.ID != ids[3] || failed.Node != nil || failed.Error["code"] != "not_found" || failed.Error["message"] != "node was removed" {
				t.Fatalf("per-node error: %+v", failed)
			}
			for _, id := range ids {
				if id != first.ID && id != failed.ID {
					close(releases[id])
				}
			}
			seen := map[string]bool{first.ID: true, failed.ID: true}
			for range count - 2 {
				result := read()
				if seen[result.ID] || result.Node == nil || result.Node.ID != result.ID || result.Error != nil {
					t.Fatalf("remaining result: %+v", result)
				}
				seen[result.ID] = true
			}
			var extra probeResult
			if err := decoder.Decode(&extra); err != io.EOF {
				t.Fatalf("batch did not end after %d results: result=%+v error=%v", count, extra, err)
			}
		})
	}
}

func TestBatchProbeDisconnectCancelsEveryProbe(t *testing.T) {
	const count = 12
	started := make(chan struct{}, count)
	canceled := make(chan error, count)
	service := &batchProbeService{fakeService: &fakeService{}, probe: func(ctx context.Context, _, _ string) (domain.NodeInfo, error) {
		started <- struct{}{}
		<-ctx.Done()
		canceled <- ctx.Err()
		return domain.NodeInfo{}, ctx.Err()
	}}
	server := httptest.NewServer(New(service, config.Config{}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 5 * time.Second
	ids := make([]string, count)
	for i := range ids {
		ids[i] = fmt.Sprintf("n_%d", i)
	}
	body, err := json.Marshal(map[string]any{"ids": ids, "kind": "ip-check"})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Post(server.URL+"/api/nodes/probe", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for range count {
		select {
		case <-started:
		case <-deadline.C:
			t.Fatal("not all probes started")
		}
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	for range count {
		select {
		case err := <-canceled:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("probe cancellation: %v", err)
			}
		case <-deadline.C:
			t.Fatal("disconnect did not cancel every probe")
		}
	}
}

func TestBatchProbeAuthenticationAndInput(t *testing.T) {
	var calls atomic.Int32
	service := &batchProbeService{fakeService: &fakeService{}, probe: func(context.Context, string, string) (domain.NodeInfo, error) {
		calls.Add(1)
		return domain.NodeInfo{}, nil
	}}
	h := New(service, config.Config{APIToken: "secret"})
	w := request(h, http.MethodPost, "/api/nodes/probe", `{"ids":["n_1"],"kind":"latency"}`, "Bearer wrong")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized batch: status=%d", w.Code)
	}
	for _, body := range []string{"", `[]`, `{"ids":[3],"kind":"latency"}`, `{"ids":["n_1"],"kind":"unknown"}`} {
		w = request(h, http.MethodPost, "/api/nodes/probe", body, "Bearer secret")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("batch body %q: status=%d", body, w.Code)
		}
	}
	w = request(h, http.MethodPost, "/api/nodes/probe", `{"ids":[],"kind":"latency"}`, "Bearer secret")
	if w.Code != http.StatusOK || w.Body.Len() != 0 || !w.Flushed {
		t.Fatalf("empty batch: status=%d body=%s flushed=%v", w.Code, w.Body.String(), w.Flushed)
	}
	if calls.Load() != 0 {
		t.Fatalf("invalid, unauthorized or empty batch started %d probes", calls.Load())
	}
}

func TestMalformedAndLargeJSONBodies(t *testing.T) {
	for _, route := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, "/api/subscriptions", http.StatusCreated},
		{http.MethodPost, "/api/subscribe", http.StatusCreated},
		{http.MethodPatch, "/api/subscriptions/s_1", http.StatusOK},
	} {
		f := &fakeService{}
		h := New(f, config.Config{})
		for _, body := range []string{"", `[]`, `{"name":`, `{"name":3}`} {
			w := request(h, route.method, route.path, body, "")
			if w.Code != http.StatusBadRequest || f.lastContext != nil {
				t.Fatalf("%s %s with %q: got %d %s", route.method, route.path, body, w.Code, w.Body.String())
			}
		}
		name := strings.Repeat("a", 1<<20)
		w := request(h, route.method, route.path, `{"name":"`+name+`"}`, "")
		if w.Code != route.status || f.lastContext == nil {
			t.Fatalf("large JSON %s %s: got %d", route.method, route.path, w.Code)
		}
		gotName := f.lastInput.Name
		if route.method == http.MethodPatch && f.lastPatch.Name != nil {
			gotName = *f.lastPatch.Name
		}
		if gotName != name {
			t.Fatal("large JSON name did not reach service intact")
		}
	}
}

func TestRoutesAndPartialUpdate(t *testing.T) {
	f := &fakeService{}
	h := New(f, config.Config{})
	w := request(h, http.MethodPost, "/api/subscribe", `{"name":"test","url":"https://example.com/sub","refresh_interval":"1h","extra":true}`, "")
	if w.Code != http.StatusCreated || w.Header().Get("Location") != "/api/subscriptions/s_1" {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if f.lastInput.RefreshInterval != "1h" {
		t.Fatalf("input: %#v", f.lastInput)
	}
	w = request(h, http.MethodPatch, "/api/subscriptions/s_1", `{"name":"new","extra":"ignored"}`, "")
	if w.Code != http.StatusOK || f.lastPatch.Name == nil || *f.lastPatch.Name != "new" || f.lastPatch.URL != nil {
		t.Fatalf("patch: %d %#v", w.Code, f.lastPatch)
	}
	w = request(h, http.MethodPost, "/api/subscriptions/s_1/refresh", "", "")
	if w.Code != http.StatusOK || f.lastID != "s_1" {
		t.Fatalf("refresh: %d", w.Code)
	}
	w = request(h, http.MethodGet, "/api/nodes?subscription_id=s_1", "", "")
	if w.Code != http.StatusOK || f.filter != "s_1" {
		t.Fatalf("nodes: %d", w.Code)
	}
	var nodes domain.NodeList
	if err := json.Unmarshal(w.Body.Bytes(), &nodes); err != nil || len(nodes.Items) != 1 {
		t.Fatalf("response: %s", w.Body.String())
	}
	w = request(h, http.MethodGet, "/api/subscriptions", "", "")
	if strings.TrimSpace(w.Body.String()) != `{"items":[]}` {
		t.Fatalf("empty list: %s", w.Body.String())
	}
	w = request(h, http.MethodDelete, "/api/subscribe/s_1", "", "")
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}

}

func TestErrorMappingPreservesDetails(t *testing.T) {
	for _, tc := range []struct {
		err      error
		status   int
		contains string
	}{
		{&domain.Error{Code: "invalid_input", Message: "name required"}, 400, "name required"},
		{&domain.Error{Code: "not_found", Message: "missing"}, 404, "missing"},
		{&domain.Error{Code: "fetch_failed", Message: "download failed"}, 502, "download failed"},
		{&domain.Error{Code: "parse_failed", Message: "invalid subscription"}, 422, "invalid subscription"},
		{context.DeadlineExceeded, 504, "timed out"},
		{errors.New("request failed: token=example-token"), 500, "request failed: token=example-token"},
	} {
		h := New(&fakeService{err: tc.err}, config.Config{})
		w := request(h, http.MethodDelete, "/api/subscriptions/s_1", "", "")
		if w.Code != tc.status || !strings.Contains(w.Body.String(), tc.contains) {
			t.Fatalf("%v: %d %s", tc.err, w.Code, w.Body.String())
		}
	}
}

func TestRouteErrorsDoNotRedirectAndPreserveAllow(t *testing.T) {
	h := New(&fakeService{}, config.Config{})
	for _, tc := range []struct {
		method, path string
		status       int
		allow        string
	}{
		{http.MethodOptions, "/api/nodes", 405, "GET"},
		{http.MethodPost, "/api/status", 405, "GET"},
		{http.MethodPut, "/api/subscriptions", 405, "GET, POST"},
		{http.MethodGet, "/api/subscriptions/s_1", 405, "PATCH, DELETE"},
		{http.MethodGet, "/api/subscriptions/s_1/refresh", 405, "POST"},
		{http.MethodGet, "/api/nodes/n_1/latency", 405, "POST"},
		{http.MethodGet, "/api/nodes/n_1/ip-check", 405, "POST"},
		{http.MethodGet, "/api/nodes/probe", 405, "POST"},
		{http.MethodGet, "/api/subscribe", 405, "POST"},
		{http.MethodPatch, "/api/subscribe/s_1", 405, "DELETE"},
		{http.MethodGet, "/api/missing", 404, ""},
		{http.MethodGet, "/api/nodes/", 404, ""},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := request(h, tc.method, tc.path, "", "")
			if w.Code != tc.status || w.Header().Get("Allow") != tc.allow || w.Header().Get("Location") != "" {
				t.Fatalf("status=%d Allow=%q Location=%q; body=%s", w.Code, w.Header().Get("Allow"), w.Header().Get("Location"), w.Body.String())
			}
			var response struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("error is not JSON: %s", w.Body.String())
			}
			wantCode := "not_found"
			if tc.status == 405 {
				wantCode = "method_not_allowed"
			}
			if response.Error.Code != wantCode || w.Header().Get("Content-Type") != "application/json; charset=utf-8" {
				t.Fatalf("unexpected error response: %s", w.Body.String())
			}
		})
	}
}

func TestAuthenticationCoversNotFoundAndMethodNotAllowed(t *testing.T) {
	h := New(&fakeService{}, config.Config{APIToken: "secret"})
	for _, path := range []string{"/api/missing", "/api/subscriptions/s_1"} {
		w := request(h, http.MethodPut, path, "", "Bearer wrong")
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != "Bearer" || w.Header().Get("Allow") != "" {
			t.Fatalf("%s: %d %v %s", path, w.Code, w.Header(), w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"code":"unauthorized"`) {
			t.Fatalf("route handled request before authentication: %s", w.Body.String())
		}
	}
}

func TestMutationHandlersPreserveRequestContext(t *testing.T) {
	type contextKey struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), contextKey{}, "sentinel"))
	cancel()
	for _, route := range []struct{ method, path, body string }{
		{http.MethodPost, "/api/subscriptions", `{"name":"a","url":"https://example.com"}`},
		{http.MethodPost, "/api/subscribe", `{"name":"a","url":"https://example.com"}`},
		{http.MethodPatch, "/api/subscriptions/s_1", `{"name":"b"}`},
		{http.MethodPost, "/api/subscriptions/s_1/refresh", ""},
		{http.MethodDelete, "/api/subscriptions/s_1", ""},
		{http.MethodDelete, "/api/subscribe/s_1", ""},
		{http.MethodPost, "/api/nodes/n_1/latency", ""},
		{http.MethodPost, "/api/nodes/n_1/ip-check", ""},
	} {
		f := &fakeService{}
		h := New(f, config.Config{})
		r := httptest.NewRequest(route.method, route.path, strings.NewReader(route.body)).WithContext(ctx)
		h.ServeHTTP(httptest.NewRecorder(), r)
		if f.lastContext == nil || f.lastContext.Value(contextKey{}) != "sentinel" || !errors.Is(f.lastContext.Err(), context.Canceled) {
			t.Fatalf("%s %s lost request context", route.method, route.path)
		}
	}
}
