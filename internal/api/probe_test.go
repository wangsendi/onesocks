package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"onesocks/internal/config"
	"onesocks/internal/domain"
)

func batchRequest(t *testing.T, ctx context.Context, ids []string, kind string) *http.Request {
	t.Helper()
	body, err := json.Marshal(map[string]any{"ids": ids, "kind": kind})
	if err != nil {
		t.Fatal(err)
	}
	return httptest.NewRequest(http.MethodPost, "/api/nodes/probe", strings.NewReader(string(body))).WithContext(ctx)
}

func startRequest(h http.Handler, w http.ResponseWriter, r *http.Request) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.ServeHTTP(w, r)
	}()
	return done
}

func requireDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	default:
		t.Fatal("request did not finish")
	}
}

func TestBatchProbeLimitAndQueuedResults(t *testing.T) {
	for _, limit := range []int{1, 3, config.DefaultProbeConcurrency} {
		for _, kind := range []string{"latency", "ip-check"} {
			t.Run(fmt.Sprintf("%s/%d", kind, limit), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					count := limit + 5
					ids := make([]string, count)
					releases := make(map[string]chan struct{}, count)
					for i := range ids {
						ids[i] = fmt.Sprintf("n_%d", i)
						releases[ids[i]] = make(chan struct{})
					}
					var calls, active atomic.Int32
					failedID := ids[limit-1]
					service := &batchProbeService{probe: func(ctx context.Context, id, gotKind string) (domain.NodeInfo, error) {
						calls.Add(1)
						if n := active.Add(1); n > int32(limit) {
							t.Errorf("active probes = %d, limit = %d", n, limit)
						}
						defer active.Add(-1)
						if gotKind != kind {
							t.Errorf("kind = %s, want %s", gotKind, kind)
						}
						select {
						case <-ctx.Done():
							return domain.NodeInfo{}, ctx.Err()
						case <-releases[id]:
						}
						if id == failedID {
							return domain.NodeInfo{}, &domain.Error{Code: "not_found", Message: "node removed"}
						}
						return domain.NodeInfo{ID: id}, nil
					}}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					h := New(service, config.Config{ProbeConcurrency: limit})
					w := httptest.NewRecorder()
					done := startRequest(h, w, batchRequest(t, ctx, ids, kind))
					synctest.Wait()
					if calls.Load() != int32(limit) || active.Load() != int32(limit) || !w.Flushed {
						t.Fatalf("calls=%d active=%d flushed=%v", calls.Load(), active.Load(), w.Flushed)
					}
					close(releases[failedID])
					synctest.Wait()
					decoder := json.NewDecoder(w.Body)
					var first probeResult
					if err := decoder.Decode(&first); err != nil || first.ID != failedID || first.Error["code"] != "not_found" {
						t.Fatalf("first streamed result = %+v, error = %v", first, err)
					}
					if calls.Load() != int32(limit+1) || active.Load() != int32(limit) {
						t.Fatal("failed probe did not free a slot for the queue")
					}
					for id, release := range releases {
						if id != failedID {
							close(release)
						}
					}
					synctest.Wait()
					requireDone(t, done)
					seen := map[string]bool{failedID: true}
					for range count - 1 {
						var result probeResult
						if err := decoder.Decode(&result); err != nil || result.Node == nil || result.Node.ID != result.ID || result.Error != nil || seen[result.ID] {
							t.Fatalf("queued result = %+v, error = %v", result, err)
						}
						seen[result.ID] = true
					}
					if err := decoder.Decode(new(probeResult)); err != io.EOF || active.Load() != 0 || calls.Load() != int32(count) {
						t.Fatalf("batch completion: error=%v calls=%d active=%d", err, calls.Load(), active.Load())
					}
				})
			})
		}
	}
}

func TestProbeLimitSharedByBatchesAndSingleRequests(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var active atomic.Int32
		started := make(chan string, 10)
		service := &batchProbeService{probe: func(ctx context.Context, id, _ string) (domain.NodeInfo, error) {
			if n := active.Add(1); n > 2 {
				t.Errorf("global concurrency exceeded: %d", n)
			}
			defer active.Add(-1)
			started <- id
			if id == "after" {
				return domain.NodeInfo{ID: id}, nil
			}
			<-ctx.Done()
			return domain.NodeInfo{}, ctx.Err()
		}}
		h := New(service, config.Config{ProbeConcurrency: 2})
		firstCtx, cancelFirst := context.WithCancel(context.Background())
		defer cancelFirst()
		first := startRequest(h, httptest.NewRecorder(), batchRequest(t, firstCtx, []string{"a0", "a1", "a2"}, "latency"))
		synctest.Wait()
		secondCtx, cancelSecond := context.WithCancel(context.Background())
		defer cancelSecond()
		second := startRequest(h, httptest.NewRecorder(), batchRequest(t, secondCtx, []string{"b0", "b1", "b2"}, "ip-check"))
		singleCtx, cancelSingle := context.WithCancel(context.Background())
		defer cancelSingle()
		single := startRequest(h, httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/nodes/single/latency", nil).WithContext(singleCtx))
		synctest.Wait()
		if len(started) != 2 || active.Load() != 2 {
			t.Fatal("another request bypassed the shared limit")
		}
		<-started
		<-started
		cancelFirst()
		synctest.Wait()
		requireDone(t, first)
		if len(started) != 2 || active.Load() != 2 {
			t.Fatal("canceling a batch did not release its slots")
		}
		seen := map[string]bool{<-started: true, <-started: true}
		if !seen["b0"] || !seen["single"] {
			t.Fatalf("queued requests started unexpected probes: %v", seen)
		}
		cancelSecond()
		cancelSingle()
		synctest.Wait()
		requireDone(t, second)
		requireDone(t, single)
		if active.Load() != 0 || len(started) != 0 {
			t.Fatal("canceled requests started queued probes or leaked workers")
		}
		w := httptest.NewRecorder()
		after := startRequest(h, w, httptest.NewRequest(http.MethodPost, "/api/nodes/after/ip-check", nil))
		synctest.Wait()
		requireDone(t, after)
		if w.Code != http.StatusOK {
			t.Fatalf("subsequent probe status = %d", w.Code)
		}
	})
}

func TestCanceledBatchDiscardsLargeQueue(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls, active atomic.Int32
		service := &batchProbeService{probe: func(ctx context.Context, _, _ string) (domain.NodeInfo, error) {
			calls.Add(1)
			active.Add(1)
			defer active.Add(-1)
			<-ctx.Done()
			return domain.NodeInfo{}, ctx.Err()
		}}
		ids := make([]string, 10000)
		for i := range ids {
			ids[i] = fmt.Sprintf("n_%d", i)
		}
		h := New(service, config.Config{ProbeConcurrency: 2})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		done := startRequest(h, httptest.NewRecorder(), batchRequest(t, ctx, ids, "ip-check"))
		synctest.Wait()
		if calls.Load() != 2 {
			t.Fatalf("started %d probes before cancellation", calls.Load())
		}
		cancel()
		synctest.Wait()
		requireDone(t, done)
		if calls.Load() != 2 || active.Load() != 0 {
			t.Fatalf("after cancellation: calls=%d active=%d", calls.Load(), active.Load())
		}
	})
}

type failingProbeWriter struct {
	*httptest.ResponseRecorder
	failWrite bool
	failFlush int
	flushes   int
}

func (w *failingProbeWriter) Write(p []byte) (int, error) {
	if w.failWrite {
		return 0, io.ErrClosedPipe
	}
	return w.ResponseRecorder.Write(p)
}

func (w *failingProbeWriter) FlushError() error {
	w.flushes++
	if w.flushes == w.failFlush {
		return io.ErrClosedPipe
	}
	w.ResponseRecorder.Flush()
	return nil
}

func TestBatchWriteFailureCancelsWorkers(t *testing.T) {
	for _, mode := range []string{"write", "flush", "headers"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				release := make(chan struct{})
				var active atomic.Int32
				service := &batchProbeService{probe: func(ctx context.Context, id, _ string) (domain.NodeInfo, error) {
					active.Add(1)
					defer active.Add(-1)
					if id == "first" {
						select {
						case <-release:
							return domain.NodeInfo{ID: id}, nil
						case <-ctx.Done():
						}
					} else {
						<-ctx.Done()
					}
					return domain.NodeInfo{}, ctx.Err()
				}}
				h := New(service, config.Config{ProbeConcurrency: 2})
				w := &failingProbeWriter{ResponseRecorder: httptest.NewRecorder(), failWrite: mode == "write"}
				if mode == "flush" {
					w.failFlush = 2
				} else if mode == "headers" {
					w.failFlush = 1
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := startRequest(h, w, batchRequest(t, ctx, []string{"first", "second", "queued"}, "latency"))
				synctest.Wait()
				if mode == "headers" && active.Load() != 0 {
					t.Fatal("failed headers started probes")
				}
				close(release)
				synctest.Wait()
				requireDone(t, done)
				if active.Load() != 0 {
					t.Fatal("write failure leaked workers")
				}
			})
		})
	}
}

func TestProbeContextAndAlreadyCanceledRequests(t *testing.T) {
	type key struct{}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "sentinel"))
	defer cancel()
	f := &fakeService{}
	h := New(f, config.Config{})
	r := httptest.NewRequest(http.MethodPost, "/api/nodes/n_1/latency", nil).WithContext(ctx)
	h.ServeHTTP(httptest.NewRecorder(), r)
	if f.lastContext != ctx || f.lastContext.Value(key{}) != "sentinel" {
		t.Fatal("probe lost its request context")
	}
	cancel()
	f.lastContext = nil
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusRequestTimeout || f.lastContext != nil {
		t.Fatal("canceled single probe reached the service")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, batchRequest(t, ctx, []string{"n_1"}, "ip-check"))
	if f.lastContext != nil || w.Body.Len() != 0 {
		t.Fatal("canceled batch reached the service")
	}
}

func TestBatchOutlivesServerWriteTimeout(t *testing.T) {
	service := &batchProbeService{probe: func(ctx context.Context, id, _ string) (domain.NodeInfo, error) {
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return domain.NodeInfo{}, ctx.Err()
		case <-timer.C:
			return domain.NodeInfo{ID: id}, nil
		}
	}}
	server := httptest.NewUnstartedServer(New(service, config.Config{ProbeConcurrency: 1}))
	server.Config.WriteTimeout = 100 * time.Millisecond
	server.Start()
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	response, err := client.Post(server.URL+"/api/nodes/probe", "application/json", strings.NewReader(`{"ids":["first","second"],"kind":"latency"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	decoder := json.NewDecoder(response.Body)
	for _, id := range []string{"first", "second"} {
		var result probeResult
		if err := decoder.Decode(&result); err != nil || result.Node == nil || result.ID != id {
			t.Fatalf("long batch result = %+v, error = %v", result, err)
		}
	}
	if err := decoder.Decode(new(probeResult)); err != io.EOF {
		t.Fatalf("stream end: %v", err)
	}
}

func TestDefaultProbeConcurrencyReported(t *testing.T) {
	w := request(New(&fakeService{}, config.Config{}), http.MethodGet, "/api/config", "", "")
	var cfg config.Config
	if err := json.Unmarshal(w.Body.Bytes(), &cfg); err != nil || cfg.ProbeConcurrency != config.DefaultProbeConcurrency {
		t.Fatalf("default concurrency = %d, error = %v", cfg.ProbeConcurrency, err)
	}
}
