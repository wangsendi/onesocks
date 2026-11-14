package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestTimeoutPreservesBatchContext(t *testing.T) {
	type key struct{}
	for _, tc := range []struct {
		method, path string
		streaming    bool
	}{
		{http.MethodPost, "/api/nodes/probe", true},
		{http.MethodGet, "/api/nodes/probe", false},
		{http.MethodPost, "/api/nodes/n_1/latency", false},
		{http.MethodPost, "/api/subscriptions/s_1/refresh", false},
		{http.MethodGet, "/", false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), key{}, "kept"))
			defer cancel()
			called := false
			h := withRequestTimeout(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				called = true
				_, hasDeadline := r.Context().Deadline()
				if hasDeadline == tc.streaming || r.Context().Value(key{}) != "kept" {
					t.Fatal("incorrect request deadline or lost context value")
				}
				if tc.streaming && r.Context() != ctx {
					t.Fatal("batch request context was replaced")
				}
				cancel()
				if r.Context().Err() != context.Canceled {
					t.Fatal("request lost parent cancellation")
				}
			}), time.Minute)
			h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(tc.method, tc.path, nil).WithContext(ctx))
			if !called {
				t.Fatal("request did not reach the handler")
			}
		})
	}
}
