package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"onesocks/internal/domain"
)

func TestSubscriptionUserAgentFallback(t *testing.T) {
	for _, tc := range []struct {
		name                string
		initial, compatible int
		invalidBody         bool
		wantAgents          []string
		wantError           string
	}{
		{"normal client", 200, 200, false, []string{"OneSocks/test"}, ""},
		{"recognized client required", 403, 200, false, []string{"OneSocks/test", "sing-box"}, ""},
		{"retry only once", 403, 403, false, []string{"OneSocks/test", "sing-box"}, "fetch_failed"},
		{"invalid credentials", 401, 200, false, []string{"OneSocks/test"}, "fetch_failed"},
		{"server error", 500, 200, false, []string{"OneSocks/test"}, "fetch_failed"},
		{"invalid subscription", 200, 200, true, []string{"OneSocks/test"}, "parse_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var agents []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ua := r.UserAgent()
				mu.Lock()
				agents = append(agents, ua)
				mu.Unlock()
				status := tc.initial
				if ua == "sing-box" {
					status = tc.compatible
				}
				w.Header().Set("Subscription-Userinfo", "upload=10; download=20; total=1000")
				w.WriteHeader(status)
				if tc.invalidBody {
					_, _ = io.WriteString(w, "not a subscription")
				} else {
					_, _ = io.WriteString(w, document(ssNode("node", 1001)))
				}
			}))
			defer server.Close()
			m := newManager(t, t.TempDir(), &fakeFactory{}, time.Second)
			result, err := m.Create(context.Background(), domain.SubscriptionInput{Name: "UA", URL: server.URL})
			if tc.wantError != "" {
				requireErrorCode(t, err, tc.wantError)
				if len(m.Subscriptions()) != 0 {
					t.Fatal("failed fetch persisted a subscription")
				}
			} else {
				if err != nil || result.Subscription.NodeCount != 1 || result.Subscription.URL != server.URL || result.Subscription.Traffic == nil || *result.Subscription.Traffic.TotalBytes != 1000 {
					t.Fatalf("subscription not imported with traffic: %+v error=%v", result, err)
				}
			}
			mu.Lock()
			got := append([]string(nil), agents...)
			mu.Unlock()
			if !reflect.DeepEqual(got, tc.wantAgents) {
				t.Fatalf("request User-Agents=%v want=%v", got, tc.wantAgents)
			}
			if tc.wantError == "" {
				if _, err := m.Refresh(context.Background(), result.Subscription.ID); err != nil {
					t.Fatalf("imported subscription could not refresh: %v", err)
				}
			}
		})
	}
}
