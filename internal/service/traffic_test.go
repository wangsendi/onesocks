package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseSubscriptionTraffic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		headers []string
		want    string
	}{
		{"full", []string{"upload=1024; download=2048; total=1073741824; expire=1700000000"}, `{"upload_bytes":1024,"download_bytes":2048,"total_bytes":1073741824,"expires_at":"2023-11-14T22:13:20Z"}`},
		{"multiple lines and whitespace", []string{" Upload = 0 ; Download = 1 ", "total=1024; unknown=10; expire=0"}, `{"upload_bytes":0,"download_bytes":1,"total_bytes":1024}`},
		{"no header", nil, `null`},
		{"invalid", []string{"upload=-1; download=1.5; total=18446744073709551616; expire=253402300800; broken"}, `null`},
		{"partial", []string{"upload=17; download=invalid; expire=1700000000"}, `{"upload_bytes":17,"expires_at":"2023-11-14T22:13:20Z"}`},
		{"zero quota", []string{"upload=0; download=0; total=0; expire=0"}, `{"upload_bytes":0,"download_bytes":0,"total_bytes":0}`},
		{"upper bounds", []string{"total=18446744073709551615; expire=253402300799"}, `{"total_bytes":18446744073709551615,"expires_at":"9999-12-31T23:59:59Z"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := json.Marshal(parseSubscriptionTraffic(tc.headers))
			if err != nil || string(got) != tc.want {
				t.Fatalf("traffic=%s want=%s error=%v", got, tc.want, err)
			}
		})
	}
}

func TestSubscriptionTrafficRefreshAndRestart(t *testing.T) {
	type response struct {
		header, body string
		status       int
	}
	body := document(ssNode("node", 1001))
	initial := response{"upload=1024; download=2048; total=1073741824; expire=1700000000", body, http.StatusOK}
	var upstream atomic.Value
	upstream.Store(initial)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reply := upstream.Load().(response)
		if reply.header != "" {
			w.Header().Set("Subscription-Userinfo", reply.header)
		}
		w.WriteHeader(reply.status)
		_, _ = io.WriteString(w, reply.body)
	}))
	defer server.Close()
	dir := t.TempDir()
	m := newManager(t, dir, &fakeFactory{}, time.Second)
	created := createSubscription(t, m, "traffic", server.URL)
	want := parseSubscriptionTraffic([]string{initial.header})
	if !reflect.DeepEqual(created.Subscription.Traffic, want) {
		t.Fatalf("create traffic=%+v want=%+v", created.Subscription.Traffic, want)
	}
	*created.Subscription.Traffic.TotalBytes = 0
	if !reflect.DeepEqual(m.Subscriptions()[0].Traffic, want) {
		t.Fatal("caller changed cached subscription traffic")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	m = newManager(t, dir, &fakeFactory{}, time.Second)
	if !reflect.DeepEqual(m.Subscriptions()[0].Traffic, want) {
		t.Fatal("restart lost subscription traffic")
	}
	id := created.Subscription.ID
	for _, reply := range []response{
		{"upload=1; download=1; total=2", body, http.StatusServiceUnavailable},
		{"upload=1; download=1; total=2", "not a subscription", http.StatusOK},
	} {
		upstream.Store(reply)
		if _, err := m.Refresh(context.Background(), id); err == nil {
			t.Fatal("invalid refresh succeeded")
		}
		if !reflect.DeepEqual(m.Subscriptions()[0].Traffic, want) || !m.Subscriptions()[0].Stale {
			t.Fatal("failed refresh did not retain previous traffic and mark subscription stale")
		}
		stored, err := m.store.Load(context.Background())
		if err != nil || !reflect.DeepEqual(stored.Subscriptions[0].Traffic, want) {
			t.Fatalf("failed refresh changed saved traffic: %v", err)
		}
	}
	upstream.Store(response{"upload=4096; download=8192; total=1073741824", body, http.StatusOK})
	updated, err := m.Refresh(context.Background(), id)
	if err != nil || updated.Subscription.Traffic == nil || *updated.Subscription.Traffic.DownloadBytes != 8192 || updated.Subscription.Stale {
		t.Fatalf("successful refresh did not update traffic: %+v error=%v", updated, err)
	}
	upstream.Store(response{"", body, http.StatusOK})
	updated, err = m.Refresh(context.Background(), id)
	if err != nil || updated.Subscription.Traffic != nil {
		t.Fatalf("missing header reused outdated traffic: %+v error=%v", updated, err)
	}
	stored, err := m.store.Load(context.Background())
	if err != nil || stored.Subscriptions[0].Traffic != nil {
		t.Fatalf("missing header retained saved traffic: %v", err)
	}
}
