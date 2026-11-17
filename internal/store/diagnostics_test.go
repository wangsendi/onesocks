package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"onesocks/internal/domain"
)

func testDiagnostics() Diagnostics {
	milliseconds := int64(123)
	at := time.Date(2026, 11, 13, 10, 20, 30, 123456789, time.UTC)
	return Diagnostics{
		Latency: &domain.LatencyResult{CheckedAt: at, Milliseconds: &milliseconds, Reused: true},
		IPCheck: &domain.IPCheckResult{CheckedAt: at, Data: json.RawMessage(`{"ip_info":{"ip":"203.0.113.8"},"mode":"fast","full":"retained"}`)},
	}
}

func TestSQLiteDiagnosticsSurviveReopenAndEquivalentRefresh(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), Filename)
	s := openTestStore(t, path)
	sub := testSubscription("s_probe", "Probe")
	if err := s.Put(ctx, 1, sub); err != nil {
		t.Fatal(err)
	}
	id := domain.NodeID(sub.ID, sub.Nodes[0].Name)
	want := testDiagnostics()
	// Separate updates must retain the other diagnostic result.
	for _, result := range []Diagnostics{{Latency: want.Latency}, {IPCheck: want.IPCheck}} {
		if updated, err := s.RecordProbe(ctx, id, sub.Nodes[0].Outbound, result); err != nil || !updated {
			t.Fatalf("RecordProbe updated=%v error=%v", updated, err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	assertDiagnostics(t, s, map[string]Diagnostics{id: want})
	original := sub.Nodes[0].Outbound
	sub.Name = "Renamed subscription"
	sub.Nodes[0].Outbound = json.RawMessage(` {"password":"fixture-password","method":"aes-128-gcm","server_port":443,"server":"example.test","type":"shadowsocks"} `)
	if err := s.Put(ctx, 2, sub); err != nil {
		t.Fatal(err)
	}
	assertDiagnostics(t, s, map[string]Diagnostics{id: want})
	if updated, err := s.RecordProbe(ctx, id, original, Diagnostics{IPCheck: want.IPCheck}); err != nil || !updated {
		t.Fatalf("equivalent outbound rejected: updated=%v error=%v", updated, err)
	}
	assertTestState(t, s, State{Generation: 2, Subscriptions: []Subscription{sub}})
}

func TestSQLiteDiagnosticsInvalidateOnChangedOrDeletedNode(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), Filename))
	sub := testSubscription("s_probe", "Probe")
	if err := s.Put(ctx, 1, sub); err != nil {
		t.Fatal(err)
	}
	id, original := domain.NodeID(sub.ID, sub.Nodes[0].Name), sub.Nodes[0].Outbound
	if updated, err := s.RecordProbe(ctx, id, original, testDiagnostics()); err != nil || !updated {
		t.Fatal(updated, err)
	}
	sub.Nodes[0].Outbound = json.RawMessage(strings.Replace(string(original), "443", "444", 1))
	if err := s.Put(ctx, 2, sub); err != nil {
		t.Fatal(err)
	}
	assertDiagnostics(t, s, map[string]Diagnostics{})
	if updated, err := s.RecordProbe(ctx, id, original, testDiagnostics()); err != nil || updated {
		t.Fatalf("stale outbound wrote diagnostics: updated=%v error=%v", updated, err)
	}
	if updated, err := s.RecordProbe(ctx, id, sub.Nodes[0].Outbound, testDiagnostics()); err != nil || !updated {
		t.Fatal(updated, err)
	}
	removed := sub.Nodes[0]
	sub.Nodes = sub.Nodes[1:]
	if err := s.Put(ctx, 3, sub); err != nil {
		t.Fatal(err)
	}
	assertDiagnostics(t, s, map[string]Diagnostics{})
	if updated, err := s.RecordProbe(ctx, id, removed.Outbound, testDiagnostics()); err != nil || updated {
		t.Fatalf("deleted node accepted diagnostics: updated=%v error=%v", updated, err)
	}
	sub.Nodes = append([]domain.NodeSpec{removed}, sub.Nodes...)
	if err := s.Put(ctx, 4, sub); err != nil {
		t.Fatal(err)
	}
	assertDiagnostics(t, s, map[string]Diagnostics{})
	if updated, err := s.RecordProbe(ctx, id, removed.Outbound, testDiagnostics()); err != nil || !updated {
		t.Fatal(updated, err)
	}
	if err := s.Delete(ctx, 5, sub.ID); err != nil {
		t.Fatal(err)
	}
	assertDiagnostics(t, s, map[string]Diagnostics{})
}

func TestSQLiteDiagnosticsWriteFailureKeepsPreviousResults(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), Filename))
	sub := testSubscription("s_probe", "Probe")
	if err := s.Put(ctx, 1, sub); err != nil {
		t.Fatal(err)
	}
	id := domain.NodeID(sub.ID, sub.Nodes[0].Name)
	want := testDiagnostics()
	if updated, err := s.RecordProbe(ctx, id, sub.Nodes[0].Outbound, want); err != nil || !updated {
		t.Fatal(updated, err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_probe BEFORE UPDATE OF latency_json ON nodes
		BEGIN SELECT RAISE(ABORT, 'injected diagnostic failure'); END`); err != nil {
		t.Fatal(err)
	}
	failed := Diagnostics{Latency: &domain.LatencyResult{CheckedAt: time.Now().UTC(), Error: "new result"}}
	if updated, err := s.RecordProbe(ctx, id, sub.Nodes[0].Outbound, failed); err == nil || updated || !strings.Contains(err.Error(), "injected diagnostic failure") {
		t.Fatalf("injected failure was not reported: updated=%v error=%v", updated, err)
	}
	assertDiagnostics(t, s, map[string]Diagnostics{id: want})
	assertTestState(t, s, State{Generation: 1, Subscriptions: []Subscription{sub}})
}

func TestSQLiteVersionTwoUpgradePreservesExistingData(t *testing.T) {
	path := filepath.Join(t.TempDir(), Filename)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The existing v2 layout, before diagnostics were added.
	const versionTwo = `CREATE TABLE app_state (id INTEGER PRIMARY KEY, generation INTEGER NOT NULL DEFAULT 0);
		INSERT INTO app_state VALUES (1, 7);
		CREATE TABLE subscriptions (id TEXT PRIMARY KEY NOT NULL, name TEXT NOT NULL UNIQUE,
		url TEXT NOT NULL UNIQUE, refresh_interval TEXT NOT NULL, last_attempt_at TEXT,
		last_success_at TEXT, last_error TEXT NOT NULL DEFAULT '');
		CREATE TABLE nodes (id TEXT PRIMARY KEY NOT NULL, subscription_id TEXT NOT NULL
		REFERENCES subscriptions(id) ON DELETE CASCADE, name TEXT NOT NULL,
		outbound_json TEXT NOT NULL, UNIQUE (subscription_id, name));
		PRAGMA user_version = 2;`
	if _, err := db.Exec(versionTwo); err != nil {
		t.Fatal(err)
	}
	sub := testSubscription("s_existing", "Existing")
	sub.Nodes = sub.Nodes[:1]
	if _, err := db.Exec("INSERT INTO subscriptions (id,name,url,refresh_interval) VALUES (?,?,?,?)", sub.ID, sub.Name, sub.URL, sub.RefreshInterval); err != nil {
		t.Fatal(err)
	}
	id := domain.NodeID(sub.ID, sub.Nodes[0].Name)
	if _, err := db.Exec("INSERT INTO nodes (id,subscription_id,name,outbound_json) VALUES (?,?,?,?)", id, sub.ID, sub.Nodes[0].Name, string(sub.Nodes[0].Outbound)); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s := openTestStore(t, path)
	assertTestState(t, s, State{Generation: 7, Subscriptions: []Subscription{sub}})
	assertDiagnostics(t, s, map[string]Diagnostics{})
	if updated, err := s.RecordProbe(context.Background(), id, sub.Nodes[0].Outbound, testDiagnostics()); err != nil || !updated {
		t.Fatalf("migrated database did not accept diagnostics: %v %v", updated, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	assertTestState(t, s, State{Generation: 7, Subscriptions: []Subscription{sub}})
	assertDiagnostics(t, s, map[string]Diagnostics{id: testDiagnostics()})
}

func assertDiagnostics(t *testing.T, s *Store, want map[string]Diagnostics) {
	t.Helper()
	got, err := s.LoadDiagnostics(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostics=%+v, want=%+v, error=%v", got, want, err)
	}
}

func TestSQLiteVersionThreeUpgradePreservesDiagnostics(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), Filename)
	s := openTestStore(t, path)
	sub := testSubscription("s_existing", "Existing")
	if err := s.Put(ctx, 7, sub); err != nil {
		t.Fatal(err)
	}
	id := domain.NodeID(sub.ID, sub.Nodes[0].Name)
	if updated, err := s.RecordProbe(ctx, id, sub.Nodes[0].Outbound, testDiagnostics()); err != nil || !updated {
		t.Fatal(updated, err)
	}
	if _, err := s.db.Exec(`ALTER TABLE subscriptions DROP COLUMN traffic_json; PRAGMA user_version = 3;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	assertTestState(t, s, State{Generation: 7, Subscriptions: []Subscription{sub}})
	assertDiagnostics(t, s, map[string]Diagnostics{id: testDiagnostics()})
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 4 {
		t.Fatalf("schema version=%d error=%v", version, err)
	}
	var traffic sql.NullString
	if err := s.db.QueryRow("SELECT traffic_json FROM subscriptions WHERE id = ?", sub.ID).Scan(&traffic); err != nil || traffic.Valid {
		t.Fatalf("migrated subscription traffic=%v error=%v", traffic, err)
	}
}
