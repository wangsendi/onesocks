package store

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"onesocks/internal/domain"
)

func TestSQLiteReopenPreservesSubscriptionsAndSettings(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "private", Filename)
	s := openTestStore(t, path)
	first := testSubscription("s_z", "First")
	attempt := time.Date(2026, 11, 13, 10, 20, 30, 123456789, time.FixedZone("fixture", 8*3600))
	success := attempt.Add(-time.Minute)
	first.LastAttemptAt, first.LastSuccessAt = &attempt, &success
	first.LastError = "previous refresh failed"
	second := testSubscription("s_a", "Second")
	second.Nodes = second.Nodes[:1]
	if err := s.Put(ctx, 7, first); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, 8, second); err != nil {
		t.Fatal(err)
	}
	empty := testSubscription("s_empty", "Empty")
	empty.Nodes = nil
	if err := s.Put(ctx, 9, empty); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	attempt, success = attempt.UTC(), success.UTC()
	assertTestState(t, s, State{Generation: 9, Subscriptions: []Subscription{first, second, empty}})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("database permissions = %v, want 0600", info.Mode().Perm())
	}
	for pragma, want := range map[string]int{
		"foreign_keys": 1,
		"busy_timeout": 5000,
		"synchronous":  2,
		"user_version": 3,
	} {
		var got int
		if err := s.db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %d, want %d", pragma, got, want)
		}
	}
	var journalMode string
	if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if journalMode != "wal" {
		t.Errorf("journal_mode = %q, want wal", journalMode)
	}
	if _, err := s.db.Exec(`INSERT INTO nodes (id, subscription_id, name, outbound_json)
		VALUES ('n_orphan', 'missing', 'orphan', '{}')`); err == nil {
		t.Fatal("foreign key constraint accepted an orphan node")
	}
}

func TestSQLiteWriteFailuresRollbackMetadataNodesAndGeneration(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), Filename))
	original := testSubscription("s_target", "Original")
	neighbor := testSubscription("s_neighbor", "Neighbor")
	if err := s.Put(ctx, 6, original); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, 7, neighbor); err != nil {
		t.Fatal(err)
	}
	baseline := State{Generation: 7, Subscriptions: []Subscription{original, neighbor}}
	changed := testSubscription("s_target", "Changed")
	changed.URL = "https://subscriptions.example.test/replacement"
	changed.RefreshInterval = "3h"
	changed.Nodes[0].Name = "replacement-one"
	changed.Nodes[1].Name = "replacement-two"
	if _, err := s.db.Exec(`CREATE TRIGGER fail_second_node BEFORE INSERT ON nodes
		WHEN NEW.subscription_id = 's_target' AND NEW.name = 'replacement-two'
		BEGIN SELECT RAISE(ABORT, 'injected node failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, 8, changed); err == nil {
		t.Fatal("Put succeeded despite injected node failure")
	}
	assertTestState(t, s, baseline)
	if _, err := s.db.Exec("DROP TRIGGER fail_second_node"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`CREATE TRIGGER fail_generation BEFORE UPDATE ON app_state
		BEGIN SELECT RAISE(ABORT, 'injected generation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, 8, changed); err == nil {
		t.Fatal("Put succeeded despite injected generation failure")
	}
	assertTestState(t, s, baseline)
	if err := s.Delete(ctx, 8, original.ID); err == nil {
		t.Fatal("Delete succeeded despite injected generation failure")
	}
	assertTestState(t, s, baseline)
	if _, err := s.db.Exec("DROP TRIGGER fail_generation"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, 8, original.ID); err != nil {
		t.Fatal(err)
	}
	assertTestState(t, s, State{Generation: 8, Subscriptions: []Subscription{neighbor}})
	var remaining int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM nodes WHERE subscription_id = ?", original.ID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("deleted subscription still has %d nodes", remaining)
	}
}

func TestSQLiteRecordFailureKeepsNodesAndGeneration(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), Filename)
	s := openTestStore(t, path)
	sub := testSubscription("s_failure", "Refresh")
	at := time.Date(2026, 11, 13, 10, 20, 30, 123456789, time.UTC)
	sub.LastAttemptAt, sub.LastSuccessAt = &at, &at
	if err := s.Put(ctx, 9, sub); err != nil {
		t.Fatal(err)
	}
	failedAt := at.Add(time.Hour)
	if err := s.RecordFailure(ctx, sub.ID, failedAt, "upstream unavailable"); err != nil {
		t.Fatal(err)
	}
	sub.LastAttemptAt = &failedAt
	sub.LastError = "upstream unavailable"
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = openTestStore(t, path)
	assertTestState(t, s, State{Generation: 9, Subscriptions: []Subscription{sub}})
}

func TestSQLiteNodeIDsAndLastNamedEntryWins(t *testing.T) {
	ctx := context.Background()
	s := openTestStore(t, filepath.Join(t.TempDir(), Filename))
	first := testSubscription("s_first", "First")
	first.Nodes = []domain.NodeSpec{
		{Name: "zeta", Outbound: json.RawMessage(`{"type":"direct"}`)},
		{Name: "alpha", Outbound: json.RawMessage(`{"type":"socks","server":"old.example","server_port":1080}`)},
		{Name: "alpha", Outbound: json.RawMessage(`{"type":"socks","server":"last.example","server_port":1080}`)},
	}
	if err := s.Put(ctx, 1, first); err != nil {
		t.Fatal(err)
	}
	first.Nodes = []domain.NodeSpec{first.Nodes[2], first.Nodes[0]}
	second := testSubscription("s_second", "Second")
	second.Nodes = []domain.NodeSpec{first.Nodes[0]}
	if err := s.Put(ctx, 2, second); err != nil {
		t.Fatal(err)
	}
	assertTestState(t, s, State{Generation: 2, Subscriptions: []Subscription{first, second}})
	ids := make(map[string]string)
	for _, sub := range []Subscription{first, second} {
		var id string
		if err := s.db.QueryRow("SELECT id FROM nodes WHERE subscription_id = ? AND name = 'alpha'", sub.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if want := domain.NodeID(sub.ID, "alpha"); id != want {
			t.Fatalf("node ID = %q, want %q", id, want)
		}
		ids[sub.ID] = id
	}
	if ids[first.ID] == ids[second.ID] {
		t.Fatal("same node name in different subscriptions has the same ID")
	}
	first.Nodes[0].Outbound = json.RawMessage(`{"type":"socks","server":"updated.example","server_port":2080}`)
	if err := s.Put(ctx, 3, first); err != nil {
		t.Fatal(err)
	}
	assertTestState(t, s, State{Generation: 3, Subscriptions: []Subscription{first, second}})
	var updatedID string
	if err := s.db.QueryRow("SELECT id FROM nodes WHERE subscription_id = ? AND name = 'alpha'", first.ID).Scan(&updatedID); err != nil {
		t.Fatal(err)
	}
	if updatedID != ids[first.ID] {
		t.Fatalf("configuration update changed node ID from %q to %q", ids[first.ID], updatedID)
	}
}

func openTestStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func assertTestState(t *testing.T, s *Store, want State) {
	t.Helper()
	got, err := s.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("stored state = %#v, want %#v", got, want)
	}
}

func testSubscription(id, name string) Subscription {
	outbound := json.RawMessage(`{"type":"shadowsocks","server":"example.test","server_port":443,"method":"aes-128-gcm","password":"fixture-password"}`)
	return Subscription{
		ID: id, Name: name,
		URL:             "https://subscriptions.example.test/" + id,
		RefreshInterval: "1h",
		Nodes: []domain.NodeSpec{
			{Name: "alias-one", Outbound: outbound},
			{Name: "alias-two", Outbound: outbound},
		},
	}
}
