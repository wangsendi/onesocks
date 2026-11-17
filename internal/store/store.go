package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"onesocks/internal/domain"
)

const Filename = "onesocks.db"

//go:embed schema.sql
var schema string

type Subscription struct {
	ID              string
	Name            string
	URL             string
	RefreshInterval string
	Nodes           []domain.NodeSpec
	LastAttemptAt   *time.Time
	LastSuccessAt   *time.Time
	LastError       string
	Traffic         *domain.SubscriptionTraffic
}

type State struct {
	Generation    uint64
	Subscriptions []Subscription
}

type Diagnostics struct {
	Latency *domain.LatencyResult
	IPCheck *domain.IPCheckResult
}

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	query := u.Query()
	for _, pragma := range []string{"busy_timeout(5000)", "journal_mode(WAL)", "foreign_keys(1)", "synchronous(FULL)"} {
		query.Add("_pragma", pragma)
	}
	u.RawQuery = query.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.initialize(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize SQLite: %w", err)
	}
	return s, nil
}

func (s *Store) initialize() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	switch version {
	case 4:
		return nil
	case 0, 2, 3:
	default:
		return fmt.Errorf("unsupported database schema version: %d", version)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statement := schema
	if version != 0 {
		statement = ""
		if version == 2 {
			statement = `ALTER TABLE nodes ADD COLUMN latency_json TEXT;
				ALTER TABLE nodes ADD COLUMN ip_check_json TEXT;`
		}
		statement += `ALTER TABLE subscriptions ADD COLUMN traffic_json TEXT;
			PRAGMA user_version = 4;`
	}
	if _, err := tx.Exec(statement); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) Load(ctx context.Context) (State, error) {
	state := State{Subscriptions: []Subscription{}}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return state, err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "SELECT generation FROM app_state WHERE id = 1").Scan(&state.Generation); err != nil {
		return state, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT s.id, s.name, s.url, s.refresh_interval,
		s.last_attempt_at, s.last_success_at, s.last_error, s.traffic_json, n.name, n.outbound_json
		FROM subscriptions s LEFT JOIN nodes n ON n.subscription_id = s.id
		ORDER BY s.rowid, n.name`)
	if err != nil {
		return state, err
	}
	defer rows.Close()
	for rows.Next() {
		var sub Subscription
		var attempt, success, traffic, nodeName sql.NullString
		var outbound []byte
		if err := rows.Scan(&sub.ID, &sub.Name, &sub.URL, &sub.RefreshInterval, &attempt, &success, &sub.LastError, &traffic, &nodeName, &outbound); err != nil {
			return state, err
		}
		if len(state.Subscriptions) == 0 || state.Subscriptions[len(state.Subscriptions)-1].ID != sub.ID {
			if sub.LastAttemptAt, err = parseTime(attempt); err != nil {
				return state, err
			}
			if sub.LastSuccessAt, err = parseTime(success); err != nil {
				return state, err
			}
			if traffic.Valid {
				if err := json.Unmarshal([]byte(traffic.String), &sub.Traffic); err != nil {
					return state, fmt.Errorf("decode traffic for subscription %s: %w", sub.ID, err)
				}
			}
			state.Subscriptions = append(state.Subscriptions, sub)
		}
		if nodeName.Valid {
			sub := &state.Subscriptions[len(state.Subscriptions)-1]
			sub.Nodes = append(sub.Nodes, domain.NodeSpec{Name: nodeName.String, Outbound: outbound})
		}
	}
	if err := rows.Err(); err != nil {
		return state, err
	}
	return state, tx.Commit()
}

func (s *Store) Put(ctx context.Context, generation uint64, sub Subscription) error {
	var traffic any
	if sub.Traffic != nil {
		data, err := json.Marshal(sub.Traffic)
		if err != nil {
			return err
		}
		traffic = string(data)
	}
	return s.write(ctx, generation, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO subscriptions
			(id, name, url, refresh_interval, last_attempt_at, last_success_at, last_error, traffic_json)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET name = excluded.name, url = excluded.url,
			refresh_interval = excluded.refresh_interval, last_attempt_at = excluded.last_attempt_at,
			last_success_at = excluded.last_success_at, last_error = excluded.last_error,
			traffic_json = excluded.traffic_json`,
			sub.ID, sub.Name, sub.URL, sub.RefreshInterval, formatTime(sub.LastAttemptAt), formatTime(sub.LastSuccessAt), sub.LastError, traffic)
		if err != nil {
			return err
		}
		return putNodes(ctx, tx, sub.ID, sub.Nodes)
	})
}

func putNodes(ctx context.Context, tx *sql.Tx, subscriptionID string, nodes []domain.NodeSpec) error {
	rows, err := tx.QueryContext(ctx, "SELECT name, outbound_json FROM nodes WHERE subscription_id = ?", subscriptionID)
	if err != nil {
		return err
	}
	existing := make(map[string]json.RawMessage)
	for rows.Next() {
		var name string
		var outbound []byte
		if err := rows.Scan(&name, &outbound); err != nil {
			_ = rows.Close()
			return err
		}
		existing[name] = outbound
	}
	err = rows.Err()
	_ = rows.Close()
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO nodes (id, subscription_id, name, outbound_json) VALUES (?, ?, ?, ?)
		ON CONFLICT(subscription_id, name) DO UPDATE SET
		latency_json = CASE WHEN ? THEN nodes.latency_json END,
		ip_check_json = CASE WHEN ? THEN nodes.ip_check_json END,
		outbound_json = excluded.outbound_json`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, node := range domain.UniqueNodes(nodes) {
		preserve := domain.EqualOutbound(existing[node.Name], node.Outbound)
		if _, err := stmt.ExecContext(ctx, domain.NodeID(subscriptionID, node.Name), subscriptionID, node.Name, string(node.Outbound), preserve, preserve); err != nil {
			return err
		}
		delete(existing, node.Name)
	}
	for name := range existing {
		if _, err := tx.ExecContext(ctx, "DELETE FROM nodes WHERE subscription_id = ? AND name = ?", subscriptionID, name); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LoadDiagnostics(ctx context.Context) (map[string]Diagnostics, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT id, latency_json, ip_check_json FROM nodes WHERE latency_json IS NOT NULL OR ip_check_json IS NOT NULL")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := make(map[string]Diagnostics)
	for rows.Next() {
		var id string
		var latency, ipCheck sql.NullString
		if err := rows.Scan(&id, &latency, &ipCheck); err != nil {
			return nil, err
		}
		var result Diagnostics
		if latency.Valid {
			if err := json.Unmarshal([]byte(latency.String), &result.Latency); err != nil {
				return nil, fmt.Errorf("decode latency for node %s: %w", id, err)
			}
		}
		if ipCheck.Valid {
			if err := json.Unmarshal([]byte(ipCheck.String), &result.IPCheck); err != nil {
				return nil, fmt.Errorf("decode IP check for node %s: %w", id, err)
			}
		}
		results[id] = result
	}
	return results, rows.Err()
}

// RecordProbe updates only the supplied result and only while the persisted
// node still has the configuration used by the probe.
func (s *Store) RecordProbe(ctx context.Context, id string, outbound json.RawMessage, result Diagnostics) (bool, error) {
	var latency, ipCheck any
	if result.Latency != nil {
		data, err := json.Marshal(result.Latency)
		if err != nil {
			return false, err
		}
		latency = string(data)
	}
	if result.IPCheck != nil {
		data, err := json.Marshal(result.IPCheck)
		if err != nil {
			return false, err
		}
		ipCheck = string(data)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var current []byte
	if err := tx.QueryRowContext(ctx, "SELECT outbound_json FROM nodes WHERE id = ?", id).Scan(&current); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if !domain.EqualOutbound(current, outbound) {
		return false, nil
	}
	updated, err := tx.ExecContext(ctx, `UPDATE nodes SET
		latency_json = COALESCE(?, latency_json), ip_check_json = COALESCE(?, ip_check_json)
		WHERE id = ? AND outbound_json = ?`, latency, ipCheck, id, string(current))
	if err != nil {
		return false, err
	}
	count, err := updated.RowsAffected()
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Store) Delete(ctx context.Context, generation uint64, id string) error {
	return s.write(ctx, generation, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, "DELETE FROM subscriptions WHERE id = ?", id)
		return err
	})
}

func (s *Store) write(ctx context.Context, generation uint64, change func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := change(tx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE app_state SET generation = ? WHERE id = 1", generation); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RecordFailure(ctx context.Context, id string, at time.Time, message string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE subscriptions SET last_attempt_at = ?, last_error = ? WHERE id = ?", formatTime(&at), message, id)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

func formatTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func parseTime(value sql.NullString) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, value.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}
