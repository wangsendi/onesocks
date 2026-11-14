package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/parser"
	"onesocks/internal/store"
)

func (m *Manager) prepare(sub store.Subscription) (store.Subscription, error) {
	if strings.TrimSpace(sub.Name) == "" {
		return sub, coded("invalid_input", "subscription name must not be empty")
	}
	// Normalize labels for deduplication when possible, but let the HTTP client
	// attempt the URL and report any unsupported or malformed URL as fetch_failed.
	if u, err := url.Parse(sub.URL); err == nil {
		u.Fragment, u.RawFragment = "", ""
		sub.URL = u.String()
	}
	if sub.RefreshInterval == "" {
		sub.RefreshInterval = m.options.RefreshInterval.String()
	}
	if d, err := time.ParseDuration(sub.RefreshInterval); err != nil || d <= 0 {
		return sub, coded("invalid_input", "refresh_interval must be a positive duration")
	}
	return sub, nil
}

func checkConflict(s store.State, sub store.Subscription) error {
	for _, other := range s.Subscriptions {
		if other.ID != sub.ID && (other.Name == sub.Name || other.URL == sub.URL) {
			return coded("conflict", "subscription name or URL already exists")
		}
	}
	return nil
}

func (m *Manager) Create(ctx context.Context, in domain.SubscriptionInput) (domain.MutationResult, error) {
	var id [10]byte
	if _, err := rand.Read(id[:]); err != nil {
		return domain.MutationResult{}, coded("storage_failed", "could not allocate subscription ID")
	}
	if in.Name == "" {
		in.Name = "subscription-" + hex.EncodeToString(id[:4])
	}
	sub, err := m.prepare(store.Subscription{ID: "s_" + hex.EncodeToString(id[:]), Name: in.Name, URL: in.URL, RefreshInterval: in.RefreshInterval})
	if err != nil {
		return domain.MutationResult{}, err
	}
	if err := m.begin(ctx); err != nil {
		return domain.MutationResult{}, err
	}
	defer m.end()
	s := m.current()
	if err := checkConflict(s, sub); err != nil {
		return domain.MutationResult{}, err
	}
	warnings, err := m.fetch(ctx, &sub)
	if err != nil {
		return domain.MutationResult{}, err
	}
	s.Subscriptions = append(s.Subscriptions, sub)
	if err = m.commit(ctx, s, sub.ID); err != nil {
		return domain.MutationResult{}, err
	}
	return domain.MutationResult{Subscription: info(sub), Generation: s.Generation + 1, Warnings: warnings}, nil
}

func (m *Manager) Update(ctx context.Context, id string, p domain.SubscriptionPatch) (domain.MutationResult, error) {
	if err := m.begin(ctx); err != nil {
		return domain.MutationResult{}, err
	}
	defer m.end()
	s := m.current()
	i := find(s, id)
	if i < 0 {
		return domain.MutationResult{}, coded("not_found", "subscription not found")
	}
	sub := s.Subscriptions[i]
	if p.Name != nil {
		sub.Name = *p.Name
	}
	if p.URL != nil {
		sub.URL = *p.URL
	}
	if p.RefreshInterval != nil {
		sub.RefreshInterval = *p.RefreshInterval
	}
	sub, err := m.prepare(sub)
	if err != nil {
		return domain.MutationResult{}, err
	}
	if err := checkConflict(s, sub); err != nil {
		return domain.MutationResult{}, err
	}
	var warnings []string
	if sub.URL != s.Subscriptions[i].URL {
		warnings, err = m.fetch(ctx, &sub)
		if err != nil {
			return domain.MutationResult{}, err
		}
	}
	s.Subscriptions[i] = sub
	if err := m.commit(ctx, s, id); err != nil {
		return domain.MutationResult{}, err
	}
	return domain.MutationResult{Subscription: info(sub), Generation: s.Generation + 1, Warnings: warnings}, nil
}

func (m *Manager) Refresh(ctx context.Context, id string) (domain.MutationResult, error) {
	if err := m.begin(ctx); err != nil {
		return domain.MutationResult{}, err
	}
	defer m.end()
	s := m.current()
	i := find(s, id)
	if i < 0 {
		return domain.MutationResult{}, coded("not_found", "subscription not found")
	}
	sub := s.Subscriptions[i]
	warnings, err := m.fetch(ctx, &sub)
	if err != nil {
		m.recordFailure(s, i, err)
		return domain.MutationResult{}, err
	}
	s.Subscriptions[i] = sub
	if err = m.commit(ctx, s, id); err != nil {
		m.recordFailure(m.current(), i, err)
		return domain.MutationResult{}, err
	}
	return domain.MutationResult{Subscription: info(sub), Generation: s.Generation + 1, Warnings: warnings}, nil
}

func (m *Manager) Delete(ctx context.Context, id string) error {
	if err := m.begin(ctx); err != nil {
		return err
	}
	defer m.end()
	s := m.current()
	i := find(s, id)
	if i < 0 {
		return coded("not_found", "subscription not found")
	}
	s.Subscriptions = append(s.Subscriptions[:i], s.Subscriptions[i+1:]...)
	return m.commit(ctx, s, id)
}

func (m *Manager) fetch(ctx context.Context, sub *store.Subscription) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, m.options.FetchTimeout)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sub.URL, nil)
	if err != nil {
		return nil, coded("fetch_failed", "could not create subscription request: "+err.Error())
	}
	req.Header.Set("User-Agent", "OneSocks/"+m.options.Version)
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, coded("fetch_failed", "subscription fetch failed: "+err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, coded("fetch_failed", fmt.Sprintf("subscription returned HTTP %d", resp.StatusCode))
	}
	// net/http negotiates and decodes gzip. Reject any encoding left over
	// before passing the response body to the subscription parser.
	switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
	case "", "identity":
	default:
		return nil, coded("fetch_failed", "unsupported subscription content encoding")
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, coded("fetch_failed", "could not read subscription body: "+err.Error())
	}
	result, err := parser.Parse(data)
	if err != nil {
		message := err.Error()
		if len(result.Warnings) > 0 {
			message += "; " + strings.Join(result.Warnings, "; ")
		}
		return nil, coded("parse_failed", message)
	}
	now := time.Now().UTC()
	sub.Nodes = domain.UniqueNodes(result.Nodes)
	sub.LastAttemptAt = &now
	sub.LastSuccessAt = &now
	sub.LastError = ""
	return result.Warnings, nil
}

func (m *Manager) recordFailure(s store.State, i int, err error) {
	now := time.Now().UTC()
	s.Subscriptions[i].LastAttemptAt = &now
	s.Subscriptions[i].LastError = err.Error()
	if err := m.store.RecordFailure(m.ctx, s.Subscriptions[i].ID, now, err.Error()); err != nil {
		slog.Warn("could not persist refresh failure", "subscription_id", s.Subscriptions[i].ID, "error", err)
	}
	m.mu.Lock()
	m.state = s
	m.mu.Unlock()
}

func info(sub store.Subscription) domain.SubscriptionInfo {
	return domain.SubscriptionInfo{ID: sub.ID, Name: sub.Name, URL: sub.URL, RefreshInterval: sub.RefreshInterval, LastAttemptAt: sub.LastAttemptAt, LastSuccessAt: sub.LastSuccessAt, LastError: sub.LastError, NodeCount: len(sub.Nodes), Stale: sub.LastError != ""}
}

func (m *Manager) Subscriptions() []domain.SubscriptionInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]domain.SubscriptionInfo, 0, len(m.state.Subscriptions))
	for _, s := range m.state.Subscriptions {
		items = append(items, info(s))
	}
	return items
}

// Start refreshes cached subscriptions on startup, then checks due times.
func (m *Manager) Start() {
	m.background.Go(func() {
		m.refreshDue(time.Time{})
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case now := <-ticker.C:
				m.refreshDue(now)
			}
		}
	})
}

// A zero time refreshes every cached subscription on startup.
func (m *Manager) refreshDue(now time.Time) {
	for _, sub := range m.current().Subscriptions {
		interval, err := time.ParseDuration(sub.RefreshInterval)
		if err != nil {
			interval = m.options.RefreshInterval
		}
		if !now.IsZero() && sub.LastAttemptAt != nil && now.Sub(*sub.LastAttemptAt) < interval {
			continue
		}
		if _, err := m.Refresh(m.ctx, sub.ID); err != nil && m.ctx.Err() == nil {
			slog.Warn("subscription refresh failed", "subscription_id", sub.ID, "error", err.Error())
		}
	}
}
