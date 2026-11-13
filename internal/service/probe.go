package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/store"
)

const (
	defaultLatencyURL = "https://cp.cloudflare.com/generate_204"
	defaultIPCheckURL = "https://iplogs.com/v1/check"
)

type nodeDiagnostics struct {
	outbound json.RawMessage
	latency  *domain.LatencyResult
	ipCheck  *domain.IPCheckResult
	running  map[string]bool
}

// Called with m.mu held when publishing a generation. Retaining the state
// object also lets an in-flight probe recognize an unchanged node.
func (m *Manager) reconcileDiagnostics(nodes []domain.NodeInfo) {
	next := make(map[string]*nodeDiagnostics, len(nodes))
	for _, node := range nodes {
		state := m.diagnostics[node.ID]
		if state == nil || !domain.EqualOutbound(state.outbound, node.Outbound) {
			state = &nodeDiagnostics{outbound: append(json.RawMessage(nil), node.Outbound...), running: make(map[string]bool)}
		}
		next[node.ID] = state
	}
	m.diagnostics = next
}

// Called with m.mu held; return copies so callers cannot mutate cached results.
func (m *Manager) nodeInfo(node domain.NodeInfo) domain.NodeInfo {
	node.Outbound = append(json.RawMessage(nil), node.Outbound...)
	state := m.diagnostics[node.ID]
	if state == nil {
		return node
	}
	if state.latency != nil {
		result := *state.latency
		if result.Milliseconds != nil {
			value := *result.Milliseconds
			result.Milliseconds = &value
		}
		node.Latency = &result
	}
	if state.ipCheck != nil {
		result := *state.ipCheck
		result.Data = append(json.RawMessage(nil), result.Data...)
		node.IPCheck = &result
	}
	return node
}

func (m *Manager) Probe(ctx context.Context, id, kind string) (domain.NodeInfo, error) {
	if kind != "latency" && kind != "ip-check" {
		return domain.NodeInfo{}, coded("invalid_input", "unknown node probe type")
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return domain.NodeInfo{}, coded("closed", "service closed")
	}
	state := m.diagnostics[id]
	if state == nil {
		m.mu.Unlock()
		return domain.NodeInfo{}, coded("not_found", "node not found")
	}
	if state.running[kind] {
		m.mu.Unlock()
		return domain.NodeInfo{}, coded("conflict", "this node probe is already running")
	}
	lease, err := m.active.acquire(id)
	if err != nil {
		m.mu.Unlock()
		return domain.NodeInfo{}, err
	}
	state.running[kind] = true
	target := m.ipCheckURL
	if kind == "latency" {
		target = m.latencyURL
	}
	m.mu.Unlock()

	latency, ipCheck := m.runProbe(ctx, lease, kind, target)

	m.mu.Lock()
	defer m.mu.Unlock()
	delete(state.running, kind)
	current := m.diagnostics[id]
	if current == nil {
		return domain.NodeInfo{}, coded("not_found", "node was removed during the probe")
	}
	if current != state {
		return domain.NodeInfo{}, coded("conflict", "node configuration changed during the probe; retry")
	}
	stored, err := m.store.RecordProbe(m.ctx, id, state.outbound, store.Diagnostics{Latency: latency, IPCheck: ipCheck})
	if err != nil {
		return domain.NodeInfo{}, coded("storage_failed", "could not persist node probe: "+err.Error())
	}
	if !stored {
		return domain.NodeInfo{}, coded("conflict", "node configuration changed during the probe; retry")
	}
	if kind == "latency" {
		state.latency = latency
	} else {
		state.ipCheck = ipCheck
	}
	for _, node := range m.active.nodes {
		if node.ID == id {
			return m.nodeInfo(node), nil
		}
	}
	return domain.NodeInfo{}, coded("not_found", "node not found")
}

func (m *Manager) runProbe(ctx context.Context, lease domain.Lease, kind, target string) (*domain.LatencyResult, *domain.IPCheckResult) {
	defer lease.Close()
	timeout := 40 * time.Second
	if kind == "latency" {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(m.ctx, cancel)
	defer stop()
	// Proxy is nil and DialContext is always the selected lease. There is no
	// environment-proxy or direct-dial fallback, including for HTTPS.
	transport := &http.Transport{DialContext: lease.DialContext, DisableKeepAlives: kind != "latency"}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if kind == "latency" {
		result := checkLatency(ctx, client, target)
		return &result, nil
	}
	result := checkIP(ctx, client, target)
	return nil, &result
}

func checkLatency(ctx context.Context, client *http.Client, target string) domain.LatencyResult {
	result := domain.LatencyResult{}
	var first time.Duration
	for round := 0; round < 2; round++ {
		reused := false
		connections := 0
		trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
			reused = info.Reused
			connections++
		}}
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodHead, target, nil)
		if err != nil {
			result.Error = err.Error()
			break
		}
		start := time.Now()
		response, err := client.Do(req)
		elapsed := time.Since(start)
		if err != nil {
			result.Error = err.Error()
			break
		}
		_ = response.Body.Close()
		if round == 1 && connections > 1 {
			// net/http may replay HEAD on a fresh connection after a reused
			// connection fails. That retry must not hide a failed second round.
			result.Error = "second latency request failed on the reused connection"
			break
		}
		if round == 0 {
			first = elapsed
			if response.Close {
				milliseconds := first.Milliseconds()
				result.Milliseconds = &milliseconds
				result.Warning = "server did not reuse the connection; latency includes connection setup"
				break
			}
			continue
		}
		result.Reused = reused
		if !reused {
			elapsed = first
			result.Warning = "server did not reuse the connection; latency includes connection setup"
		}
		milliseconds := elapsed.Milliseconds()
		result.Milliseconds = &milliseconds
	}
	result.CheckedAt = time.Now().UTC()
	return result
}

func checkIP(ctx context.Context, client *http.Client, target string) (result domain.IPCheckResult) {
	defer func() { result.CheckedAt = time.Now().UTC() }()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader("{}"))
	if err != nil {
		result.Error = err.Error()
		return result
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		result.Error = err.Error()
		return result
	}
	if json.Valid(body) {
		result.Data = body
	}
	if response.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("IP check returned HTTP %d", response.StatusCode)
		if detail := strings.TrimSpace(string(body)); detail != "" {
			result.Error += ": " + detail
		}
		if retry := response.Header.Get("Retry-After"); retry != "" {
			result.Error += "; Retry-After: " + retry
		}
	} else if result.Data == nil {
		result.Error = "IP check returned invalid JSON"
	} else {
		var data struct {
			IPInfo struct {
				IP string `json:"ip"`
			} `json:"ip_info"`
		}
		if err := json.Unmarshal(result.Data, &data); err != nil || net.ParseIP(data.IPInfo.IP) == nil {
			result.Error = "IP check response did not include a valid ip_info.ip"
		}
	}
	return result
}
