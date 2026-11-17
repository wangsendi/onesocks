package domain

import (
	"bytes"
	"cmp"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"net"
	"reflect"
	"slices"
	"time"
)

// NodeSpec is a subscription entry expressed as a sing-box outbound JSON object.
// Name and the subscription ID determine the node identity.
type NodeSpec struct {
	Name     string          `json:"name"`
	Outbound json.RawMessage `json:"outbound"`
}

func NodeID(subscriptionID, name string) string {
	sum := md5.Sum([]byte(subscriptionID + "\x00" + name))
	return "n_" + hex.EncodeToString(sum[:])
}

// EqualOutbound ignores JSON object key ordering and whitespace. UseNumber
// avoids rounding large configuration integers while comparing decoded values.
func EqualOutbound(a, b json.RawMessage) bool {
	if bytes.Equal(a, b) {
		return true
	}
	if !json.Valid(a) || !json.Valid(b) {
		return false
	}
	var first, second any
	left := json.NewDecoder(bytes.NewReader(a))
	left.UseNumber()
	right := json.NewDecoder(bytes.NewReader(b))
	right.UseNumber()
	if left.Decode(&first) != nil || right.Decode(&second) != nil {
		return false
	}
	return reflect.DeepEqual(first, second)
}

// UniqueNodes keeps the last entry for each name and returns nodes by name.
func UniqueNodes(nodes []NodeSpec) []NodeSpec {
	byName := make(map[string]NodeSpec, len(nodes))
	for _, node := range nodes {
		byName[node.Name] = node
	}
	result := make([]NodeSpec, 0, len(byName))
	for _, node := range byName {
		result = append(result, node)
	}
	slices.SortFunc(result, func(a, b NodeSpec) int { return cmp.Compare(a.Name, b.Name) })
	return result
}

type ParseResult struct {
	Nodes    []NodeSpec
	Warnings []string
}

type NodeInfo struct {
	ID             string          `json:"id"`
	Username       string          `json:"username"`
	Name           string          `json:"name"`
	Protocol       string          `json:"protocol"`
	SubscriptionID string          `json:"subscription_id"`
	Health         string          `json:"health"`
	Outbound       json.RawMessage `json:"outbound"`
	Latency        *LatencyResult  `json:"latency,omitempty"`
	IPCheck        *IPCheckResult  `json:"ip_check,omitempty"`
}

type LatencyResult struct {
	CheckedAt    time.Time `json:"checked_at"`
	Milliseconds *int64    `json:"milliseconds"`
	Reused       bool      `json:"reused"`
	Warning      string    `json:"warning,omitempty"`
	Error        string    `json:"error,omitempty"`
}

type IPCheckResult struct {
	CheckedAt time.Time       `json:"checked_at"`
	Data      json.RawMessage `json:"data,omitempty"`
	Error     string          `json:"error,omitempty"`
}

type NodeList struct {
	Items      []NodeInfo `json:"items"`
	Generation uint64     `json:"generation"`
}

type SubscriptionInfo struct {
	ID              string               `json:"id"`
	Name            string               `json:"name"`
	URL             string               `json:"url"`
	RefreshInterval string               `json:"refresh_interval"`
	LastAttemptAt   *time.Time           `json:"last_attempt_at,omitempty"`
	LastSuccessAt   *time.Time           `json:"last_success_at,omitempty"`
	LastError       string               `json:"last_error,omitempty"`
	NodeCount       int                  `json:"node_count"`
	Stale           bool                 `json:"stale"`
	Traffic         *SubscriptionTraffic `json:"traffic,omitempty"`
}

type SubscriptionTraffic struct {
	UploadBytes   *uint64    `json:"upload_bytes,omitempty"`
	DownloadBytes *uint64    `json:"download_bytes,omitempty"`
	TotalBytes    *uint64    `json:"total_bytes,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

func (t *SubscriptionTraffic) Clone() *SubscriptionTraffic {
	if t == nil {
		return nil
	}
	copy := *t
	for _, field := range []**uint64{&copy.UploadBytes, &copy.DownloadBytes, &copy.TotalBytes} {
		if *field != nil {
			value := **field
			*field = &value
		}
	}
	if t.ExpiresAt != nil {
		value := *t.ExpiresAt
		copy.ExpiresAt = &value
	}
	return &copy
}

type SubscriptionInput struct {
	Name            string `json:"name"`
	URL             string `json:"url"`
	RefreshInterval string `json:"refresh_interval,omitempty"`
}

type SubscriptionPatch struct {
	Name            *string `json:"name,omitempty"`
	URL             *string `json:"url,omitempty"`
	RefreshInterval *string `json:"refresh_interval,omitempty"`
}

type MutationResult struct {
	Subscription SubscriptionInfo `json:"subscription"`
	Generation   uint64           `json:"generation"`
	Warnings     []string         `json:"warnings,omitempty"`
}

type Status struct {
	Version           string `json:"version"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	NodeCount         int    `json:"node_count"`
	SubscriptionCount int    `json:"subscription_count"`
	Generation        uint64 `json:"generation"`
	Ready             bool   `json:"ready"`
	Updating          bool   `json:"updating"`
}

// Lease pins a runtime generation until the SOCKS session has finished.
type Lease interface {
	DialContext(context.Context, string, string) (net.Conn, error)
	Close() error
}

type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }
