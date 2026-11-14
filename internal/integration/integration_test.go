package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"onesocks/internal/api"
	"onesocks/internal/config"
	"onesocks/internal/domain"
	"onesocks/internal/engine/singbox"
	"onesocks/internal/service"
	"onesocks/internal/socks"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	boxjson "github.com/sagernet/sing/common/json"
	"golang.org/x/net/proxy"
)

func startShadowsocks(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	ctx := singbox.Context(context.Background())
	raw := fmt.Sprintf(`{"log":{"disabled":true},"inbounds":[{"type":"shadowsocks","tag":"test-in","listen":"127.0.0.1","listen_port":%d,"method":"aes-128-gcm","password":"integration-secret"}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","default_domain_resolver":"local"},"dns":{"servers":[{"type":"local","tag":"local"}]}}`, port)
	var opts option.Options
	if err := boxjson.UnmarshalContext(ctx, []byte(raw), &opts); err != nil {
		t.Fatal(err)
	}
	server, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatal(err)
	}
	if err = server.Start(); err != nil {
		_ = server.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	// Exercise bootstrap DNS for the proxy server itself as well as target DNS.
	return fmt.Sprintf("localhost:%d", port)
}

func TestAPIToSOCKSToSingBoxAndRefresh(t *testing.T) {
	remote := startShadowsocks(t)
	credential := base64.RawStdEncoding.EncodeToString([]byte("aes-128-gcm:integration-secret"))
	var body atomic.Value
	body.Store("ss://" + credential + "@" + remote + "#香港01")
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body.Load().(string)) }))
	defer source.Close()
	opts := service.Options{DataDir: t.TempDir(), FetchTimeout: 3 * time.Second, RefreshInterval: time.Hour, DrainTimeout: time.Second, Factory: singbox.New, Version: "test"}
	manager, err := service.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	control := httptest.NewServer(api.New(manager, config.Config{APIToken: "admin-secret"}))
	defer control.Close()
	request := func(method, path string, payload any, want int) []byte {
		t.Helper()
		var buf bytes.Buffer
		if payload != nil {
			if err := json.NewEncoder(&buf).Encode(payload); err != nil {
				t.Fatal(err)
			}
		}
		req, err := http.NewRequest(method, control.URL+path, &buf)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer admin-secret")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != want {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, resp.StatusCode, want, data)
		}
		return data
	}
	var first domain.MutationResult
	if err := json.Unmarshal(request("POST", "/api/subscriptions", domain.SubscriptionInput{Name: "机场A", URL: source.URL + "/first?token=subscription-token#GLaDOS"}, 201), &first); err != nil {
		t.Fatal(err)
	}
	if first.Subscription.URL != source.URL+"/first?token=subscription-token" {
		t.Fatalf("subscription URL was masked: %q", first.Subscription.URL)
	}
	request("POST", "/api/subscribe", domain.SubscriptionInput{URL: source.URL + "/second"}, 201)
	var list domain.NodeList
	if err := json.Unmarshal(request("GET", "/api/nodes", nil, 200), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 2 {
		t.Fatalf("want 2 nodes, got %+v", list)
	}
	var node domain.NodeInfo
	for _, n := range list.Items {
		if n.SubscriptionID == first.Subscription.ID {
			node = n
		}
	}
	if node.ID == "" || node.Name != "机场A-香港01" {
		t.Fatalf("unexpected node: %+v", node)
	}
	if !bytes.Contains(node.Outbound, []byte("integration-secret")) {
		t.Fatal("node outbound credentials were omitted")
	}
	if !bytes.Contains(request("GET", "/api/subscriptions", nil, 200), []byte("subscription-token")) {
		t.Fatal("subscription list omitted the URL token")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- socks.New(manager, socks.Config{}).Serve(socksCtx, listener) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	dial := func(username, target string) (net.Conn, error) {
		d, err := proxy.SOCKS5("tcp", listener.Addr().String(), &proxy.Auth{User: username, Password: "anything"}, &net.Dialer{Timeout: 3 * time.Second})
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return d.(proxy.ContextDialer).DialContext(ctx, "tcp", target)
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "through-sing-box") }))
	defer target.Close()
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dial(node.Username, address)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(data) != "through-sing-box" {
		t.Fatalf("proxy response %q: %v", data, err)
	}
	// Keep a real TCP session alive across two generation changes.
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		conn, err := echo.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()
	conn, err := dial(node.Name, echo.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	checkEcho := func(text string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(conn, text); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(text))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatal(err)
		}
		if string(got) != text {
			t.Fatalf("echo %q", got)
		}
	}
	checkEcho("before")
	// Authentication must pin the old runtime even when CONNECT arrives only
	// after a refresh removes that username from the current node pool.
	pending := authenticateOnly(t, listener.Addr().String(), node.Username)
	body.Store("ss://" + credential + "@" + remote + "#香港改名")
	request("POST", "/api/subscriptions/"+first.Subscription.ID+"/refresh", nil, 200)
	packet := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], uint16(target.Listener.Addr().(*net.TCPAddr).Port))
	packet = append(packet, []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")...)
	if _, err := pending.Write(packet); err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	if _, err := io.ReadFull(pending, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != 5 || header[1] != 0 || header[2] != 0 || (header[3] != 1 && header[3] != 4) {
		t.Fatalf("authenticated session lost its runtime after refresh: %v", header)
	}
	boundSize := int64(6)
	if header[3] == 4 {
		boundSize = 18
	}
	if _, err := io.CopyN(io.Discard, pending, boundSize); err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(pending)
	_ = pending.Close()
	if err != nil || !bytes.Contains(response, []byte("through-sing-box")) {
		t.Fatalf("authenticated session could not use its pinned runtime: %q, %v", response, err)
	}
	if err := json.Unmarshal(request("GET", "/api/nodes?subscription_id="+url.QueryEscape(first.Subscription.ID), nil, 200), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 || list.Items[0].ID == node.ID || list.Items[0].ID != domain.NodeID(first.Subscription.ID, "香港改名") || !strings.HasSuffix(list.Items[0].Name, "香港改名") {
		t.Fatalf("node rename did not replace its identity: %+v", list)
	}
	renamed := list.Items[0]
	for _, username := range []string{node.Username, node.Name} {
		if c, err := dial(username, target.Listener.Addr().String()); err == nil {
			_ = c.Close()
			t.Fatalf("renamed node accepted old username %q", username)
		}
	}
	for _, username := range []string{renamed.Username, renamed.Name} {
		c, err := dial(username, target.Listener.Addr().String())
		if err != nil {
			t.Fatalf("renamed node rejected new username %q: %v", username, err)
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(c, "GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"); err != nil {
			_ = c.Close()
			t.Fatal(err)
		}
		response, err := io.ReadAll(c)
		_ = c.Close()
		if err != nil || !bytes.Contains(response, []byte("through-sing-box")) {
			t.Fatalf("new username failed to forward through the renamed node: %q, %v", response, err)
		}
	}
	checkEcho("after-refresh")
	request("DELETE", "/api/subscriptions/"+first.Subscription.ID, nil, 204)
	for _, username := range []string{renamed.Username, renamed.Name} {
		if c, err := dial(username, echo.Addr().String()); err == nil {
			_ = c.Close()
			t.Fatal("deleted node accepted a new connection")
		}
	}
	checkEcho("after-delete")
	_ = conn.Close()
	transport.CloseIdleConnections()
	// The remaining subscription and its node IDs survive a process restart.
	remaining := manager.Nodes("")
	if len(remaining.Items) != 1 {
		t.Fatalf("unexpected remaining nodes: %+v", remaining)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	restored, err := service.New(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if got := restored.Nodes(""); len(got.Items) != 1 || got.Items[0].ID != remaining.Items[0].ID {
		t.Fatalf("cache restore failed: %+v", got)
	}
}

func authenticateOnly(t *testing.T, address, username string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	packet := append([]byte{5, 1, 2, 1, byte(len(username))}, []byte(username)...)
	packet = append(packet, 8)
	packet = append(packet, []byte("anything")...)
	if _, err := conn.Write(packet); err != nil {
		t.Fatal(err)
	}
	var replies [4]byte
	if _, err := io.ReadFull(conn, replies[:]); err != nil {
		t.Fatal(err)
	}
	if replies != [4]byte{5, 2, 1, 0} {
		t.Fatalf("SOCKS5 authentication failed: %v", replies)
	}
	return conn
}
