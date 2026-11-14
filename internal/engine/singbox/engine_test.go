package singbox

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"onesocks/internal/engine"
	"onesocks/internal/parser"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
	boxjson "github.com/sagernet/sing/common/json"
)

const integrationUUID = "11111111-2222-4333-8444-555555555555"

// These tests use real sing-box servers and loopback targets, so no subscription
// provider, public website or external credentials are required.
func TestRealProxyProtocols(t *testing.T) {
	certificate, key := selfSigned(t)
	for _, protocol := range []string{"shadowsocks", "vless", "vmess", "trojan", "hysteria2", "anytls"} {
		t.Run(protocol, func(t *testing.T) {
			port := freePort(t, protocol == "hysteria2")
			inbound := map[string]any{"type": protocol, "tag": "proxy", "listen": "127.0.0.1", "listen_port": port}
			var share string
			switch protocol {
			case "shadowsocks":
				inbound["method"], inbound["password"] = "aes-128-gcm", "integration-secret"
				share = fmt.Sprintf("ss://aes-128-gcm:integration-secret@127.0.0.1:%d#SS", port)
			case "vless":
				inbound["users"] = []any{map[string]any{"uuid": integrationUUID}}
				share = fmt.Sprintf("vless://%s@127.0.0.1:%d?security=none#VLESS", integrationUUID, port)
			case "vmess":
				inbound["users"] = []any{map[string]any{"uuid": integrationUUID}}
				// Exercise the sing-box JSON parser as well as the VMess wire protocol.
				share = fmt.Sprintf(`{"outbounds":[{"type":"vmess","tag":"VMess","server":"127.0.0.1","server_port":%d,"uuid":%q,"security":"auto"}]}`, port, integrationUUID)
			case "trojan":
				inbound["users"] = []any{map[string]any{"password": "integration-secret"}}
				inbound["tls"] = map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}}
				share = fmt.Sprintf("trojan://integration-secret@127.0.0.1:%d?insecure=1&sni=localhost#Trojan", port)
			case "anytls":
				inbound["users"] = []any{map[string]any{"password": "integration-secret"}}
				inbound["tls"] = map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}}
				share = fmt.Sprintf("anytls://integration-secret@127.0.0.1:%d?insecure=1&sni=localhost#AnyTLS", port)
			case "hysteria2":
				inbound["users"] = []any{map[string]any{"password": "integration-secret"}}
				inbound["tls"] = map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}}
				inbound["obfs"] = map[string]any{"type": "salamander", "password": "integration-obfs"}
				share = fmt.Sprintf("hy2://integration-secret@127.0.0.1:%d?insecure=1&sni=localhost&obfs=salamander&obfs-password=integration-obfs#HY2", port)
			}
			startProxy(t, inbound)
			parsed, err := parser.Parse([]byte(share))
			if err != nil || len(parsed.Nodes) != 1 {
				t.Fatalf("parse protocol config: %v, warnings=%v", err, parsed.Warnings)
			}
			client, err := New(context.Background(), []engine.Node{{ID: "node", Outbound: parsed.Nodes[0].Outbound}})
			if err != nil {
				t.Fatalf("create real outbound: %v", err)
			}
			t.Cleanup(func() { _ = client.Close() })
			target, _ := echoTarget(t, "tcp", "127.0.0.1:0", "")
			assertEcho(t, client, "node", target)
			// The proxy receives a domain destination and resolves it on the server.
			_, targetPort, _ := net.SplitHostPort(target)
			assertEcho(t, client, "node", net.JoinHostPort("localhost", targetPort))
			t.Run("udp", func(t *testing.T) {
				target := udpEchoTarget(t, "127.0.0.1:0")
				assertUDPEcho(t, client, "node", target)
				_, port, _ := net.SplitHostPort(target)
				assertUDPEcho(t, client, "node", net.JoinHostPort("localhost", port))
			})
			t.Run("ipv6-target", func(t *testing.T) {
				probe, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skip("IPv6 loopback is unavailable")
				}
				_ = probe.Close()
				ipv6, _ := echoTarget(t, "tcp6", "[::1]:0", "")
				assertEcho(t, client, "node", ipv6)
				assertUDPEcho(t, client, "node", udpEchoTarget(t, "[::1]:0"))
			})
		})
	}
}

func TestServerFirstAndConcurrentEngineInstances(t *testing.T) {
	port := freePort(t, false)
	startProxy(t, map[string]any{"type": "shadowsocks", "tag": "proxy", "listen": "127.0.0.1", "listen_port": port, "method": "aes-128-gcm", "password": "integration-secret", "network": "tcp"})
	parsed, err := parser.Parse([]byte(fmt.Sprintf("ss://aes-128-gcm:integration-secret@127.0.0.1:%d#SS", port)))
	if err != nil {
		t.Fatal(err)
	}
	nodes := []engine.Node{{ID: "node", Outbound: parsed.Nodes[0].Outbound}}
	first, err := New(context.Background(), nodes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = first.Close() })
	second, err := New(context.Background(), nodes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	const banner = "SSH-2.0-OneSocks-integration\r\n"
	target, _ := echoTarget(t, "tcp", "127.0.0.1:0", banner)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := first.DialContext(ctx, "node", "tcp", target)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(banner))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("server-first banner before any application write: %v", err)
	}
	if string(buf) != banner {
		t.Fatalf("unexpected banner %q", buf)
	}
	// Closing one generation must not close another instance or this target.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	echo, _ := echoTarget(t, "tcp", "127.0.0.1:0", "")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) { defer wg.Done(); assertEcho(t, second, "node", echo) }(i)
	}
	wg.Wait()
}

func TestRealWebSocketAndGRPCTransports(t *testing.T) {
	certificate, key := selfSigned(t)
	for _, protocol := range []string{"vless", "vmess", "trojan"} {
		for _, transport := range []string{"ws", "grpc"} {
			t.Run(protocol+"/"+transport, func(t *testing.T) {
				port := freePort(t, false)
				inbound := map[string]any{"type": protocol, "tag": "proxy", "listen": "127.0.0.1", "listen_port": port}
				params := url.Values{"type": []string{transport}}
				if transport == "ws" {
					inbound["transport"] = map[string]any{"type": "ws", "path": "/proxy"}
					params.Set("path", "/proxy")
				} else {
					inbound["transport"] = map[string]any{"type": "grpc", "service_name": "proxy-service"}
					params.Set("serviceName", "proxy-service")
				}
				var share string
				if protocol == "trojan" {
					inbound["users"] = []any{map[string]any{"password": "integration-secret"}}
					inbound["tls"] = map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}}
					params.Set("insecure", "1")
					params.Set("sni", "localhost")
					share = fmt.Sprintf("trojan://integration-secret@127.0.0.1:%d?%s#transport", port, params.Encode())
				} else {
					inbound["users"] = []any{map[string]any{"uuid": integrationUUID}}
					if protocol == "vless" {
						share = fmt.Sprintf("vless://%s@127.0.0.1:%d?%s#transport", integrationUUID, port, params.Encode())
					} else {
						path := "/proxy"
						if transport == "grpc" {
							path = "proxy-service"
						}
						raw, _ := json.Marshal(map[string]any{"v": "2", "ps": "transport", "add": "127.0.0.1", "port": port, "id": integrationUUID, "net": transport, "type": "none", "path": path})
						share = "vmess://" + base64.StdEncoding.EncodeToString(raw)
					}
				}
				startProxy(t, inbound)
				parsed, err := parser.Parse([]byte(share))
				if err != nil {
					t.Fatalf("parse transport configuration: %v (%v)", err, parsed.Warnings)
				}
				client, err := New(context.Background(), []engine.Node{{ID: "node", Outbound: parsed.Nodes[0].Outbound}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				target, _ := echoTarget(t, "tcp", "127.0.0.1:0", "")
				assertEcho(t, client, "node", target)
			})
		}
	}
}

func TestMissingOrFailedNodeNeverDialsTargetDirectly(t *testing.T) {
	target, accepted := echoTarget(t, "tcp", "127.0.0.1:0", "")
	// Reserve a port until immediately before dialing to obtain a closed endpoint.
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portText, _ := net.SplitHostPort(closed.Addr().String())
	port, _ := strconv.Atoi(portText)
	_ = closed.Close()
	raw := json.RawMessage(fmt.Sprintf(`{"type":"shadowsocks","server":"127.0.0.1","server_port":%d,"method":"aes-128-gcm","password":"integration-secret"}`, port))
	client, err := New(context.Background(), []engine.Node{{ID: "bad-node", Outbound: raw}})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, id := range []string{"missing-node", "bad-node"} {
		conn, err := client.DialContext(ctx, id, "tcp", target)
		if conn != nil {
			_ = conn.Close()
		}
		if err == nil {
			t.Fatalf("unexpected success through %q", id)
		}
	}
	if accepted.Load() != 0 {
		t.Fatal("target was contacted despite an invalid node")
	}
}

func TestRealShadowsocksCloseWritePreservesResponse(t *testing.T) {
	port := freePort(t, false)
	startProxy(t, map[string]any{"type": "shadowsocks", "tag": "proxy", "listen": "127.0.0.1", "listen_port": port, "method": "aes-128-gcm", "password": "integration-secret", "network": "tcp"})
	parsed, err := parser.Parse([]byte(fmt.Sprintf("ss://aes-128-gcm:integration-secret@127.0.0.1:%d#SS", port)))
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(context.Background(), []engine.Node{{ID: "node", Outbound: parsed.Nodes[0].Outbound}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// The target deliberately sends nothing until it receives EOF. Closing
		// the entire proxy connection would lose the response that follows.
		data, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("response:"), data...))
		}
		serverDone <- err
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("EOF target: %v", err)
			}
		case <-time.After(6 * time.Second):
			t.Error("EOF target did not finish")
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := client.DialContext(ctx, "node", "tcp", listener.Addr().String())
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("real Shadowsocks connection does not expose CloseWrite")
	}
	const payload = "payload followed by write EOF"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	want := "response:" + payload
	response := make([]byte, len(want))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read response after CloseWrite: %v", err)
	}
	if string(response) != want {
		t.Fatalf("response=%q want=%q", response, want)
	}
}

func assertEcho(t *testing.T, client engine.Engine, id, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := client.DialContext(ctx, id, "tcp", address)
	// SOCKS only retains the dial context for connection establishment. A
	// successfully established stream must survive its immediate cancellation.
	cancel()
	if err != nil {
		t.Errorf("dial via proxy: %v", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	const message = "OneSocks real protocol round trip\x00\xff"
	if _, err := io.WriteString(conn, message); err != nil {
		t.Errorf("proxy write: %v", err)
		return
	}
	data := make([]byte, len(message))
	if _, err := io.ReadFull(conn, data); err != nil {
		t.Errorf("proxy read: %v", err)
		return
	}
	if string(data) != message {
		t.Errorf("proxy changed payload %q", data)
	}
}

func startProxy(t *testing.T, inbound map[string]any) {
	t.Helper()
	ctx := Context(context.Background())
	raw, err := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}},
		"route":     map[string]any{"final": "direct", "default_domain_resolver": "local"},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"inbounds":  []any{inbound},
	})
	if err != nil {
		t.Fatal(err)
	}
	var options option.Options
	if err := boxjson.UnmarshalContext(ctx, raw, &options); err != nil {
		t.Fatalf("decode server configuration: %v", err)
	}
	server, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		t.Fatalf("create test proxy: %v", err)
	}
	if err := server.Start(); err != nil {
		_ = server.Close()
		t.Fatalf("start test proxy: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
}

func freePort(t *testing.T, udp bool) int {
	t.Helper()
	if udp {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.LocalAddr().(*net.UDPAddr).Port
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func echoTarget(t *testing.T, network, address, banner string) (string, *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var mu sync.Mutex
	connections := make(map[net.Conn]bool)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			mu.Lock()
			connections[conn] = true
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer conn.Close()
				defer func() { mu.Lock(); delete(connections, conn); mu.Unlock() }()
				if banner != "" {
					_, _ = io.WriteString(conn, banner)
				}
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		for conn := range connections {
			_ = conn.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	return listener.Addr().String(), &accepted
}

func selfSigned(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))), strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})))
}

func newAnyTLSFixture(t *testing.T) engine.Engine {
	t.Helper()
	certificate, key := selfSigned(t)
	port := freePort(t, false)
	startProxy(t, map[string]any{
		"type": "anytls", "tag": "proxy", "listen": "127.0.0.1", "listen_port": port,
		"users": []any{map[string]any{"name": "test", "password": "integration-secret"}},
		"tls":   map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}},
	})
	raw, err := json.Marshal(map[string]any{
		"type": "anytls", "server": "127.0.0.1", "server_port": port,
		"password": "integration-secret", "min_idle_session": 1,
		"tls": map[string]any{"enabled": true, "server_name": "localhost", "insecure": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := New(context.Background(), []engine.Node{{ID: "node", Outbound: raw}})
	if err != nil {
		t.Fatalf("create AnyTLS outbound: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestAnyTLSClosingOneStreamPreservesOtherStreams(t *testing.T) {
	client := newAnyTLSFixture(t)
	target, _ := echoTarget(t, "tcp", "127.0.0.1:0", "")
	dial := func() net.Conn {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := client.DialContext(ctx, "node", "tcp", target)
		cancel()
		if err != nil {
			t.Fatalf("dial AnyTLS stream: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	first, second := dial(), dial()
	check := func(conn net.Conn, message string) {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.WriteString(conn, message); err != nil {
			t.Fatalf("write to active AnyTLS stream: %v", err)
		}
		got := make([]byte, len(message))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("read active AnyTLS stream: %v", err)
		}
		if string(got) != message {
			t.Fatalf("cross-stream payload mismatch: %q != %q", got, message)
		}
		_ = conn.SetDeadline(time.Time{})
	}
	check(first, "first stream before close")
	check(second, "second stream before close")
	// AnyTLS owns pooled TLS sessions. A per-stream close (and write half-close,
	// when exposed) must not damage active streams or future session reuse.
	if half, ok := first.(interface{ CloseWrite() error }); ok {
		if err := half.CloseWrite(); err != nil {
			t.Fatalf("half-close first AnyTLS stream: %v", err)
		}
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first AnyTLS stream: %v", err)
	}
	check(second, "second stream survives first close")
	third := dial()
	check(third, "new stream survives previous close")
	check(second, "second stream remains isolated from new stream")
}

func TestBuiltInObfsLocalPluginConfiguration(t *testing.T) {
	for _, mode := range []string{"tls", "http"} {
		t.Run(mode, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"type": "shadowsocks", "server": "127.0.0.1", "server_port": 9,
				"method": "aes-128-gcm", "password": "integration-secret",
				"plugin": "obfs-local", "plugin_opts": "obfs=" + mode + ";obfs-host=localhost",
			})
			if err != nil {
				t.Fatal(err)
			}
			// This verifies configuration decoding and startup of the embedded
			// plugin only. It deliberately makes no obfs wire-protocol claim.
			client, err := New(context.Background(), []engine.Node{{ID: "node", Outbound: raw}})
			if err != nil {
				t.Fatalf("built-in obfs-local %s plugin configuration rejected: %v", mode, err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
