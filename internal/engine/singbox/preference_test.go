package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"onesocks/internal/engine"

	"github.com/sagernet/sing/common"
)

func TestNodeIPPreferenceSelectsFamilyAndFallsBack(t *testing.T) {
	addresses, err := net.DefaultResolver.LookupIPAddr(context.Background(), "localhost")
	if err != nil {
		t.Fatal(err)
	}
	var has4, has6 bool
	for _, address := range addresses {
		if address.IP.To4() != nil {
			has4 = true
		} else {
			has6 = true
		}
	}
	if !has4 || !has6 {
		t.Skip("requires localhost resolving to both IPv4 and IPv6")
	}
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	_ = listener.Close()
	start := func(t *testing.T, hosts []string) int {
		t.Helper()
		listener, err := net.Listen("tcp", net.JoinHostPort(hosts[0], "0"))
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		for _, host := range hosts {
			startProxy(t, map[string]any{"type": "shadowsocks", "listen": host, "listen_port": port, "method": "aes-128-gcm", "password": "preference-fixture", "network": "tcp"})
		}
		return port
	}
	for _, tc := range []struct {
		name, preference, server, sourcePreference string
		hosts                                      []string
		wantHost                                   string
	}{
		{"prefer IPv4", "ipv4", "localhost", "", []string{"127.0.0.1", "::1"}, "127.0.0.1"},
		{"prefer IPv6", "ipv6", "localhost", "", []string{"127.0.0.1", "::1"}, "::1"},
		{"IPv6 falls back to IPv4", "ipv6", "localhost", "", []string{"127.0.0.1"}, "127.0.0.1"},
		{"IPv4 falls back to IPv6", "ipv4", "localhost", "", []string{"::1"}, "::1"},
		{"literal IPv4 remains IPv4", "ipv6", "127.0.0.1", "", []string{"127.0.0.1"}, "127.0.0.1"},
		{"auto preserves node preference", "auto", "localhost", "prefer_ipv6", []string{"127.0.0.1", "::1"}, "::1"},
		{"global overrides node preference", "ipv4", "localhost", "ipv6_only", []string{"127.0.0.1", "::1"}, "127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			port := start(t, tc.hosts)
			fields := map[string]any{"type": "shadowsocks", "server": tc.server, "server_port": port, "method": "aes-128-gcm", "password": "preference-fixture"}
			if tc.sourcePreference != "" {
				fields["domain_resolver"] = map[string]any{"server": "bootstrap", "strategy": tc.sourcePreference}
			}
			raw, _ := json.Marshal(fields)
			original := bytes.Clone(raw)
			client, err := NewWithOptions(context.Background(), []engine.Node{{ID: "node", Outbound: raw}}, Options{NodeIPPreference: tc.preference})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if !bytes.Equal(raw, original) {
				t.Fatal("runtime preference modified persisted node configuration")
			}
			target, _ := echoTarget(t, "tcp4", "127.0.0.1:0", "")
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "node", "tcp", target)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			underlying := conn
			if wrapped, ok := underlying.(*halfCloseConn); ok {
				underlying = wrapped.Conn
			}
			socket, ok := common.Cast[*net.TCPConn](underlying)
			if !ok {
				t.Fatal("cannot inspect proxy TCP connection")
			}
			want := net.JoinHostPort(tc.wantHost, strconv.Itoa(port))
			if socket.RemoteAddr().String() != want {
				t.Fatalf("proxy address=%s want=%s", socket.RemoteAddr(), want)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.WriteString(conn, "preferred family echo"); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len("preferred family echo"))
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != "preferred family echo" {
				t.Fatalf("echo=%q error=%v", data, err)
			}
		})
	}
}

func TestInvalidNodeIPPreference(t *testing.T) {
	client, err := NewWithOptions(context.Background(), nil, Options{NodeIPPreference: "ipv5"})
	if client != nil {
		_ = client.Close()
	}
	if err == nil {
		t.Fatal("invalid preference silently accepted")
	}
}

func TestNodeIPPreferenceWithHysteria2(t *testing.T) {
	probe, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 UDP loopback unavailable: %v", err)
	}
	_ = probe.Close()
	certificate, key := selfSigned(t)
	port := freePort(t, true)
	for _, endpoint := range []struct{ host, password string }{{"127.0.0.1", "ipv4"}, {"::1", "ipv6"}} {
		startProxy(t, map[string]any{
			"type": "hysteria2", "listen": endpoint.host, "listen_port": port,
			"users": []any{map[string]any{"password": endpoint.password}},
			"tls":   map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}},
		})
	}
	target, _ := echoTarget(t, "tcp4", "127.0.0.1:0", "")
	udpTarget := udpEchoTarget(t, "127.0.0.1:0")
	for _, preference := range []string{"ipv4", "ipv6"} {
		t.Run(preference, func(t *testing.T) {
			// Different credentials prove which address family accepted the QUIC session.
			raw, _ := json.Marshal(map[string]any{
				"type": "hysteria2", "server": "localhost", "server_port": port, "password": preference,
				"tls": map[string]any{"enabled": true, "insecure": true, "server_name": "localhost"},
			})
			client, err := NewWithOptions(context.Background(), []engine.Node{{ID: "node", Outbound: raw}}, Options{NodeIPPreference: preference})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			assertEcho(t, client, "node", target)
			assertUDPEcho(t, client, "node", udpTarget)
		})
	}
}
