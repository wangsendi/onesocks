//go:build linux

package singbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"testing"
	"time"

	"onesocks/internal/engine"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"golang.org/x/sys/unix"
)

func TestOutboundInterfaceBindsActualSocket(t *testing.T) {
	// Use a non-loopback destination so sing's IsVirtual shortcut cannot make
	// this test pass without setting a kernel socket binding. The test fixture
	// explicitly selects the interface owning the controlled server's address.
	interfaceName, host := bindingTestNetwork(t)
	listener, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("non-loopback local listener unavailable: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	startProxy(t, map[string]any{
		"type": "shadowsocks", "tag": "proxy", "listen": host, "listen_port": port,
		"method": "aes-128-gcm", "password": "interface-test-secret", "network": "tcp",
	})
	address := net.JoinHostPort(host, strconv.Itoa(port))
	// Check only the controlled network path and required OS capability before
	// exercising OneSocks. Permission/path limitations produce an explicit skip.
	preflight := net.Dialer{Timeout: time.Second, Control: func(_, _ string, raw syscall.RawConn) error {
		var bindErr error
		if err := raw.Control(func(fd uintptr) { bindErr = unix.BindToDevice(int(fd), interfaceName) }); err != nil {
			return err
		}
		return bindErr
	}}
	probe, err := preflight.Dial("tcp", address)
	if err != nil {
		t.Skipf("kernel interface binding to controlled target unavailable: %v", err)
	}
	_ = probe.Close()
	target, _ := echoTarget(t, "tcp", "127.0.0.1:0", "")
	for _, tc := range []struct{ name, sourceInterface, globalInterface, wantBound string }{
		{name: "defaults remain unbound"},
		{name: "global overrides source interface", sourceInterface: "onesocks-missing", globalInterface: interfaceName, wantBound: interfaceName},
		{name: "empty global preserves source binding", sourceInterface: interfaceName, wantBound: interfaceName},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fields := map[string]any{"type": "shadowsocks", "server": host, "server_port": port, "method": "aes-128-gcm", "password": "interface-test-secret"}
			if tc.sourceInterface != "" {
				fields["bind_interface"] = tc.sourceInterface
			}
			raw, _ := json.Marshal(fields)
			original := bytes.Clone(raw)
			nodes := []engine.Node{{ID: "node", Outbound: raw}}
			ctx := service.ContextWithDefaultRegistry(context.Background())
			client, err := NewWithOptions(ctx, nodes, Options{OutboundInterface: tc.globalInterface})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = client.Close() })
			if !bytes.Equal(nodes[0].Outbound, original) || nodes[0].ID != "node" {
				t.Fatal("runtime override changed the original node identity/configuration")
			}
			if got := service.FromContext[adapter.NetworkManager](ctx).DefaultOptions().BindInterface; got != tc.globalInterface {
				t.Fatalf("internal transport default interface=%q, want %q", got, tc.globalInterface)
			}
			dialCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			conn, err := client.DialContext(dialCtx, "node", "tcp", target)
			cancel()
			if err != nil {
				t.Fatalf("real SS dial to controlled non-loopback server: %v", err)
			}
			defer conn.Close()
			if got := boundDevice(t, conn); got != tc.wantBound {
				t.Fatalf("kernel SO_BINDTODEVICE=%q, want %q", got, tc.wantBound)
			}
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			const payload = "interface-bound SS round trip"
			if _, err := io.WriteString(conn, payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, response); err != nil {
				t.Fatal(err)
			}
			if string(response) != payload {
				t.Fatal("interface-bound SS payload mismatch")
			}
		})
	}
}

func TestUnknownOutboundInterfaceIsRejected(t *testing.T) {
	client, err := NewWithOptions(context.Background(), nil, Options{OutboundInterface: "onesocks-interface-that-does-not-exist"})
	if client != nil {
		_ = client.Close()
	}
	if err == nil {
		t.Fatal("invalid interface silently fell back to ordinary routing")
	}
}

func bindingTestNetwork(t *testing.T) (string, string) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err != nil {
				continue
			}
			ip := prefix.Addr().Unmap()
			if ip.Is4() && !ip.IsUnspecified() && !ip.IsLinkLocalUnicast() && !N.IsVirtual(ip) {
				return iface.Name, ip.String()
			}
		}
	}
	t.Skip("requires an up interface with a non-loopback local IPv4 address")
	return "", ""
}

func boundDevice(t *testing.T, conn net.Conn) string {
	t.Helper()
	if wrapped, ok := conn.(*halfCloseConn); ok {
		conn = wrapped.Conn
	}
	socket, ok := common.Cast[syscall.Conn](conn)
	if !ok {
		t.Fatal("cannot inspect the real proxy socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var name string
	var optionErr error
	if err := raw.Control(func(fd uintptr) {
		name, optionErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatal(err)
	}
	if optionErr != nil {
		if errors.Is(optionErr, unix.ENOPROTOOPT) {
			t.Skip("SO_BINDTODEVICE inspection unavailable")
		}
		t.Fatal(optionErr)
	}
	return name
}
