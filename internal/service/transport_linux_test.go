//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func nonLoopbackInterface(t *testing.T) (string, netip.Addr) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("cannot enumerate test interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			prefix, err := netip.ParsePrefix(address.String())
			if err == nil && prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
				return iface.Name, prefix.Addr()
			}
		}
	}
	t.Skip("no up non-loopback interface with an IPv4 address")
	return "", netip.Addr{}
}

func socketBoundTo(conn net.Conn, want string) error {
	socket, ok := conn.(syscall.Conn)
	if !ok {
		return fmt.Errorf("connection does not expose a socket")
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}
	var device string
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		device, inspectErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		return err
	}
	if inspectErr != nil {
		return inspectErr
	}
	if device != want {
		return fmt.Errorf("socket bound to %q, want %q", device, want)
	}
	return nil
}

func bindingUnavailable(t *testing.T, err error) {
	t.Helper()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("interface socket binding unavailable: %v", err)
	}
}

func TestSubscriptionHTTPActuallyBindsInterface(t *testing.T) {
	iface, address := nonLoopbackInterface(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on non-loopback test interface: %v", err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "bound subscription fixture")
	}))
	_ = server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	transport := newSubscriptionTransport(Options{OutboundInterface: iface, FetchTimeout: 2 * time.Second})
	defer transport.CloseIdleConnections()
	if transport.Proxy != nil {
		t.Fatal("subscription binding must not enable environment proxies")
	}
	var inspected atomic.Int32
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dial(ctx, network, address)
		if err != nil {
			return nil, err
		}
		if err := socketBoundTo(conn, iface); err != nil {
			_ = conn.Close()
			return nil, err
		}
		inspected.Add(1)
		return conn, nil
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	response, err := client.Get(server.URL)
	if err != nil {
		bindingUnavailable(t, err)
		t.Fatalf("HTTP on a bound non-loopback socket failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || string(body) != "bound subscription fixture" || inspected.Load() == 0 {
		t.Fatalf("body=%q, socket inspections=%d, error=%v", body, inspected.Load(), err)
	}
}

func TestSubscriptionDNSActuallyBindsInterface(t *testing.T) {
	iface, address := nonLoopbackInterface(t)
	dnsServer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: address.AsSlice()})
	if err != nil {
		t.Skipf("cannot listen for DNS on non-loopback test interface: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := dnsServer.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buffer[:n])
			if err != nil {
				continue
			}
			question, err := parser.Question()
			if err != nil {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true})
			_ = builder.StartQuestions()
			_ = builder.Question(question)
			_ = builder.StartAnswers()
			if question.Type == dnsmessage.TypeA {
				_ = builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: address.As4()})
			}
			data, err := builder.Finish()
			if err == nil {
				_, _ = dnsServer.WriteToUDP(data, peer)
			}
		}
	}()
	defer func() { _ = dnsServer.Close(); <-done }()
	dialer := newBoundSubscriptionDialer(Options{OutboundInterface: iface, FetchTimeout: 2 * time.Second})
	originalDNSDial := dialer.Resolver.Dial
	var inspected atomic.Int32
	bindErrors := make(chan error, 1)
	dialer.Resolver.Dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		// Redirect only the DNS test endpoint. The production resolver callback
		// still opens and binds the real socket, then LookupNetIP uses it.
		conn, err := originalDNSDial(ctx, network, dnsServer.LocalAddr().String())
		if err == nil {
			err = socketBoundTo(conn, iface)
		}
		if err != nil {
			if conn != nil {
				_ = conn.Close()
			}
			select {
			case bindErrors <- err:
			default:
			}
			return nil, err
		}
		inspected.Add(1)
		return conn, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	addresses, err := dialer.Resolver.LookupNetIP(ctx, "ip4", "onesocks-bound-fixture.invalid.")
	select {
	case bindErr := <-bindErrors:
		bindingUnavailable(t, bindErr)
		t.Fatalf("DNS socket binding failed: %v", bindErr)
	default:
	}
	if err != nil || len(addresses) != 1 || addresses[0] != address || inspected.Load() == 0 {
		t.Fatalf("DNS lookup=%v, socket inspections=%d, error=%v", addresses, inspected.Load(), err)
	}
}

func TestSubscriptionBindingFailureDoesNotFallBack(t *testing.T) {
	_, address := nonLoopbackInterface(t)
	listener, err := net.Listen("tcp4", net.JoinHostPort(address.String(), "0"))
	if err != nil {
		t.Skipf("cannot listen on non-loopback test interface: %v", err)
	}
	defer listener.Close()
	transport := newSubscriptionTransport(Options{OutboundInterface: "onesocks-missing-interface", FetchTimeout: time.Second})
	defer transport.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := transport.DialContext(ctx, "tcp", listener.Addr().String())
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("invalid interface silently fell back to an unbound connection")
	}
	// The DNS callback must propagate the same binding failure as HTTP.
	dialer := newBoundSubscriptionDialer(Options{OutboundInterface: "onesocks-missing-interface", FetchTimeout: time.Second})
	conn, err = dialer.Resolver.Dial(ctx, "udp", net.JoinHostPort(address.String(), "53"))
	if conn != nil {
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("DNS silently fell back to an unbound connection")
	}
}
