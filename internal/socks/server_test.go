package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"onesocks/internal/domain"
)

type testBackend struct {
	username string
	active   atomic.Int32
	dials    atomic.Int32
	dial     func(context.Context, string, string) (net.Conn, error)
	released chan struct{}
}

func (b *testBackend) Acquire(username string) (domain.Lease, error) {
	if username != b.username {
		return nil, errors.New("unknown username")
	}
	b.active.Add(1)
	return &testLease{backend: b}, nil
}

type testLease struct {
	backend *testBackend
	once    sync.Once
}

func (l *testLease) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	l.backend.dials.Add(1)
	if l.backend.dial != nil {
		return l.backend.dial(ctx, network, address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (l *testLease) Close() error {
	l.once.Do(func() {
		l.backend.active.Add(-1)
		if l.backend.released != nil {
			l.backend.released <- struct{}{}
		}
	})
	return nil
}

func startServer(t *testing.T, backend *testBackend, cfg Config) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- New(backend, cfg).Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("SOCKS5 server did not stop")
		}
		if active := backend.active.Load(); active != 0 {
			t.Errorf("leaked %d node leases", active)
		}
	})
	return listener.Addr().String(), cancel, done
}

func connect(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func expectBytes(t *testing.T, conn net.Conn, want []byte) {
	t.Helper()
	got := make([]byte, len(want))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("reply = %v, want %v", got, want)
	}
}

func authenticate(t *testing.T, conn net.Conn, username, password string, fragment bool, status byte) {
	t.Helper()
	send := func(packet []byte) {
		if fragment {
			for _, b := range packet {
				if err := writeAll(conn, []byte{b}); err != nil {
					t.Fatal(err)
				}
			}
		} else if err := writeAll(conn, packet); err != nil {
			t.Fatal(err)
		}
	}
	send([]byte{5, 2, 0, 2})
	expectBytes(t, conn, []byte{5, 2})
	packet := append([]byte{1, byte(len(username))}, []byte(username)...)
	packet = append(packet, byte(len(password)))
	packet = append(packet, []byte(password)...)
	send(packet)
	expectBytes(t, conn, []byte{1, status})
}

func TestAuthenticationAndLeaseRelease(t *testing.T) {
	for _, tc := range []struct {
		name, known, username, password, configured string
		status                                      byte
	}{
		{"arbitrary", "n_test", "n_test", "anything", "", 0},
		{"unicode fragmented", "订阅-香港", "订阅-香港", "p", "", 0},
		{"max length", strings.Repeat("a", 255), strings.Repeat("a", 255), "p", "", 0},
		{"unknown", "n_test", "missing", "p", "", 1},
		{"wrong password", "n_test", "n_test", "wrong", "secret", 1},
		{"shared password", "n_test", "n_test", "secret", "secret", 0},
		{"empty username", "", "", "p", "", 1},
		{"empty password", "n_test", "n_test", "", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &testBackend{username: tc.known}
			address, _, _ := startServer(t, backend, Config{Password: tc.configured})
			conn := connect(t, address)
			authenticate(t, conn, tc.username, tc.password, true, tc.status)
			_ = conn.Close()
		})
	}
}

func TestRequiresUsernamePassword(t *testing.T) {
	backend := &testBackend{username: "n_test"}
	address, _, _ := startServer(t, backend, Config{})
	conn := connect(t, address)
	if err := writeAll(conn, []byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, conn, []byte{5, 255})
}

func TestUnsupportedCommandsNeverDial(t *testing.T) {
	for _, command := range []byte{2, 3, 255} {
		t.Run(strconv.Itoa(int(command)), func(t *testing.T) {
			backend := &testBackend{username: "n_test"}
			address, _, _ := startServer(t, backend, Config{})
			conn := connect(t, address)
			authenticate(t, conn, "n_test", "p", false, 0)
			if err := writeAll(conn, []byte{5, command, 0, 1}); err != nil {
				t.Fatal(err)
			}
			expectBytes(t, conn, []byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
			if backend.dials.Load() != 0 {
				t.Fatal("unsupported command triggered outbound dial")
			}
		})
	}
}

func readReply(t *testing.T, conn net.Conn, code byte) {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatal(err)
	}
	if header[0] != 5 || header[1] != code || header[2] != 0 {
		t.Fatalf("bad reply header: %v", header)
	}
	size := 6
	if header[3] == 4 {
		size = 18
	}
	if _, err := io.ReadFull(conn, make([]byte, size)); err != nil {
		t.Fatal(err)
	}
}

func TestPipelinedPayloadAndHalfClose(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	targetDone := make(chan error, 1)
	go func() {
		conn, err := target.Accept()
		if err != nil {
			targetDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		data, err := io.ReadAll(conn)
		if err == nil {
			err = writeAll(conn, append([]byte("reply:"), data...))
		}
		targetDone <- err
	}()
	backend := &testBackend{username: "n_test"}
	address, _, _ := startServer(t, backend, Config{})
	conn := connect(t, address)
	authenticate(t, conn, "n_test", "p", false, 0)
	port := target.Addr().(*net.TCPAddr).Port
	packet := []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}
	binary.BigEndian.PutUint16(packet[8:], uint16(port))
	packet = append(packet, []byte("pipelined payload")...)
	if err := writeAll(conn, packet); err != nil {
		t.Fatal(err)
	}
	readReply(t, conn, 0)
	if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "reply:pipelined payload" {
		t.Fatalf("received %q", got)
	}
	if err := <-targetDone; err != nil {
		t.Fatal(err)
	}
}

func TestRequestAddressForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr []byte
		want string
	}{
		{"IPv4", []byte{1, 127, 0, 0, 1}, "127.0.0.1:443"},
		{"IPv6", append([]byte{4}, net.ParseIP("2001:db8::1").To16()...), "[2001:db8::1]:443"},
		{"unresolvable domain", append([]byte{3, 18}, []byte("proxy-only.invalid")...), "proxy-only.invalid:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialed := make(chan string, 1)
			backend := &testBackend{username: "n_test", dial: func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" {
					t.Errorf("network = %q, want tcp", network)
				}
				dialed <- address
				return nil, syscall.ECONNREFUSED
			}}
			address, _, _ := startServer(t, backend, Config{})
			conn := connect(t, address)
			authenticate(t, conn, "n_test", "p", false, 0)
			packet := append([]byte{5, 1, 0}, tc.addr...)
			packet = append(packet, 1, 187)
			if err := writeAll(conn, packet); err != nil {
				t.Fatal(err)
			}
			readReply(t, conn, 5)
			select {
			case got := <-dialed:
				if got != tc.want {
					t.Fatalf("address = %q, want %q", got, tc.want)
				}
			default:
				t.Fatal("request did not reach the selected lease")
			}
		})
	}
}

func TestCancellationInterruptsDialAndReleasesLease(t *testing.T) {
	dialStarted := make(chan struct{})
	backend := &testBackend{username: "n_test", dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(dialStarted)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	address, cancel, _ := startServer(t, backend, Config{})
	conn := connect(t, address)
	authenticate(t, conn, "n_test", "p", false, 0)
	if err := writeAll(conn, []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("dial was not started")
	}
	cancel()
	// A bounded failure reply may race cancellation; either way the session
	// must finish promptly instead of leaving the client or lease blocked.
	_, err := io.ReadAll(conn)
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("client stayed open after server cancellation")
	}
}

func TestDialFailureReturnsSOCKSError(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code byte
	}{
		{"refused", syscall.ECONNREFUSED, 5},
		{"network unreachable", syscall.ENETUNREACH, 3},
		{"host unreachable", syscall.EHOSTUNREACH, 4},
		{"timeout", context.DeadlineExceeded, 6},
		{"generic failure", errors.New("dial failed"), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &testBackend{username: "n_test", dial: func(context.Context, string, string) (net.Conn, error) {
				return nil, tc.err
			}}
			address, _, _ := startServer(t, backend, Config{})
			conn := connect(t, address)
			authenticate(t, conn, "n_test", "p", false, 0)
			if err := writeAll(conn, []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
				t.Fatal(err)
			}
			readReply(t, conn, tc.code)
		})
	}
}

func TestCancellationClosesEstablishedSession(t *testing.T) {
	targetSide, proxySide := net.Pipe()
	defer targetSide.Close()
	backend := &testBackend{username: "n_test", dial: func(context.Context, string, string) (net.Conn, error) {
		return proxySide, nil
	}}
	address, cancel, _ := startServer(t, backend, Config{})
	conn := connect(t, address)
	authenticate(t, conn, "n_test", "p", false, 0)
	if err := writeAll(conn, []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	readReply(t, conn, 0)
	cancel()
	_ = targetSide.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	_, err := targetSide.Read(b[:])
	if err == nil {
		t.Fatal("upstream stayed open after cancellation")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatal("upstream was not closed by cancellation")
	}
}

func TestInvalidRequestsNeverDial(t *testing.T) {
	for _, tc := range []struct {
		name   string
		packet []byte
		code   byte
	}{
		{"version", []byte{4, 1, 0, 1}, 1},
		{"reserved byte", []byte{5, 1, 1, 1}, 1},
		{"address type", []byte{5, 1, 0, 255}, 8},
		{"empty domain", []byte{5, 1, 0, 3, 0}, 8},
		{"zero port", []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 0}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &testBackend{username: "n_test", released: make(chan struct{}, 1)}
			address, _, _ := startServer(t, backend, Config{})
			conn := connect(t, address)
			authenticate(t, conn, "n_test", "p", false, 0)
			if err := writeAll(conn, tc.packet); err != nil {
				t.Fatal(err)
			}
			readReply(t, conn, tc.code)
			select {
			case <-backend.released:
			case <-time.After(time.Second):
				t.Fatal("rejected request kept its lease")
			}
			if backend.dials.Load() != 0 {
				t.Fatal("invalid request triggered outbound dial")
			}
		})
	}
}

func TestIncompleteRequestReleasesAuthenticatedLease(t *testing.T) {
	backend := &testBackend{username: "n_test", released: make(chan struct{}, 1)}
	address, _, _ := startServer(t, backend, Config{})
	conn := connect(t, address)
	authenticate(t, conn, "n_test", "p", false, 0)
	if got := backend.active.Load(); got != 1 {
		t.Fatalf("authentication pinned %d leases, want 1", got)
	}
	if err := writeAll(conn, []byte{5, 1, 0, 3, 18, 'p'}); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-backend.released:
	case <-time.After(time.Second):
		t.Fatal("incomplete request kept its lease until server shutdown")
	}
	if backend.dials.Load() != 0 {
		t.Fatal("incomplete request triggered outbound dial")
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func TestHandshakeTimeoutClosesIncompleteSessions(t *testing.T) {
	for _, stage := range []string{"greeting", "credentials", "request"} {
		t.Run(stage, func(t *testing.T) {
			backend := &testBackend{username: "n_test", released: make(chan struct{}, 1)}
			address, _, _ := startServer(t, backend, Config{HandshakeTimeout: 200 * time.Millisecond})
			conn := connect(t, address)
			switch stage {
			case "greeting":
				if err := writeAll(conn, []byte{5}); err != nil {
					t.Fatal(err)
				}
			case "credentials":
				if err := writeAll(conn, []byte{5, 1, 2}); err != nil {
					t.Fatal(err)
				}
				expectBytes(t, conn, []byte{5, 2})
				if err := writeAll(conn, []byte{1, 6, 'n'}); err != nil {
					t.Fatal(err)
				}
			case "request":
				authenticate(t, conn, "n_test", "p", false, 0)
			}
			_, err := io.ReadAll(conn)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				t.Fatal("incomplete handshake outlived the server deadline")
			}
			if stage == "request" {
				select {
				case <-backend.released:
				case <-time.After(time.Second):
					t.Fatal("handshake timeout kept the authenticated lease")
				}
			}
			if backend.dials.Load() != 0 {
				t.Fatal("incomplete handshake triggered outbound dial")
			}
		})
	}
}

func TestDialTimeoutReturnsTTLExpired(t *testing.T) {
	backend := &testBackend{username: "n_test", released: make(chan struct{}, 1), dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	address, _, _ := startServer(t, backend, Config{DialTimeout: 20 * time.Millisecond})
	conn := connect(t, address)
	authenticate(t, conn, "n_test", "p", false, 0)
	if err := writeAll(conn, []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
		t.Fatal(err)
	}
	readReply(t, conn, 6)
	select {
	case <-backend.released:
	case <-time.After(time.Second):
		t.Fatal("dial timeout kept the lease")
	}
}

type authReplyFailureConn struct{ net.Conn }

func (c authReplyFailureConn) Write(p []byte) (int, error) {
	if len(p) == 2 && p[0] == 1 && p[1] == 0 {
		return 0, io.ErrClosedPipe
	}
	return c.Conn.Write(p)
}

func TestAuthenticationReplyFailureReleasesLease(t *testing.T) {
	backend := &testBackend{username: "n_test"}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(time.Second))
	done := make(chan struct{})
	go func() {
		New(backend, Config{}).handle(context.Background(), authReplyFailureConn{server})
		close(done)
	}()
	if err := writeAll(client, []byte{5, 1, 2}); err != nil {
		t.Fatal(err)
	}
	expectBytes(t, client, []byte{5, 2})
	if err := writeAll(client, []byte{1, 6, 'n', '_', 't', 'e', 's', 't', 1, 'p'}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed authentication reply left the session running")
	}
	if backend.active.Load() != 0 || backend.dials.Load() != 0 {
		t.Fatal("failed authentication reply leaked a lease or dialed upstream")
	}
}
