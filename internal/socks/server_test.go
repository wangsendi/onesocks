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
	l.once.Do(func() { l.backend.active.Add(-1) })
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
	for _, command := range []byte{2, 3} {
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
		{"domain", append([]byte{3, 11}, []byte("example.com")...), "example.com:443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			packet := append([]byte{5, 1, 0}, tc.addr...)
			packet = append(packet, 1, 187)
			go func() { _ = writeAll(left, packet) }()
			got, code, err := readRequest(right)
			if err != nil || code != 0 || got != tc.want {
				t.Fatalf("address = %q, code=%d, err=%v", got, code, err)
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
		{"timeout", context.DeadlineExceeded, 6},
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
