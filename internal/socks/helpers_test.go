package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
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

func startServer(t *testing.T, backend *testBackend, cfg Config) (string, context.CancelFunc) {
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
	return listener.Addr().String(), cancel
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
