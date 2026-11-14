package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

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
	for _, command := range []byte{2, 255} {
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
