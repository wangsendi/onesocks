package socks

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"
	"time"
)

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
	address, _ := startServer(t, backend, Config{})
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
			address, _ := startServer(t, backend, Config{})
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
			address, _ := startServer(t, backend, Config{})
			conn := connect(t, address)
			authenticate(t, conn, "n_test", "p", false, 0)
			if err := writeAll(conn, []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80}); err != nil {
				t.Fatal(err)
			}
			readReply(t, conn, tc.code)
		})
	}
}

func TestDialTimeoutReturnsTTLExpired(t *testing.T) {
	backend := &testBackend{username: "n_test", released: make(chan struct{}, 1), dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	address, _ := startServer(t, backend, Config{DialTimeout: 20 * time.Millisecond})
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
