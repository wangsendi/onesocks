package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

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
