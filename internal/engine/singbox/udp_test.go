package singbox

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"onesocks/internal/engine"
)

func udpEchoTarget(t *testing.T, address string) string {
	t.Helper()
	conn, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, source, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo(buffer[:n], source)
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return conn.LocalAddr().String()
}

func assertUDPEcho(t *testing.T, client engine.Engine, id, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	conn, err := client.DialContext(ctx, id, "udp", address)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 65535)
	for _, payload := range [][]byte{[]byte("first-datagram"), bytes.Repeat([]byte("q"), 4096), []byte("last-datagram")} {
		if n, err := conn.Write(payload); err != nil || n != len(payload) {
			t.Fatalf("UDP write %d: %v", n, err)
		}
		n, err := conn.Read(buffer)
		if err != nil || !bytes.Equal(buffer[:n], payload) {
			t.Fatalf("UDP read %d bytes: %v", n, err)
		}
	}
}
