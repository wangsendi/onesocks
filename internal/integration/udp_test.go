package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/engine/singbox"
	"onesocks/internal/service"
	"onesocks/internal/socks"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/things-go/go-socks5/statute"
)

func udpService(t *testing.T, drain time.Duration) (*service.Manager, domain.MutationResult, string, string) {
	t.Helper()
	remote := startShadowsocks(t)
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "ss://aes-128-gcm:integration-secret@%s#udp", remote)
	}))
	t.Cleanup(source.Close)
	manager, err := service.New(context.Background(), service.Options{
		DataDir: t.TempDir(), FetchTimeout: 3 * time.Second, RefreshInterval: time.Hour, DrainTimeout: drain, Factory: singbox.New,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	sub, err := manager.Create(context.Background(), domain.SubscriptionInput{Name: "UDP", URL: source.URL})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- socks.New(manager, socks.Config{}).Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("SOCKS server failed to stop")
		}
	})
	return manager, sub, listener.Addr().String(), manager.Nodes("").Items[0].Username
}

type socksPacketConn struct {
	net.PacketConn
	control net.Conn
	relay   net.Addr
}

func openPacketConn(t *testing.T, address, username string) *socksPacketConn {
	t.Helper()
	control := authenticateOnly(t, address, username)
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	reply, err := statute.ParseReply(control)
	if err != nil || reply.Response != 0 {
		t.Fatalf("UDP associate: %+v, %v", reply, err)
	}
	_ = control.SetDeadline(time.Time{})
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn := &socksPacketConn{PacketConn: packet, control: control, relay: &net.UDPAddr{IP: reply.BndAddr.IP, Port: reply.BndAddr.Port}}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func (c *socksPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	packet, err := statute.NewDatagram(destination.String(), payload)
	if err != nil {
		return 0, err
	}
	if _, err = c.PacketConn.WriteTo(packet.Bytes(), c.relay); err != nil {
		return 0, err
	}
	return len(payload), nil
}

func (c *socksPacketConn) ReadFrom(buffer []byte) (int, net.Addr, error) {
	packet := make([]byte, 65535)
	for {
		n, source, err := c.PacketConn.ReadFrom(packet)
		if err != nil {
			return 0, nil, err
		}
		if source.String() != c.relay.String() {
			continue
		}
		datagram, err := statute.ParseDatagram(packet[:n])
		if err != nil {
			return 0, nil, err
		}
		if len(datagram.Data) > len(buffer) {
			return 0, nil, io.ErrShortBuffer
		}
		n = copy(buffer, datagram.Data)
		return n, &net.UDPAddr{IP: datagram.DstAddr.IP, Port: datagram.DstAddr.Port}, nil
	}
}

func (c *socksPacketConn) Close() error {
	_ = c.control.Close()
	return c.PacketConn.Close()
}

func TestHTTP3ThroughSOCKSAndShadowsocks(t *testing.T) {
	_, _, address, username := udpService(t, time.Second)
	// Borrow httptest's verified loopback certificate; the target only listens
	// on UDP, so a successful HTTP/3 request cannot fall back to TCP.
	certificate := httptest.NewTLSServer(http.NotFoundHandler())
	serverTLS := certificate.TLS.Clone()
	roots := x509.NewCertPool()
	roots.AddCert(certificate.Certificate())
	certificate.Close()
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h3 := &http3.Server{TLSConfig: serverTLS, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 3 {
			t.Errorf("server protocol = %s", r.Proto)
		}
		_, _ = io.Copy(w, r.Body)
	})}
	done := make(chan error, 1)
	go func() { done <- h3.Serve(target) }()
	t.Cleanup(func() { _ = h3.Close(); _ = target.Close(); <-done })
	packet := openPacketConn(t, address, username)
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}, Dial: func(ctx context.Context, _ string, tlsConfig *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
		return quic.DialEarly(ctx, packet, target.LocalAddr(), tlsConfig, cfg)
	}}
	defer transport.Close()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	payload := bytes.Repeat([]byte("HTTP/3 through authenticated SOCKS5 UDP\n"), 4096)
	response, err := client.Post("https://"+target.LocalAddr().String()+"/echo", "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	got, err := io.ReadAll(response.Body)
	if err != nil || response.ProtoMajor != 3 || !bytes.Equal(got, payload) {
		t.Fatalf("HTTP/3 response protocol=%s bytes=%d: %v", response.Proto, len(got), err)
	}
}

func TestUDPAssociationSurvivesDeleteUntilDrain(t *testing.T) {
	manager, sub, address, username := udpService(t, 250*time.Millisecond)
	packet := openPacketConn(t, address, username)
	target, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 65535)
		for {
			n, peer, err := target.ReadFrom(buffer)
			if err != nil {
				return
			}
			_, _ = target.WriteTo(buffer[:n], peer)
		}
	}()
	t.Cleanup(func() { _ = target.Close(); <-done })
	echo := func() {
		t.Helper()
		_ = packet.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := packet.WriteTo([]byte("pinned UDP"), target.LocalAddr()); err != nil {
			t.Fatal(err)
		}
		buffer := make([]byte, 128)
		n, _, err := packet.ReadFrom(buffer)
		if err != nil || string(buffer[:n]) != "pinned UDP" {
			t.Fatalf("UDP echo %q: %v", buffer[:n], err)
		}
	}
	echo()
	if err := manager.Delete(context.Background(), sub.Subscription.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Acquire(username); err == nil {
		t.Fatal("deleted UDP node accepts new sessions")
	}
	echo()
	// Waiting on the old control socket isn't sufficient: the UDP route must
	// stop forwarding at the runtime's drain deadline even if TCP stays open.
	time.Sleep(300 * time.Millisecond)
	_ = packet.SetDeadline(time.Now().Add(100 * time.Millisecond))
	_, _ = packet.WriteTo([]byte("retired"), target.LocalAddr())
	buffer := make([]byte, 128)
	if _, _, err := packet.ReadFrom(buffer); err == nil {
		t.Fatal("UDP survived runtime drain")
	}
}
