package socks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/things-go/go-socks5/statute"
)

func udpClient(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func associateClient(t *testing.T, address, declared string) (net.Conn, *net.UDPAddr) {
	t.Helper()
	control := connect(t, address)
	authenticate(t, control, "n_test", "p", false, 0)
	dest, err := statute.ParseAddrSpec(declared)
	if err != nil {
		t.Fatal(err)
	}
	request := statute.Request{Version: 5, Command: 3, DstAddr: dest}
	if _, err := control.Write(request.Bytes()); err != nil {
		t.Fatal(err)
	}
	response, err := statute.ParseReply(control)
	if err != nil || response.Response != 0 {
		t.Fatalf("associate: %+v, %v", response, err)
	}
	if response.BndAddr.IP.IsUnspecified() || response.BndAddr.Port == 0 {
		t.Fatalf("unusable relay: %+v", response.BndAddr)
	}
	return control, &net.UDPAddr{IP: response.BndAddr.IP, Port: response.BndAddr.Port}
}

func udpPacket(t *testing.T, destination string, payload []byte) []byte {
	t.Helper()
	packet, err := statute.NewDatagram(destination, payload)
	if err != nil {
		t.Fatal(err)
	}
	return packet.Bytes()
}

func sendUDP(t *testing.T, conn *net.UDPConn, relay *net.UDPAddr, packet []byte) {
	t.Helper()
	if _, err := conn.WriteToUDP(packet, relay); err != nil {
		t.Fatal(err)
	}
}

func readUDP(t *testing.T, conn *net.UDPConn, destination string, payload []byte) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, maxUDPPacket)
	n, _, err := conn.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := statute.ParseDatagram(buffer[:n])
	if err != nil || packet.Frag != 0 || packet.DstAddr.String() != destination || !bytes.Equal(packet.Data, payload) {
		t.Fatalf("UDP reply: %+v, %v; wanted %s, %d bytes", packet, err, destination, len(payload))
	}
}

func udpEcho(t *testing.T) string {
	t.Helper()
	conn := udpClient(t, "127.0.0.1")
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxUDPPacket)
		for {
			n, peer, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], peer)
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return conn.LocalAddr().String()
}

func TestUDPAssociatePacketBoundariesAndControlLifetime(t *testing.T) {
	backend := &testBackend{username: "n_test", released: make(chan struct{}, 1)}
	address, _, _ := startServer(t, backend, Config{})
	control, relay := associateClient(t, address, "0.0.0.0:0")
	client := udpClient(t, "127.0.0.1")
	for _, destination := range []string{udpEcho(t), udpEcho(t)} {
		for _, payload := range [][]byte{[]byte("first"), bytes.Repeat([]byte("q"), 4096), {}, []byte("tail")} {
			sendUDP(t, client, relay, udpPacket(t, destination, payload))
			readUDP(t, client, destination, payload)
		}
	}
	if backend.dials.Load() != 2 {
		t.Fatalf("dials=%d, want one per destination", backend.dials.Load())
	}
	_ = control.Close()
	select {
	case <-backend.released:
	case <-time.After(time.Second):
		t.Fatal("UDP lease survived control close")
	}
}

func TestUDPRejectsMalformedPacketsAndOtherSources(t *testing.T) {
	backend := &testBackend{username: "n_test"}
	address, _, _ := startServer(t, backend, Config{})
	_, relay := associateClient(t, address, "0.0.0.0:0")
	client := udpClient(t, "127.0.0.1")
	destination := udpEcho(t)
	valid := udpPacket(t, destination, []byte("valid"))
	badRSV := bytes.Clone(valid)
	badRSV[0] = 1
	fragment := bytes.Clone(valid)
	fragment[2] = 1
	for _, packet := range [][]byte{{5}, badRSV, fragment, {0, 0, 0, 3, 0, 0, 80}, udpPacket(t, "127.0.0.1:0", []byte("bad"))} {
		sendUDP(t, client, relay, packet)
	}
	foreign := udpClient(t, "127.0.0.2")
	sendUDP(t, foreign, relay, valid)
	sendUDP(t, client, relay, valid)
	readUDP(t, client, destination, []byte("valid"))
	otherPort := udpClient(t, "127.0.0.1")
	sendUDP(t, otherPort, relay, valid)
	sendUDP(t, client, relay, valid)
	readUDP(t, client, destination, []byte("valid"))
	if backend.dials.Load() != 1 {
		t.Fatalf("untrusted datagram dialed: %d", backend.dials.Load())
	}
}

func TestUDPDeclaredPortAndPeer(t *testing.T) {
	backend := &testBackend{username: "n_test"}
	address, _, _ := startServer(t, backend, Config{})
	client := udpClient(t, "127.0.0.1")
	_, relay := associateClient(t, address, client.LocalAddr().String())
	destination := udpEcho(t)
	packet := udpPacket(t, destination, []byte("known-port"))
	sendUDP(t, udpClient(t, "127.0.0.1"), relay, packet)
	sendUDP(t, client, relay, packet)
	readUDP(t, client, destination, []byte("known-port"))
	if backend.dials.Load() != 1 {
		t.Fatal("ignored declared port")
	}
	for _, declared := range []string{"127.0.0.2:0", "client.invalid:0"} {
		conn := connect(t, address)
		authenticate(t, conn, "n_test", "p", false, 0)
		addr, _ := statute.ParseAddrSpec(declared)
		req := statute.Request{Version: 5, Command: 3, DstAddr: addr}
		_, _ = conn.Write(req.Bytes())
		rep, err := statute.ParseReply(conn)
		if err != nil || rep.Response != statute.RepRuleFailure {
			t.Fatalf("declared %s: %+v, %v", declared, rep, err)
		}
	}
}

func TestUDPIdleAssociationReleasesLease(t *testing.T) {
	backend := &testBackend{username: "n_test", released: make(chan struct{}, 1)}
	address, _, _ := startServer(t, backend, Config{UDPIdleTimeout: 50 * time.Millisecond})
	control, _ := associateClient(t, address, "0.0.0.0:0")
	var b [1]byte
	if _, err := control.Read(b[:]); err != io.EOF {
		t.Fatalf("idle control: %v", err)
	}
	select {
	case <-backend.released:
	case <-time.After(time.Second):
		t.Fatal("idle association leaked lease")
	}
}

type closeNotifyConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *closeNotifyConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.closed) })
	return err
}

func TestUDPIdleDestinationClosesWhileAnotherStaysActive(t *testing.T) {
	quiet, busy := udpEcho(t), udpEcho(t)
	closed := make(chan struct{})
	backend := &testBackend{username: "n_test", dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err == nil && address == quiet {
			conn = &closeNotifyConn{Conn: conn, closed: closed}
		}
		return conn, err
	}}
	address, _, _ := startServer(t, backend, Config{UDPIdleTimeout: 300 * time.Millisecond})
	_, relay := associateClient(t, address, "0.0.0.0:0")
	client := udpClient(t, "127.0.0.1")
	echo := func(destination string) {
		t.Helper()
		sendUDP(t, client, relay, udpPacket(t, destination, []byte("active")))
		readUDP(t, client, destination, []byte("active"))
	}
	echo(quiet)
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case <-closed:
			echo(busy)
			return
		case <-tick.C:
			echo(busy)
		case <-deadline.C:
			t.Fatal("idle destination survived while another destination was active")
		}
	}
}

func TestUDPSlowDialDoesNotBlockOtherDestinationsAndCancels(t *testing.T) {
	entered, canceled := make(chan struct{}), make(chan struct{})
	backend := &testBackend{username: "n_test", dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "slow.invalid:443" {
			close(entered)
			<-ctx.Done()
			close(canceled)
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
	address, _, _ := startServer(t, backend, Config{})
	control, relay := associateClient(t, address, "0.0.0.0:0")
	client := udpClient(t, "127.0.0.1")
	sendUDP(t, client, relay, udpPacket(t, "slow.invalid:443", []byte("queued")))
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not start")
	}
	destination := udpEcho(t)
	sendUDP(t, client, relay, udpPacket(t, destination, []byte("independent")))
	readUDP(t, client, destination, []byte("independent"))
	_ = control.Close()
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("control close did not cancel UDP dial")
	}
}

func TestUDPFlowLimitAndShutdown(t *testing.T) {
	var active atomic.Int32
	entered := make(chan struct{}, maxUDPFlows+1)
	backend := &testBackend{username: "n_test", released: make(chan struct{}, 1), dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		active.Add(1)
		defer active.Add(-1)
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	address, cancel, _ := startServer(t, backend, Config{})
	_, relay := associateClient(t, address, "0.0.0.0:0")
	client := udpClient(t, "127.0.0.1")
	for i := range maxUDPFlows {
		sendUDP(t, client, relay, udpPacket(t, fmt.Sprintf("target.invalid:%d", 1000+i), []byte("x")))
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("missing flow")
		}
	}
	sendUDP(t, client, relay, udpPacket(t, "overflow.invalid:443", []byte("x")))
	select {
	case <-entered:
		t.Fatal("flow cap exceeded")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case <-backend.released:
	case <-time.After(time.Second):
		t.Fatal("shutdown did not release UDP association")
	}
	if active.Load() != 0 {
		t.Error("UDP workers still dialing after shutdown")
	}
}
