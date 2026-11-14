package socks

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"time"

	"onesocks/internal/domain"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
	"golang.org/x/sync/errgroup"
)

const (
	maxUDPFlows  = 128
	udpQueueSize = 8
	maxUDPPacket = 65535
)

type udpAssociation struct {
	cfg        Config
	lease      domain.Lease
	control    net.Conn
	relay      *net.UDPConn
	peer       *net.TCPAddr
	clientPort int // Only the receive loop reads or pins the client's UDP port.

	flowsMu sync.Mutex
	flows   map[string]chan []byte
	workers sync.WaitGroup
}

func (s *Server) associate(ctx context.Context, client net.Conn, lease domain.Lease, request *socks5.Request) error {
	local, localOK := client.LocalAddr().(*net.TCPAddr)
	peer, peerOK := client.RemoteAddr().(*net.TCPAddr)
	if !localOK || !peerOK {
		return reply(client, statute.RepServerFailure, nil)
	}
	declared := request.RawDestAddr
	if declared.FQDN != "" || (!declared.IP.IsUnspecified() && !declared.IP.Equal(peer.IP)) {
		return reply(client, statute.RepRuleFailure, nil)
	}
	relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Zone: local.Zone})
	if err != nil {
		return reply(client, statute.RepServerFailure, nil)
	}
	defer relay.Close()
	if err := socks5.SendReply(client, statute.RepSuccess, relay.LocalAddr()); err != nil {
		return err
	}
	a := &udpAssociation{
		cfg: s.cfg, lease: lease, control: client, relay: relay,
		peer: peer, clientPort: declared.Port, flows: make(map[string]chan []byte),
	}
	return a.run(ctx, request.Reader)
}

func (a *udpAssociation) run(ctx context.Context, reader io.Reader) error {
	_ = a.control.SetDeadline(time.Time{})
	a.touch()
	group, ctx := errgroup.WithContext(ctx)
	stop := context.AfterFunc(ctx, a.close)
	defer stop()
	defer a.workers.Wait()
	group.Go(func() error {
		// TCP only controls the association's lifetime; payload travels over UDP.
		_, err := io.Copy(io.Discard, reader)
		if err == nil {
			err = io.EOF
		}
		return err
	})
	group.Go(func() error { return a.receive(ctx) })
	return group.Wait()
}

func (a *udpAssociation) close() {
	_ = a.relay.Close()
	_ = a.control.Close()
}

func (a *udpAssociation) touch() {
	_ = a.control.SetReadDeadline(time.Now().Add(a.cfg.UDPIdleTimeout))
}

func (a *udpAssociation) receive(ctx context.Context) error {
	buffer := make([]byte, maxUDPPacket)
	for {
		n, source, err := a.relay.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		// UDP carries no credentials: require the TCP peer and pin its UDP port.
		if !source.IP.Equal(a.peer.IP) || (a.clientPort != 0 && source.Port != a.clientPort) {
			continue
		}
		// The library ignores RSV and does not reassemble fragmented datagrams.
		if n < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		packet, err := statute.ParseDatagram(buffer[:n])
		if err != nil || packet.DstAddr.Port == 0 || (packet.DstAddr.AddrType == statute.ATYPDomain && packet.DstAddr.FQDN == "") {
			continue
		}
		a.clientPort = source.Port
		a.touch()
		queue := a.flowQueue(ctx, source, packet.DstAddr.String())
		// One producer: available capacity cannot shrink before this send.
		if queue != nil && len(queue) < cap(queue) {
			queue <- bytes.Clone(packet.Data)
		}
	}
}

func (a *udpAssociation) flowQueue(ctx context.Context, source *net.UDPAddr, destination string) chan<- []byte {
	a.flowsMu.Lock()
	defer a.flowsMu.Unlock()
	if queue, ok := a.flows[destination]; ok {
		return queue
	}
	if len(a.flows) >= maxUDPFlows || ctx.Err() != nil {
		return nil
	}
	queue := make(chan []byte, udpQueueSize)
	a.flows[destination] = queue
	a.workers.Go(func() {
		defer func() {
			a.flowsMu.Lock()
			delete(a.flows, destination)
			a.flowsMu.Unlock()
		}()
		a.forward(ctx, source, destination, queue)
	})
	return queue
}
