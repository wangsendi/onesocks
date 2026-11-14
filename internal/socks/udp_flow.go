package socks

import (
	"context"
	"net"
	"time"

	"github.com/things-go/go-socks5/statute"
	"golang.org/x/sync/errgroup"
)

func (a *udpAssociation) forward(ctx context.Context, client *net.UDPAddr, destination string, queue <-chan []byte) {
	packet, err := statute.NewDatagram(destination, nil)
	if err != nil {
		return
	}
	dialCtx, cancelDial := context.WithTimeout(ctx, a.cfg.DialTimeout)
	upstream, err := a.lease.DialContext(dialCtx, "udp", destination)
	cancelDial()
	if err != nil {
		return
	}
	defer upstream.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	group, ctx := errgroup.WithContext(ctx)
	stop := context.AfterFunc(ctx, func() { _ = upstream.Close() })
	defer stop()
	idle := time.AfterFunc(a.cfg.UDPIdleTimeout, cancel)
	defer idle.Stop()
	active := func() {
		idle.Reset(a.cfg.UDPIdleTimeout)
		a.touch()
	}
	group.Go(func() error {
		return a.forwardReplies(ctx, upstream, client, packet.Header(), active)
	})
	group.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case payload := <-queue:
				active()
				if _, err := upstream.Write(payload); err != nil {
					return err
				}
			}
		}
	})
	_ = group.Wait()
}

func (a *udpAssociation) forwardReplies(ctx context.Context, upstream net.Conn, client *net.UDPAddr, header []byte, active func()) error {
	// Keep room for a full datagram plus its header to avoid truncating replies.
	buffer := make([]byte, len(header)+maxUDPPacket)
	copy(buffer, header)
	for {
		n, err := upstream.Read(buffer[len(header):])
		if err != nil {
			return err
		}
		if _, err := a.relay.WriteToUDP(buffer[:len(header)+n], client); err == nil {
			active()
		} else if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
