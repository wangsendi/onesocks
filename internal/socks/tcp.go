package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"time"

	"onesocks/internal/domain"

	"github.com/sagernet/sing/common/bufio"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

func (s *Server) connect(ctx context.Context, client net.Conn, lease domain.Lease, request *socks5.Request) error {
	if request.RawDestAddr.Port == 0 {
		return reply(client, statute.RepServerFailure, nil)
	}
	_ = client.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	upstream, err := lease.DialContext(dialCtx, "tcp", request.RawDestAddr.String())
	cancel()
	if err != nil {
		_ = client.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		return reply(client, dialErrorCode(err), nil)
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stop()
	_ = client.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	if err := reply(client, statute.RepSuccess, upstream.LocalAddr()); err != nil {
		return err
	}
	_ = client.SetDeadline(time.Time{})
	// Preserve payload buffered during the handshake and TCP half-close.
	return bufio.CopyConn(ctx, &bufferedConn{Conn: client, reader: request.Reader}, upstream)
}

func dialErrorCode(err error) byte {
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		return statute.RepNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH):
		return statute.RepHostUnreachable
	case errors.Is(err, syscall.ECONNREFUSED):
		return statute.RepConnectionRefused
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return statute.RepTTLExpired
	default:
		return statute.RepServerFailure
	}
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *bufferedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return c.Close()
}
