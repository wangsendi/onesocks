// Package socks implements a SOCKS5 TCP endpoint whose username selects a node.
package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"onesocks/internal/domain"

	"github.com/sagernet/sing/common/bufio"
	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

type Backend interface {
	Acquire(username string) (domain.Lease, error)
}

type Config struct {
	Password         string
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
}

type Server struct {
	backend Backend
	cfg     Config
}

func New(backend Backend, cfg Config) *Server {
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 15 * time.Second
	}
	return &Server{backend: backend, cfg: cfg}
}

// Serve owns listener and closes active sessions when ctx is cancelled. It
// waits for all connection handlers before returning.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	clients := make(map[net.Conn]struct{})
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		mu.Lock()
		for conn := range clients {
			_ = conn.Close()
		}
		mu.Unlock()
		close(stopped)
	}()
	var serveErr error
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				serveErr = err
			}
			break
		}
		if ctx.Err() != nil {
			_ = conn.Close()
			break
		}
		mu.Lock()
		clients[conn] = struct{}{}
		mu.Unlock()
		workers.Go(func() {
			defer func() {
				_ = conn.Close()
				mu.Lock()
				delete(clients, conn)
				mu.Unlock()
			}()
			s.handle(ctx, conn)
		})
	}
	cancel()
	<-stopped
	workers.Wait()
	return serveErr
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	if ctx.Err() != nil {
		return
	}
	_ = client.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	auth := &nodeAuthenticator{backend: s.backend, password: s.cfg.Password}
	defer func() {
		if auth.lease != nil {
			_ = auth.lease.Close()
		}
	}()
	// Each authenticator owns one session's lease, including when parsing or
	// writing the handshake fails before the CONNECT handler is reached.
	handler := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{auth}),
		socks5.WithResolver(remoteResolver{}),
		socks5.WithConnectHandle(func(_ context.Context, _ io.Writer, request *socks5.Request) error {
			// ServeConn starts with context.Background; retain our service context.
			return s.connect(ctx, client, auth.lease, request)
		}),
	)
	_ = handler.ServeConn(client)
}

func (s *Server) connect(ctx context.Context, client net.Conn, lease domain.Lease, request *socks5.Request) error {
	if request.RawDestAddr.Port == 0 {
		return reply(client, statute.RepServerFailure, nil)
	}
	// Handshake deadlines do not constrain the lifetime of a forwarded session.
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
	// ServeConn buffers input while parsing. Forward any already-read payload
	// through the same reader, while retaining TCP half-close on the socket.
	return bufio.CopyConn(ctx, &bufferedConn{Conn: client, reader: request.Reader}, upstream)
}
