// Package socks implements a SOCKS5 endpoint whose username selects a node.
package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"onesocks/internal/domain"

	socks5 "github.com/things-go/go-socks5"
)

type Backend interface {
	Acquire(username string) (domain.Lease, error)
}

type Config struct {
	Password         string
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
	UDPIdleTimeout   time.Duration
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
	if cfg.UDPIdleTimeout <= 0 {
		cfg.UDPIdleTimeout = 2 * time.Minute
	}
	return &Server{backend: backend, cfg: cfg}
}

// Serve owns listener and closes active sessions when ctx is cancelled. It
// waits for all connection handlers before returning.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer func() {
		cancel()
		_ = listener.Close()
		workers.Wait()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				return err
			}
			return nil
		}
		workers.Go(func() {
			s.handle(ctx, conn)
		})
	}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	if ctx.Err() != nil {
		return
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()
	_ = client.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	auth := &nodeAuthenticator{backend: s.backend, password: s.cfg.Password}
	// Authentication can acquire a lease before command parsing fails.
	defer func() {
		if auth.lease != nil {
			_ = auth.lease.Close()
		}
	}()
	// ServeConn uses context.Background; both handlers retain the service context.
	handler := socks5.NewServer(
		socks5.WithAuthMethods([]socks5.Authenticator{auth}),
		socks5.WithResolver(remoteResolver{}),
		socks5.WithConnectHandle(func(_ context.Context, _ io.Writer, request *socks5.Request) error {
			return s.connect(ctx, client, auth.lease, request)
		}),
		socks5.WithAssociateHandle(func(_ context.Context, _ io.Writer, request *socks5.Request) error {
			return s.associate(ctx, client, auth.lease, request)
		}),
	)
	_ = handler.ServeConn(client)
}
