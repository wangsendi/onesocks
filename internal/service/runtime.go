package service

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"onesocks/internal/domain"
	"onesocks/internal/engine"

	N "github.com/sagernet/sing/common/network"
)

type generation struct {
	mu          sync.Mutex
	engine      engine.Engine
	ctx         context.Context
	cancel      context.CancelFunc
	nodes       []domain.NodeInfo
	aliases     map[string]string
	refs        int
	retired     bool
	closed      bool
	timer       *time.Timer
	connections map[*trackedConn]struct{}
	done        chan struct{}
	onClose     func()
}

func (g *generation) acquire(id string) (domain.Lease, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.retired {
		return nil, errors.New("runtime unavailable")
	}
	g.refs++
	return &lease{generation: g, id: id, connections: make(map[*trackedConn]struct{})}, nil
}

func (g *generation) retire(timeout time.Duration) {
	g.mu.Lock()
	g.retired = true
	empty := g.refs == 0
	if !empty && !g.closed && g.timer == nil {
		g.timer = time.AfterFunc(timeout, g.close)
	}
	g.mu.Unlock()
	if empty {
		g.close()
	}
}

func (g *generation) release() {
	g.mu.Lock()
	g.refs--
	closeNow := g.retired && g.refs == 0
	g.mu.Unlock()
	if closeNow {
		g.close()
	}
}

func (g *generation) close() {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return
	}
	g.closed = true
	if g.timer != nil {
		g.timer.Stop()
	}
	g.cancel()
	conns := make([]*trackedConn, 0, len(g.connections))
	for c := range g.connections {
		conns = append(conns, c)
	}
	g.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	if g.engine != nil {
		_ = g.engine.Close()
	}
	close(g.done)
	if g.onClose != nil {
		g.onClose()
	}
}

type lease struct {
	mu          sync.Mutex
	generation  *generation
	id          string
	closed      bool
	connections map[*trackedConn]struct{}
}

func (l *lease) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	l.mu.Lock()
	closed := l.closed
	l.mu.Unlock()
	if closed {
		return nil, errors.New("lease closed")
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(l.generation.ctx, cancel)
	defer stop()
	defer cancel()
	conn, err := l.generation.engine.DialContext(ctx, l.id, network, address)
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	g := l.generation
	g.mu.Lock()
	defer g.mu.Unlock()
	if l.closed || g.closed {
		_ = conn.Close()
		return nil, errors.New("runtime closed")
	}
	tracked := &trackedConn{Conn: conn, generation: g, lease: l}
	g.connections[tracked] = struct{}{}
	l.connections[tracked] = struct{}{}
	return tracked, nil
}

func (l *lease) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	conns := make([]*trackedConn, 0, len(l.connections))
	for c := range l.connections {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	l.generation.release()
	return nil
}

type trackedConn struct {
	net.Conn
	once       sync.Once
	generation *generation
	lease      *lease
	err        error
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		c.err = c.Conn.Close()
		c.lease.mu.Lock()
		delete(c.lease.connections, c)
		c.lease.mu.Unlock()
		c.generation.mu.Lock()
		delete(c.generation.connections, c)
		c.generation.mu.Unlock()
	})
	return c.err
}

func (c *trackedConn) CloseWrite() error {
	// Unwrap sing's encrypted/counting connections to retain TCP half-close.
	if cw, ok := N.UnwrapWriter(c.Conn).(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return c.Close()
}
