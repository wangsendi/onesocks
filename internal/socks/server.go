// Package socks implements a SOCKS5 TCP endpoint whose username selects a node.
package socks

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"onesocks/internal/domain"
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
	lease, err := s.authenticate(client)
	if err != nil {
		return
	}
	defer lease.Close()
	address, replyCode, err := readRequest(client)
	if err != nil {
		if replyCode != 0 {
			_ = reply(client, replyCode, nil)
		}
		return
	}
	// Handshake deadlines do not constrain the lifetime of a forwarded session.
	_ = client.SetDeadline(time.Time{})
	dialCtx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	upstream, err := lease.DialContext(dialCtx, "tcp", address)
	cancel()
	if err != nil {
		_ = client.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
		_ = reply(client, dialErrorCode(err), nil)
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() {
		_ = client.Close()
		_ = upstream.Close()
	})
	defer stop()
	_ = client.SetWriteDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	if err := reply(client, 0, upstream.LocalAddr()); err != nil {
		return
	}
	_ = client.SetDeadline(time.Time{})
	relay(client, upstream)
}

func (s *Server) authenticate(conn net.Conn) (domain.Lease, error) {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 5 || header[1] == 0 {
		_ = writeAll(conn, []byte{5, 0xff})
		return nil, errors.New("invalid SOCKS5 greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return nil, err
	}
	if !bytes.Contains(methods, []byte{2}) {
		_ = writeAll(conn, []byte{5, 0xff})
		return nil, errors.New("username/password authentication required")
	}
	if err := writeAll(conn, []byte{5, 2}); err != nil {
		return nil, err
	}
	reject := func(message string) (domain.Lease, error) {
		_ = writeAll(conn, []byte{1, 1})
		return nil, errors.New(message)
	}
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	if header[0] != 1 || header[1] == 0 {
		return reject("invalid authentication request")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return nil, err
	}
	var passwordLength [1]byte
	if _, err := io.ReadFull(conn, passwordLength[:]); err != nil {
		return nil, err
	}
	if passwordLength[0] == 0 {
		return reject("empty password")
	}
	password := make([]byte, int(passwordLength[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return nil, err
	}
	if s.cfg.Password != "" && subtle.ConstantTimeCompare(password, []byte(s.cfg.Password)) != 1 {
		return reject("authentication failed")
	}
	lease, err := s.backend.Acquire(string(username))
	if err != nil {
		return reject("authentication failed")
	}
	if err := writeAll(conn, []byte{1, 0}); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

func readRequest(conn net.Conn) (string, byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return "", 0, err
	}
	if header[0] != 5 || header[2] != 0 {
		return "", 1, errors.New("invalid SOCKS5 request")
	}
	if header[1] != 1 {
		return "", 7, errors.New("unsupported SOCKS5 command")
	}
	var size int
	switch header[3] {
	case 1:
		size = net.IPv4len
	case 4:
		size = net.IPv6len
	case 3:
		var length [1]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			return "", 0, err
		}
		size = int(length[0])
		if size == 0 {
			return "", 8, errors.New("empty destination hostname")
		}
	default:
		return "", 8, errors.New("unsupported address type")
	}
	address := make([]byte, size)
	if _, err := io.ReadFull(conn, address); err != nil {
		return "", 0, err
	}
	host := string(address)
	if header[3] != 3 {
		host = net.IP(address).String()
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(conn, portBytes[:]); err != nil {
		return "", 0, err
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	if port == 0 {
		return "", 1, errors.New("invalid destination port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), 0, nil
}

func reply(conn net.Conn, code byte, bound net.Addr) error {
	packet := []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}
	addr, ok := bound.(*net.TCPAddr)
	if !ok || addr == nil {
		return writeAll(conn, packet)
	}
	if ipv4 := addr.IP.To4(); ipv4 != nil {
		copy(packet[4:8], ipv4)
	} else if ipv6 := addr.IP.To16(); ipv6 != nil {
		packet = make([]byte, 22)
		copy(packet, []byte{5, code, 0, 4})
		copy(packet[4:20], ipv6)
	}
	binary.BigEndian.PutUint16(packet[len(packet)-2:], uint16(addr.Port))
	return writeAll(conn, packet)
}

func dialErrorCode(err error) byte {
	var netErr net.Error
	switch {
	case errors.Is(err, syscall.ENETUNREACH):
		return 3
	case errors.Is(err, syscall.EHOSTUNREACH):
		return 4
	case errors.Is(err, syscall.ECONNREFUSED):
		return 5
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return 6
	default:
		return 1
	}
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func relay(client, upstream net.Conn) {
	done := make(chan error, 2)
	copyStream := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			// Generic connections cannot represent TCP's write-side EOF.
			_ = dst.Close()
		}
		done <- err
	}
	go copyStream(upstream, client)
	go copyStream(client, upstream)
	if err := <-done; err != nil {
		_ = client.Close()
		_ = upstream.Close()
	}
	<-done
}
