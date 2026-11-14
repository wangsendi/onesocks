package socks

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"syscall"

	"onesocks/internal/domain"

	socks5 "github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/statute"
)

// nodeAuthenticator is local to one ServeConn call. Pin the selected runtime
// before acknowledging authentication; the caller releases it on every exit.
type nodeAuthenticator struct {
	backend  Backend
	password string
	lease    domain.Lease
}

func (a *nodeAuthenticator) GetCode() uint8 { return statute.MethodUserPassAuth }

func (a *nodeAuthenticator) Valid(username, password, _ string) bool {
	if username == "" || password == "" {
		return false
	}
	if a.password != "" && subtle.ConstantTimeCompare([]byte(password), []byte(a.password)) != 1 {
		return false
	}
	var err error
	a.lease, err = a.backend.Acquire(username)
	return err == nil
}

func (a *nodeAuthenticator) Authenticate(reader io.Reader, writer io.Writer, userAddr string) (*socks5.AuthContext, error) {
	auth, err := (socks5.UserPassAuthenticator{Credentials: a}).Authenticate(reader, writer, userAddr)
	if err != nil {
		return nil, err
	}
	delete(auth.Payload, "password")
	// ServeConn supplies its buffered reader. Peek preserves the library's
	// parsing and pipelined data, while keeping our early rejection policy.
	buffered := reader.(*bufio.Reader)
	header, err := buffered.Peek(4)
	if err != nil {
		return nil, err
	}
	code := statute.RepSuccess
	switch {
	case header[0] != statute.VersionSocks5 || header[2] != 0:
		code = statute.RepServerFailure
	case header[1] != statute.CommandConnect:
		code = statute.RepCommandNotSupported
	case header[3] == statute.ATYPDomain:
		header, err = buffered.Peek(5)
		if err != nil {
			return nil, err
		}
		if header[4] == 0 {
			code = statute.RepAddrTypeNotSupported
		}
	}
	if code != statute.RepSuccess {
		_ = reply(writer, code, nil)
		return nil, errors.New("SOCKS5 request rejected")
	}
	return auth, nil
}

// Domain destinations must reach the selected proxy without local DNS lookup.
type remoteResolver struct{}

func (remoteResolver) Resolve(ctx context.Context, _ string) (context.Context, net.IP, error) {
	return ctx, nil, nil
}

func reply(writer io.Writer, code byte, bound net.Addr) error {
	addr, ok := bound.(*net.TCPAddr)
	if !ok || addr == nil {
		bound = &net.TCPAddr{IP: net.IPv4zero}
	} else if addr.IP.To16() == nil {
		bound = &net.TCPAddr{IP: net.IPv4zero, Port: addr.Port}
	}
	return socks5.SendReply(writer, code, bound)
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
