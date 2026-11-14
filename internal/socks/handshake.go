package socks

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"io"
	"net"

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
	if err := validateRequest(reader.(*bufio.Reader), writer); err != nil {
		return nil, err
	}
	return auth, nil
}

func validateRequest(buffered *bufio.Reader, writer io.Writer) error {
	header, err := buffered.Peek(4)
	if err != nil {
		return err
	}
	code := statute.RepSuccess
	switch {
	case header[0] != statute.VersionSocks5 || header[2] != 0:
		code = statute.RepServerFailure
	case header[1] != statute.CommandConnect && header[1] != statute.CommandAssociate:
		code = statute.RepCommandNotSupported
	case header[3] == statute.ATYPDomain:
		header, err = buffered.Peek(5)
		if err != nil {
			return err
		}
		if header[4] == 0 {
			code = statute.RepAddrTypeNotSupported
		}
	}
	if code != statute.RepSuccess {
		_ = reply(writer, code, nil)
		return errors.New("SOCKS5 request rejected")
	}
	return nil
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
