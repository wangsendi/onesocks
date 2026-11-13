package engine

import (
	"context"
	"encoding/json"
	"net"
)

type Node struct {
	ID       string
	Outbound json.RawMessage
}

type Engine interface {
	DialContext(context.Context, string, string, string) (net.Conn, error)
	Close() error
}

type Factory func(context.Context, []Node) (Engine, error)
