package singbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"onesocks/internal/engine"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxservice "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/dns/transport/local"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/anytls"
	"github.com/sagernet/sing-box/protocol/direct"
	"github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/shadowsocks"
	"github.com/sagernet/sing-box/protocol/trojan"
	"github.com/sagernet/sing-box/protocol/vless"
	"github.com/sagernet/sing-box/protocol/vmess"
	"github.com/sagernet/sing/common"
	boxjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Context registers only the protocols used by OneSocks. Direct is an internal
// transport dependency, never exposed as a selectable subscription node.
func Context(ctx context.Context) context.Context {
	in := inbound.NewRegistry()
	shadowsocks.RegisterInbound(in)
	trojan.RegisterInbound(in)
	vless.RegisterInbound(in)
	vmess.RegisterInbound(in)
	hysteria2.RegisterInbound(in)
	anytls.RegisterInbound(in)
	out := outbound.NewRegistry()
	direct.RegisterOutbound(out)
	shadowsocks.RegisterOutbound(out)
	trojan.RegisterOutbound(out)
	vless.RegisterOutbound(out)
	vmess.RegisterOutbound(out)
	hysteria2.RegisterOutbound(out)
	anytls.RegisterOutbound(out)
	dnsRegistry := dns.NewTransportRegistry()
	local.RegisterTransport(dnsRegistry)
	return box.Context(ctx, in, out, endpoint.NewRegistry(), dnsRegistry, boxservice.NewRegistry(), certificate.NewRegistry())
}

type Engine struct {
	box       *box.Box
	halfClose map[string]bool
	once      sync.Once
	err       error
}

type Options struct {
	// OutboundInterface pins proxy connections and bootstrap DNS to this
	// interface through sing-box's native socket binding. Empty uses defaults.
	OutboundInterface string
}

func New(ctx context.Context, nodes []engine.Node) (engine.Engine, error) {
	return NewWithOptions(ctx, nodes, Options{})
}

func NewWithOptions(ctx context.Context, nodes []engine.Node, opts Options) (engine.Engine, error) {
	if opts.OutboundInterface != "" {
		if _, err := net.InterfaceByName(opts.OutboundInterface); err != nil {
			return nil, fmt.Errorf("outbound interface %q: %w", opts.OutboundInterface, err)
		}
	}
	ctx = Context(ctx)
	rawOutbounds := make([]json.RawMessage, 0, len(nodes))
	halfClose := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(node.Outbound, &fields); err != nil {
			return nil, fmt.Errorf("invalid outbound JSON")
		}
		var protocol string
		_ = json.Unmarshal(fields["type"], &protocol)
		transport := fields["transport"]
		// These protocols wrap a single underlying TCP/TLS connection when no
		// transport or multiplexing is used. Never unwrap shared transports.
		var plugin string
		_ = json.Unmarshal(fields["plugin"], &plugin)
		rawTCP := protocol == "shadowsocks" || protocol == "vless" || protocol == "trojan" || protocol == "vmess"
		halfClose[node.ID] = rawTCP && plugin == "" && (len(transport) == 0 || string(transport) == "null")
		tag, _ := json.Marshal(node.ID)
		fields["tag"] = tag
		if opts.OutboundInterface != "" {
			value, _ := json.Marshal(opts.OutboundInterface)
			fields["bind_interface"] = value
		}
		b, err := json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		rawOutbounds = append(rawOutbounds, b)
	}
	// Bootstrap DNS is explicit; final destinations remain domain addresses and
	// are passed to the selected proxy protocol rather than resolved by OneSocks.
	bootstrap := map[string]any{"type": "local", "tag": "bootstrap"}
	route := map[string]any{"default_domain_resolver": "bootstrap"}
	if opts.OutboundInterface != "" {
		bootstrap["bind_interface"] = opts.OutboundInterface
		bootstrap["prefer_go"] = true
		route["default_interface"] = opts.OutboundInterface
	}
	raw := map[string]any{
		"log":       map[string]any{"disabled": true},
		"dns":       map[string]any{"servers": []any{bootstrap}},
		"route":     route,
		"outbounds": rawOutbounds,
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var options option.Options
	if err = boxjson.UnmarshalContext(ctx, data, &options); err != nil {
		return nil, fmt.Errorf("outbound configuration rejected: %w", err)
	}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return nil, err
	}
	if err = instance.Start(); err != nil {
		_ = instance.Close()
		return nil, err
	}
	return &Engine{box: instance, halfClose: halfClose}, nil
}

func (e *Engine) DialContext(ctx context.Context, nodeID, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
	out, ok := e.box.Outbound().Outbound(nodeID)
	if !ok {
		return nil, fmt.Errorf("node not found")
	}
	if !slices.Contains(out.Network(), network) {
		return nil, fmt.Errorf("node does not support %s", network)
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, err
	}
	conn, err := out.DialContext(ctx, network, M.ParseSocksaddr(address))
	if err != nil {
		return nil, err
	}
	// Flush deferred TCP handshakes for server-first protocols such as SSH.
	// UDP writes are payload and must never be used as handshake probes.
	if network == "tcp" && N.NeedHandshakeForWrite(conn) {
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetWriteDeadline(deadline)
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		_, err = conn.Write(nil)
		stop()
		_ = conn.SetWriteDeadline(time.Time{})
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if network == "tcp" && e.halfClose[nodeID] {
		mux, multiplexed := out.(adapter.OutboundWithMultiplex)
		if !multiplexed || !mux.MultiplexEnabled() {
			if writer, ok := common.Cast[interface{ CloseWrite() error }](conn); ok {
				return &halfCloseConn{Conn: conn, writer: writer}, nil
			}
		}
	}
	return conn, nil
}

type halfCloseConn struct {
	net.Conn
	writer interface{ CloseWrite() error }
}

func (c *halfCloseConn) CloseWrite() error { return c.writer.CloseWrite() }

func (e *Engine) Close() error { e.once.Do(func() { e.err = e.box.Close() }); return e.err }
