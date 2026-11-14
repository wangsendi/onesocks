package parser

import (
	"bytes"
	"cmp"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"onesocks/internal/domain"

	"gopkg.in/yaml.v3"
)

type clashInteger int

func (v *clashInteger) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag != "!!int" && n.Tag != "!!str" {
		return errors.New("expected an integer")
	}
	number, err := strconv.Atoi(n.Value)
	if err == nil {
		*v = clashInteger(number)
	}
	return err
}

type clashProxy struct {
	Name        string       `yaml:"name"`
	Type        string       `yaml:"type"`
	Server      string       `yaml:"server"`
	Port        clashInteger `yaml:"port"`
	Password    string       `yaml:"password"`
	UUID        string       `yaml:"uuid"`
	Cipher      string       `yaml:"cipher"`
	AlterID     clashInteger `yaml:"alterId"`
	Flow        string       `yaml:"flow"`
	UDP         *bool        `yaml:"udp"`
	PacketAddr  bool         `yaml:"packet-addr"`
	XUDP        bool         `yaml:"xudp"`
	Network     string       `yaml:"network"`
	TLS         bool         `yaml:"tls"`
	SNI         string       `yaml:"sni"`
	ServerName  string       `yaml:"servername"`
	Insecure    bool         `yaml:"skip-cert-verify"`
	ALPN        []string     `yaml:"alpn"`
	Fingerprint string       `yaml:"client-fingerprint"`
	Reality     *struct {
		PublicKey string               `yaml:"public-key"`
		ShortID   string               `yaml:"short-id"`
		Extra     map[string]yaml.Node `yaml:",inline"`
	} `yaml:"reality-opts"`
	WS *struct {
		Path                string               `yaml:"path"`
		Headers             map[string]string    `yaml:"headers"`
		MaxEarlyData        clashInteger         `yaml:"max-early-data"`
		EarlyDataHeaderName string               `yaml:"early-data-header-name"`
		HTTPUpgrade         bool                 `yaml:"v2ray-http-upgrade"`
		HTTPUpgradeFastOpen bool                 `yaml:"v2ray-http-upgrade-fast-open"`
		Extra               map[string]yaml.Node `yaml:",inline"`
	} `yaml:"ws-opts"`
	GRPC *struct {
		ServiceName string               `yaml:"grpc-service-name"`
		Extra       map[string]yaml.Node `yaml:",inline"`
	} `yaml:"grpc-opts"`
	Plugin            string               `yaml:"plugin"`
	PluginOpts        map[string]any       `yaml:"plugin-opts"`
	UDPOverTCP        bool                 `yaml:"udp-over-tcp"`
	UDPOverTCPVersion clashInteger         `yaml:"udp-over-tcp-version"`
	Obfs              string               `yaml:"obfs"`
	ObfsPassword      string               `yaml:"obfs-password"`
	Up                string               `yaml:"up"`
	Down              string               `yaml:"down"`
	IdleCheck         string               `yaml:"idle-session-check-interval"`
	IdleTimeout       string               `yaml:"idle-session-timeout"`
	MinIdle           clashInteger         `yaml:"min-idle-session"`
	TFO               bool                 `yaml:"tfo"`
	MPTCP             bool                 `yaml:"mptcp"`
	Interface         string               `yaml:"interface-name"`
	RoutingMark       clashInteger         `yaml:"routing-mark"`
	IPVersion         string               `yaml:"ip-version"`
	DialerProxy       string               `yaml:"dialer-proxy"`
	Extra             map[string]yaml.Node `yaml:",inline"`
}

func parseClash(data []byte) (domain.ParseResult, error) {
	var result domain.ParseResult
	var doc struct {
		Proxies     []yaml.Node `yaml:"proxies"`
		Fingerprint string      `yaml:"global-client-fingerprint"`
		Providers   yaml.Node   `yaml:"proxy-providers"`
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&doc); err != nil {
		return result, errors.New("invalid Clash subscription YAML")
	}
	if err := decoder.Decode(new(yaml.Node)); err != io.EOF {
		return result, errors.New("Clash subscription must contain one YAML document")
	}
	if doc.Proxies == nil {
		if doc.Providers.Kind != 0 {
			return result, errors.New("Clash subscription has no proxies; use a proxy-provider's subscription URL directly")
		}
		return result, errors.New("unrecognized subscription format: expected URI list, sing-box outbounds or Clash proxies")
	}
	for i, entry := range doc.Proxies {
		var proxy clashProxy
		var node domain.NodeSpec
		err := entry.Decode(&proxy)
		if err != nil {
			// YAML decoder errors can include passwords or the original source.
			err = errors.New("invalid Clash proxy fields")
		} else {
			proxy.Fingerprint = cmp.Or(proxy.Fingerprint, doc.Fingerprint)
			node, err = proxy.node()
		}
		appendNode(&result, node, err, i)
	}
	if doc.Providers.Kind != 0 {
		result.Warnings = append(result.Warnings, "Clash proxy-provider references were not fetched; only the proxies list was imported")
	}
	return finish(result)
}

func (p clashProxy) node() (domain.NodeSpec, error) {
	var zero domain.NodeSpec
	typ := p.Type
	if typ == "ss" {
		typ = "shadowsocks"
	} else if typ == "hy2" {
		typ = "hysteria2"
	}
	if !supported[typ] {
		return zero, errors.New("unsupported Clash proxy protocol")
	}
	if p.Server == "" || p.Port < 1 || p.Port > 65535 {
		return zero, errors.New("invalid Clash proxy server or port")
	}
	if p.DialerProxy != "" {
		return zero, errors.New("Clash dialer-proxy chains cannot be imported independently")
	}
	if p.Reality != nil && len(p.Reality.Extra) > 0 {
		return zero, errors.New("unsupported Clash Reality option")
	}
	if p.WS != nil && len(p.WS.Extra) > 0 {
		return zero, errors.New("unsupported Clash WebSocket option")
	}
	if p.GRPC != nil && len(p.GRPC.Extra) > 0 {
		return zero, errors.New("unsupported Clash gRPC option")
	}
	if len(p.PluginOpts) > 0 && p.Plugin == "" {
		return zero, errors.New("Clash plugin options require a plugin")
	}
	// Ignore display metadata, but never silently discard unfamiliar wire settings.
	for key := range p.Extra {
		switch key {
		case "icon", "benchmark-url", "benchmark-timeout":
		default:
			return zero, errors.New("unsupported Clash proxy option")
		}
	}
	obj := map[string]any{"type": typ, "server": p.Server, "server_port": int(p.Port)}
	switch typ {
	case "shadowsocks":
		obj["method"], obj["password"] = p.Cipher, p.Password
		if p.Plugin != "" {
			plugin, options, err := clashPlugin(p.Plugin, p.PluginOpts)
			if err != nil {
				return zero, err
			}
			obj["plugin"], obj["plugin_opts"] = plugin, options
		}
		if p.UDPOverTCP {
			obj["udp_over_tcp"] = map[string]any{"enabled": true, "version": int(cmp.Or(p.UDPOverTCPVersion, 2))}
		}
	case "vmess", "vless":
		obj["uuid"] = p.UUID
		if typ == "vmess" {
			obj["security"], obj["alter_id"] = cmp.Or(p.Cipher, "auto"), int(p.AlterID)
		} else if p.Flow != "" {
			obj["flow"] = p.Flow
		}
		if p.PacketAddr && p.XUDP {
			return zero, errors.New("conflicting Clash UDP packet encodings")
		}
		if p.PacketAddr {
			obj["packet_encoding"] = "packetaddr"
		}
		if p.XUDP {
			obj["packet_encoding"] = "xudp"
		}
	case "trojan", "hysteria2", "anytls":
		obj["password"] = p.Password
	}
	if p.UDP != nil && !*p.UDP {
		if typ == "anytls" {
			return zero, errors.New("AnyTLS UDP disabling cannot be translated")
		}
		obj["network"] = "tcp"
	}
	if typ == "hysteria2" {
		if p.Obfs != "" || p.ObfsPassword != "" {
			if p.Obfs != "salamander" {
				return zero, errors.New("unsupported Clash Hysteria2 obfuscation")
			}
			obj["obfs"] = map[string]any{"type": p.Obfs, "password": p.ObfsPassword}
		}
		for field, value := range map[string]string{"up_mbps": p.Up, "down_mbps": p.Down} {
			if value == "" {
				continue
			}
			value = strings.TrimSuffix(strings.ToLower(strings.ReplaceAll(value, " ", "")), "mbps")
			n, err := strconv.Atoi(value)
			if err != nil || n <= 0 {
				return zero, errors.New("Clash bandwidth must be a positive integer in Mbps")
			}
			obj[field] = n
		}
	}
	if typ == "anytls" {
		obj["min_idle_session"] = int(p.MinIdle)
		for field, value := range map[string]string{"idle_session_check_interval": p.IdleCheck, "idle_session_timeout": p.IdleTimeout} {
			if value == "" {
				continue
			}
			if _, err := strconv.Atoi(value); err == nil {
				value += "s"
			}
			if _, err := time.ParseDuration(value); err != nil {
				return zero, errors.New("invalid Clash AnyTLS session interval")
			}
			obj[field] = value
		}
	}
	if err := p.addTLS(obj, typ); err != nil {
		return zero, err
	}
	if err := p.addTransport(obj, typ); err != nil {
		return zero, err
	}
	if p.TFO {
		obj["tcp_fast_open"] = true
	}
	if p.MPTCP {
		obj["tcp_multi_path"] = true
	}
	if p.Interface != "" {
		obj["bind_interface"] = p.Interface
	}
	if p.RoutingMark != 0 {
		obj["routing_mark"] = int(p.RoutingMark)
	}
	if p.IPVersion != "" && p.IPVersion != "dual" {
		strategy := map[string]string{"ipv4": "ipv4_only", "ipv6": "ipv6_only", "ipv4-prefer": "prefer_ipv4", "ipv6-prefer": "prefer_ipv6"}[p.IPVersion]
		if strategy == "" {
			return zero, errors.New("unsupported Clash IP version")
		}
		obj["domain_resolver"] = map[string]any{"server": "bootstrap", "strategy": strategy}
	}
	return makeNode(p.Name, obj)
}
