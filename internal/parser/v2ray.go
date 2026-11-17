package parser

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"onesocks/internal/domain"
)

type v2rayOutbound struct {
	Protocol       string          `json:"protocol"`
	Tag            string          `json:"tag"`
	Settings       json.RawMessage `json:"settings"`
	StreamSettings *v2rayStream    `json:"streamSettings"`
	SendThrough    string          `json:"sendThrough"`
	ProxySettings  map[string]any  `json:"proxySettings"`
	Mux            map[string]any  `json:"mux"`
}

type v2rayServer struct {
	Address  string            `json:"address"`
	Port     int               `json:"port"`
	Users    []json.RawMessage `json:"users"`
	Method   string            `json:"method"`
	Password string            `json:"password"`
	Email    string            `json:"email"`
	Level    int               `json:"level"`
	OTA      bool              `json:"ota"`
	IVCheck  bool              `json:"ivCheck"`
}

type v2rayUser struct {
	ID         string `json:"id"`
	AlterID    int    `json:"alterId"`
	Security   string `json:"security"`
	Encryption string `json:"encryption"`
	Flow       string `json:"flow"`
	Email      string `json:"email"`
	Level      int    `json:"level"`
}

type v2rayStream struct {
	Network         string         `json:"network"`
	Security        string         `json:"security"`
	TLSSettings     *v2rayTLS      `json:"tlsSettings"`
	RealitySettings *v2rayReality  `json:"realitySettings"`
	TCPSettings     *v2rayTCP      `json:"tcpSettings"`
	RawSettings     *v2rayTCP      `json:"rawSettings"`
	WSSettings      *v2rayWS       `json:"wsSettings"`
	GRPCSettings    *v2rayGRPC     `json:"grpcSettings"`
	Sockopt         map[string]any `json:"sockopt"`
}

type v2rayTLS struct {
	ServerName    string   `json:"serverName"`
	AllowInsecure bool     `json:"allowInsecure"`
	ALPN          []string `json:"alpn"`
	Fingerprint   string   `json:"fingerprint"`
	MinVersion    string   `json:"minVersion"`
	MaxVersion    string   `json:"maxVersion"`
	CipherSuites  string   `json:"cipherSuites"`
}

type v2rayReality struct {
	Show        bool   `json:"show"`
	ServerName  string `json:"serverName"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"publicKey"`
	Password    string `json:"password"`
	ShortID     string `json:"shortId"`
	SpiderX     string `json:"spiderX"`
}

type v2rayTCP struct {
	Header *struct {
		Type string `json:"type"`
	} `json:"header"`
	AcceptProxyProtocol bool `json:"acceptProxyProtocol"`
}

type v2rayWS struct {
	Path                string            `json:"path"`
	Host                string            `json:"host"`
	Headers             map[string]string `json:"headers"`
	MaxEarlyData        int               `json:"maxEarlyData"`
	EarlyDataHeaderName string            `json:"earlyDataHeaderName"`
	AcceptProxyProtocol bool              `json:"acceptProxyProtocol"`
}

type v2rayGRPC struct {
	ServiceName         string `json:"serviceName"`
	MultiMode           bool   `json:"multiMode"`
	Authority           string `json:"authority"`
	IdleTimeout         int    `json:"idle_timeout"`
	HealthCheckTimeout  int    `json:"health_check_timeout"`
	PermitWithoutStream bool   `json:"permit_without_stream"`
	InitialWindowsSize  int    `json:"initial_windows_size"`
}

type v2rayCandidate struct {
	fields map[string]any
	user   int
}

// Decode failures must not expose source credentials or local file paths.
func decodeV2Ray(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return errors.New("invalid or unsupported V2Ray configuration fields")
	}
	return nil
}

func v2rayNodes(raw json.RawMessage) ([]domain.NodeSpec, []string, error) {
	var outbound v2rayOutbound
	if err := decodeV2Ray(raw, &outbound); err != nil {
		return nil, nil, err
	}
	switch outbound.Protocol {
	case "vmess", "vless", "trojan", "shadowsocks":
	default:
		return nil, nil, errors.New("unsupported V2Ray outbound protocol")
	}
	if len(outbound.ProxySettings) != 0 {
		return nil, nil, errors.New("V2Ray proxy chains cannot be imported independently")
	}
	if enabled, present := outbound.Mux["enabled"]; present && enabled != false {
		return nil, nil, errors.New("V2Ray Mux cannot be translated to sing-box multiplexing")
	}
	common := map[string]any{"type": outbound.Protocol}
	if outbound.SendThrough != "" {
		ip := net.ParseIP(outbound.SendThrough)
		if ip == nil {
			return nil, nil, errors.New("unsupported V2Ray sendThrough address")
		}
		if ip.To4() != nil {
			common["inet4_bind_address"] = ip.String()
		} else {
			common["inet6_bind_address"] = ip.String()
		}
	}
	if err := outbound.StreamSettings.apply(common); err != nil {
		return nil, nil, err
	}
	var settings struct {
		VNext   []json.RawMessage `json:"vnext"`
		Servers []json.RawMessage `json:"servers"`
	}
	if err := decodeV2Ray(outbound.Settings, &settings); err != nil {
		return nil, nil, err
	}
	servers := settings.Servers
	if outbound.Protocol == "vmess" || outbound.Protocol == "vless" {
		if len(settings.Servers) > 0 {
			return nil, nil, errors.New("V2Ray VMess/VLESS settings require vnext")
		}
		servers = settings.VNext
	} else if len(settings.VNext) > 0 {
		return nil, nil, errors.New("V2Ray Trojan/Shadowsocks settings require servers")
	}
	var nodes []domain.NodeSpec
	var warnings []string
	for i, rawServer := range servers {
		var server v2rayServer
		if err := decodeV2Ray(rawServer, &server); err != nil {
			warnings = append(warnings, fmt.Sprintf("server %d: %s", i+1, err))
			continue
		}
		objects, serverWarnings, err := server.objects(common)
		for _, warning := range serverWarnings {
			warnings = append(warnings, fmt.Sprintf("server %d: %s", i+1, warning))
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("server %d: %s", i+1, err))
			continue
		}
		for _, candidate := range objects {
			obj := candidate.fields
			name := outbound.Tag
			// Keep all source alternatives even though a tag normally identifies
			// one load-balanced outbound in V2Ray. Never name nodes after secrets.
			if name != "" && (len(servers) > 1 || len(server.Users) > 1) {
				name = fmt.Sprintf("%s-%d-%d", name, i+1, candidate.user)
			}
			node, err := makeNode(name, obj)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("server %d: %s", i+1, err))
				continue
			}
			if name == "" && (len(servers) > 1 || len(server.Users) > 1) {
				node.Name += fmt.Sprintf("-%d-%d", i+1, candidate.user)
			}
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return nil, warnings, errors.New("V2Ray outbound has no supported valid servers or users")
	}
	return nodes, warnings, nil
}

func (s v2rayServer) objects(common map[string]any) ([]v2rayCandidate, []string, error) {
	if s.Address == "" || s.Port < 1 || s.Port > 65535 {
		return nil, nil, errors.New("invalid V2Ray server address or port")
	}
	if s.OTA || s.IVCheck {
		return nil, nil, errors.New("unsupported V2Ray Shadowsocks authentication option")
	}
	base := func() map[string]any {
		obj := make(map[string]any, len(common)+4)
		for key, value := range common {
			obj[key] = value
		}
		obj["server"], obj["server_port"] = s.Address, s.Port
		return obj
	}
	typ := text(common["type"])
	if typ == "trojan" || typ == "shadowsocks" {
		if len(s.Users) > 0 || typ == "trojan" && s.Method != "" {
			return nil, nil, errors.New("unsupported V2Ray server authentication fields")
		}
		obj := base()
		obj["password"] = s.Password
		if typ == "shadowsocks" {
			obj["method"] = s.Method
		}
		return []v2rayCandidate{{fields: obj, user: 1}}, nil, nil
	}
	if s.Method != "" || s.Password != "" {
		return nil, nil, errors.New("unsupported V2Ray VMess/VLESS server fields")
	}
	var objects []v2rayCandidate
	var warnings []string
	for i, rawUser := range s.Users {
		var user v2rayUser
		if err := decodeV2Ray(rawUser, &user); err != nil {
			warnings = append(warnings, fmt.Sprintf("user %d: %s", i+1, err))
			continue
		}
		obj := base()
		obj["uuid"] = user.ID
		if typ == "vmess" {
			if user.Flow != "" || user.Encryption != "" {
				warnings = append(warnings, fmt.Sprintf("user %d: unsupported VMess user encryption or flow", i+1))
				continue
			}
			obj["security"], obj["alter_id"] = cmp.Or(user.Security, "auto"), user.AlterID
		} else {
			if user.Security != "" || user.AlterID != 0 || user.Encryption != "" && user.Encryption != "none" {
				warnings = append(warnings, fmt.Sprintf("user %d: unsupported VLESS user encryption", i+1))
				continue
			}
			if user.Flow != "" {
				obj["flow"] = user.Flow
			}
		}
		objects = append(objects, v2rayCandidate{fields: obj, user: i + 1})
	}
	return objects, warnings, nil
}

func (s *v2rayStream) apply(obj map[string]any) error {
	if s == nil {
		return nil
	}
	if len(s.Sockopt) > 0 {
		return errors.New("unsupported V2Ray socket options")
	}
	if s.Security != "" && s.Security != "none" {
		if obj["type"] == "shadowsocks" {
			return errors.New("V2Ray Shadowsocks TLS cannot be translated")
		}
		tls := map[string]any{"enabled": true}
		switch s.Security {
		case "tls":
			if s.TLSSettings != nil {
				t := s.TLSSettings
				tls["server_name"], tls["insecure"] = t.ServerName, t.AllowInsecure
				if len(t.ALPN) > 0 {
					tls["alpn"] = t.ALPN
				}
				if t.Fingerprint != "" {
					tls["utls"] = map[string]any{"enabled": true, "fingerprint": t.Fingerprint}
				}
				if t.MinVersion != "" {
					tls["min_version"] = t.MinVersion
				}
				if t.MaxVersion != "" {
					tls["max_version"] = t.MaxVersion
				}
				if t.CipherSuites != "" {
					tls["cipher_suites"] = strings.Split(t.CipherSuites, ":")
				}
			}
		case "reality":
			if obj["type"] != "vless" || s.RealitySettings == nil {
				return errors.New("V2Ray Reality requires VLESS and Reality settings")
			}
			r := s.RealitySettings
			if r.SpiderX != "" && r.SpiderX != "/" || r.PublicKey != "" && r.Password != "" && r.PublicKey != r.Password {
				return errors.New("unsupported V2Ray Reality options")
			}
			tls["server_name"] = r.ServerName
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": cmp.Or(r.Fingerprint, "chrome")}
			tls["reality"] = map[string]any{"enabled": true, "public_key": cmp.Or(r.PublicKey, r.Password), "short_id": r.ShortID}
		default:
			return errors.New("unsupported V2Ray stream security")
		}
		obj["tls"] = tls
	}
	network := cmp.Or(s.Network, "tcp")
	if network != "tcp" && network != "raw" && obj["type"] == "shadowsocks" {
		return errors.New("V2Ray Shadowsocks transport cannot be translated")
	}
	switch network {
	case "tcp", "raw":
		settings := s.TCPSettings
		if network == "raw" {
			settings = s.RawSettings
		}
		if settings != nil && (settings.AcceptProxyProtocol || settings.Header != nil && settings.Header.Type != "" && settings.Header.Type != "none") {
			return errors.New("V2Ray TCP header obfuscation cannot be translated")
		}
	case "ws":
		transport := map[string]any{"type": "ws"}
		if w := s.WSSettings; w != nil {
			if w.AcceptProxyProtocol {
				return errors.New("unsupported V2Ray WebSocket PROXY protocol")
			}
			if w.MaxEarlyData < 0 {
				return errors.New("invalid V2Ray WebSocket early data size")
			}
			path, err := url.Parse(w.Path)
			if err != nil {
				return errors.New("invalid V2Ray WebSocket path")
			}
			query, err := url.ParseQuery(path.RawQuery)
			if err != nil {
				return errors.New("invalid V2Ray WebSocket path query")
			}
			earlyData := w.MaxEarlyData
			if value := query.Get("ed"); value != "" {
				earlyData, err = strconv.Atoi(value)
				if err != nil || earlyData < 0 {
					return errors.New("invalid V2Ray WebSocket early data size")
				}
				query.Del("ed")
				path.RawQuery = query.Encode()
			}
			transport["path"] = path.String()
			headers := w.Headers
			if w.Host != "" {
				if headers == nil {
					headers = map[string]string{}
				}
				headers["Host"] = w.Host
			}
			if len(headers) > 0 {
				transport["headers"] = headers
			}
			if earlyData > 0 {
				transport["max_early_data"] = earlyData
				transport["early_data_header_name"] = cmp.Or(w.EarlyDataHeaderName, "Sec-WebSocket-Protocol")
			}
		}
		obj["transport"] = transport
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if g := s.GRPCSettings; g != nil {
			if g.MultiMode || g.Authority != "" || g.InitialWindowsSize != 0 {
				return errors.New("unsupported V2Ray gRPC mode or options")
			}
			transport["service_name"] = g.ServiceName
			if g.IdleTimeout != 0 {
				transport["idle_timeout"] = fmt.Sprintf("%ds", g.IdleTimeout)
			}
			if g.HealthCheckTimeout != 0 {
				transport["ping_timeout"] = fmt.Sprintf("%ds", g.HealthCheckTimeout)
			}
			transport["permit_without_stream"] = g.PermitWithoutStream
		}
		obj["transport"] = transport
	default:
		return errors.New("unsupported V2Ray transport; supported networks are tcp, ws and grpc")
	}
	return nil
}
