package parser

import (
	"cmp"
	"errors"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func (p clashProxy) addTLS(obj map[string]any, typ string) error {
	enabled := p.TLS || p.Reality != nil || typ == "trojan" || typ == "hysteria2" || typ == "anytls"
	if !enabled {
		return nil
	}
	if typ == "shadowsocks" {
		return errors.New("Clash Shadowsocks TLS requires a supported plugin")
	}
	tls := map[string]any{"enabled": true}
	if name := cmp.Or(p.SNI, p.ServerName); name != "" {
		tls["server_name"] = name
	}
	if p.Insecure {
		tls["insecure"] = true
	}
	if len(p.ALPN) > 0 {
		tls["alpn"] = p.ALPN
	}
	// QUIC uses its own TLS handshake, not a uTLS ClientHello profile.
	if p.Fingerprint != "" && typ != "hysteria2" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": p.Fingerprint}
	}
	if p.Reality != nil {
		if typ != "vless" {
			return errors.New("Clash Reality is only supported for VLESS")
		}
		tls["reality"] = map[string]any{"enabled": true, "public_key": p.Reality.PublicKey, "short_id": p.Reality.ShortID}
		if tls["utls"] == nil {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
	}
	obj["tls"] = tls
	return nil
}

func (p clashProxy) addTransport(obj map[string]any, typ string) error {
	network := cmp.Or(p.Network, "tcp")
	if network == "tcp" {
		if p.WS != nil || p.GRPC != nil {
			return errors.New("Clash transport options require the matching network")
		}
		return nil
	}
	if typ != "vless" && typ != "vmess" && typ != "trojan" {
		return errors.New("Clash network is unsupported for this proxy protocol")
	}
	switch network {
	case "ws":
		if p.GRPC != nil {
			return errors.New("conflicting Clash transport options")
		}
		transport := map[string]any{"type": "ws"}
		if p.WS != nil {
			ws := p.WS
			if ws.HTTPUpgradeFastOpen {
				return errors.New("Clash HTTP upgrade fast open cannot be translated")
			}
			if ws.MaxEarlyData < 0 {
				return errors.New("invalid Clash WebSocket early data size")
			}
			path, err := url.Parse(ws.Path)
			if err != nil {
				return errors.New("invalid Clash WebSocket path")
			}
			query, err := url.ParseQuery(path.RawQuery)
			if err != nil {
				return errors.New("invalid Clash WebSocket path query")
			}
			earlyData := int(ws.MaxEarlyData)
			if value := query.Get("ed"); value != "" {
				earlyData, err = strconv.Atoi(value)
				if err != nil || earlyData < 0 {
					return errors.New("invalid Clash WebSocket early data size")
				}
				query.Del("ed")
				path.RawQuery = query.Encode()
			}
			transport["path"], transport["headers"] = path.String(), ws.Headers
			if ws.HTTPUpgrade {
				if earlyData > 0 {
					return errors.New("Clash HTTP upgrade early data cannot be translated")
				}
				transport["type"] = "httpupgrade"
				for key, value := range ws.Headers {
					if strings.EqualFold(key, "Host") {
						transport["host"] = value
					}
				}
			} else if earlyData > 0 {
				transport["max_early_data"] = earlyData
				transport["early_data_header_name"] = cmp.Or(ws.EarlyDataHeaderName, "Sec-WebSocket-Protocol")
			}
		}
		obj["transport"] = transport
	case "grpc":
		if p.WS != nil {
			return errors.New("conflicting Clash transport options")
		}
		transport := map[string]any{"type": "grpc"}
		if p.GRPC != nil {
			transport["service_name"] = p.GRPC.ServiceName
		}
		obj["transport"] = transport
	default:
		return errors.New("unsupported Clash transport; supported networks are tcp, ws and grpc")
	}
	return nil
}

func clashPlugin(name string, options map[string]any) (string, string, error) {
	values := make(map[string]string)
	switch name {
	case "obfs", "obfs-local":
		name = "obfs-local"
		for key, value := range options {
			s, ok := value.(string)
			if !ok {
				return "", "", errors.New("invalid Clash obfs plugin option")
			}
			switch key {
			case "mode":
				if s != "http" && s != "tls" {
					return "", "", errors.New("unsupported Clash obfs mode")
				}
				values["obfs"] = s
			case "host":
				values["obfs-host"] = s
			default:
				return "", "", errors.New("unsupported Clash obfs plugin option")
			}
		}
	case "v2ray-plugin":
		// Clash's bool mux=false must be explicit: sing-box's plugin defaults to mux=1.
		values["mux"] = "0"
		for key, value := range options {
			switch key {
			case "mode", "host", "path":
				s, ok := value.(string)
				if !ok {
					return "", "", errors.New("invalid Clash v2ray-plugin option")
				}
				if key == "mode" && s != "websocket" {
					return "", "", errors.New("unsupported Clash v2ray-plugin mode")
				}
				values[key] = s
			case "tls", "mux":
				b, ok := value.(bool)
				if !ok {
					return "", "", errors.New("invalid Clash v2ray-plugin flag")
				}
				if b {
					values[key] = "1"
				}
			default:
				return "", "", errors.New("unsupported Clash v2ray-plugin option")
			}
		}
	default:
		return "", "", errors.New("unsupported Clash Shadowsocks plugin")
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	escape := strings.NewReplacer("\\", "\\\\", ";", "\\;", "=", "\\=")
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+escape.Replace(values[key]))
	}
	return name, strings.Join(parts, ";"), nil
}
