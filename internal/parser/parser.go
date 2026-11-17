// Package parser converts subscription documents into independent sing-box outbounds.
package parser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"onesocks/internal/domain"

	"github.com/sagernet/sing-box/transport/sip003"
)

var supported = map[string]bool{"shadowsocks": true, "vless": true, "trojan": true, "vmess": true, "hysteria2": true, "anytls": true}

// Parse accepts URI lists, sing-box/V2Ray JSON, Clash YAML and Surge profiles,
// optionally base64 encoded.
// Diagnostics deliberately never include URI credentials or source documents.
func Parse(data []byte) (domain.ParseResult, error) {
	var result domain.ParseResult
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(data) == 0 {
		return result, errors.New("subscription is empty")
	}
	if decoded, err := decode64(string(data)); err == nil && len(bytes.TrimSpace(decoded)) > 0 {
		data = bytes.TrimSpace(bytes.TrimPrefix(decoded, []byte{0xef, 0xbb, 0xbf}))
	}
	if json.Valid(data) && (data[0] == '{' || data[0] == '[') {
		return parseJSON(data)
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	first := true
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "//") {
			continue
		}
		if first && !hasURIScheme(line) {
			if isSurge(line) {
				return parseSurge(data)
			}
			return parseClash(data)
		}
		first = false
		n, err := parseURI(line)
		appendNode(&result, n, err, i)
	}
	return finish(result)
}

func hasURIScheme(line string) bool {
	scheme, _, found := strings.Cut(line, "://")
	if !found || scheme == "" {
		return false
	}
	for i, c := range scheme {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			continue
		}
		if i > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			continue
		}
		return false
	}
	return true
}

func finish(r domain.ParseResult) (domain.ParseResult, error) {
	if len(r.Nodes) == 0 {
		return r, errors.New("subscription contains no supported valid nodes")
	}
	return r, nil
}

func appendNode(r *domain.ParseResult, n domain.NodeSpec, err error, index int) {
	if err != nil {
		r.Warnings = append(r.Warnings, fmt.Sprintf("entry %d: %s", index+1, err))
		return
	}
	r.Nodes = append(r.Nodes, n)
}

func decode64(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := encoding.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func makeNode(name string, obj map[string]any) (domain.NodeSpec, error) {
	var zero domain.NodeSpec
	typ := text(obj["type"])
	if !supported[typ] {
		return zero, errors.New("unsupported outbound protocol")
	}
	if text(obj["detour"]) != "" {
		return zero, errors.New("chained outbounds cannot be imported independently")
	}
	for _, field := range []string{"server_port", "min_idle_session"} {
		if value, present := obj[field]; present && value != nil {
			count, err := number(value)
			if err != nil {
				return zero, errors.New("invalid outbound numeric field")
			}
			obj[field] = count
		}
	}
	if typ == "vmess" && text(obj["security"]) == "" {
		obj["security"] = "auto"
	}
	if err := rejectLocalFiles(obj); err != nil {
		return zero, err
	}
	if strings.TrimSpace(name) == "" {
		name = typ + "-" + net.JoinHostPort(text(obj["server"]), text(obj["server_port"]))
	}
	encoded, err := json.Marshal(obj)
	if err != nil {
		return zero, errors.New("invalid outbound configuration")
	}
	return domain.NodeSpec{Name: name, Outbound: encoded}, nil
}

// A downloaded node may contain inline TLS material, but cannot direct the
// application to load local certificate/key files. Other validation belongs
// to sing-box's actual options decoder and protocol constructors.
func rejectLocalFiles(obj map[string]any) error {
	if tls, ok := obj["tls"].(map[string]any); ok {
		for _, field := range []string{"certificate_path", "client_certificate_path", "client_key_path"} {
			if tls[field] != nil {
				return errors.New("subscription TLS cannot reference local files")
			}
		}
		if ech, ok := tls["ech"].(map[string]any); ok && ech["config_path"] != nil {
			return errors.New("subscription ECH cannot reference local files")
		}
	}
	if obj["plugin"] == "v2ray-plugin" {
		options, err := sip003.ParsePluginOptions(text(obj["plugin_opts"]))
		if err != nil {
			return errors.New("invalid Shadowsocks plugin options")
		}
		if _, present := options.Get("cert"); present {
			return errors.New("subscription plugin cannot reference local certificate files")
		}
	}
	return nil
}

func text(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		return strconv.FormatBool(t)
	default:
		return ""
	}
}
func number(v any) (int, error) { return strconv.Atoi(text(v)) }
