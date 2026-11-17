package parser

import (
	"cmp"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"onesocks/internal/domain"
)

func isSurge(line string) bool {
	if strings.HasPrefix(line, "[") {
		return true
	}
	declaration, _ := surgeFields(line, '=')
	if len(declaration) < 2 {
		return false
	}
	protocol, _, _ := strings.Cut(declaration[1], ",")
	protocol = strings.TrimSpace(protocol)
	if protocol == "" {
		return false
	}
	for _, c := range protocol {
		if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func parseSurge(data []byte) (domain.ParseResult, error) {
	var result domain.ParseResult
	section := "proxy" // Policy-list subscriptions may omit the section header.
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#!include") && section == "proxy" {
			result.Warnings = append(result.Warnings, "Surge include references were not fetched; add the referenced subscription URL directly")
		}
		fields, err := surgeFields(line, ',')
		if err == nil && (len(fields) == 0 || fields[0] == "") {
			continue
		}
		if err == nil && len(fields) == 1 && strings.HasPrefix(fields[0], "[") && strings.HasSuffix(fields[0], "]") {
			section = strings.ToLower(strings.TrimSpace(strings.Trim(fields[0], "[]")))
			continue
		}
		if section != "proxy" {
			continue
		}
		var node domain.NodeSpec
		if err == nil {
			node, err = surgeNode(fields)
		}
		appendNode(&result, node, err, i)
	}
	return finish(result)
}

// Split before unquoting: a quoted password or ALPN list can contain commas.
// Comment delimiters are recognized only outside quotes and after whitespace.
func surgeFields(line string, separator byte) ([]string, error) {
	var fields []string
	var quote, previous byte
	start := 0
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(line) && (line[i+1] == quote || line[i+1] == '\\') {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if (c == '"' || c == '\'') && (previous == 0 || previous == '=') {
			quote, previous = c, c
			continue
		}
		if (i == 0 || line[i-1] == ' ' || line[i-1] == '\t') && (c == '#' || c == ';' || c == '/' && strings.HasPrefix(line[i:], "//")) {
			line = line[:i]
			break
		}
		if c == separator {
			fields = append(fields, strings.TrimSpace(line[start:i]))
			start = i + 1
			previous = 0
		} else if c != ' ' && c != '\t' {
			previous = c
		}
	}
	if quote != 0 {
		return fields, errors.New("unterminated Surge quoted value")
	}
	return append(fields, strings.TrimSpace(line[start:])), nil
}

func surgeValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 1 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		quote := string(value[0])
		return strings.NewReplacer("\\"+quote, quote, "\\\\", "\\").Replace(value[1 : len(value)-1])
	}
	return value
}

type surgeOptions map[string]string

func (p surgeOptions) take(key string) string {
	value := p[key]
	delete(p, key)
	return value
}

func surgeNode(fields []string) (domain.NodeSpec, error) {
	var zero domain.NodeSpec
	declaration, err := surgeFields(fields[0], '=')
	if err != nil || len(declaration) != 2 {
		return zero, errors.New("invalid Surge proxy declaration")
	}
	name, typ := declaration[0], strings.ToLower(declaration[1])
	if typ == "ss" {
		typ = "shadowsocks"
	}
	if !supported[typ] {
		return zero, errors.New("unsupported Surge proxy protocol")
	}
	if len(fields) < 3 {
		return zero, errors.New("Surge proxy requires a server and port")
	}
	port, err := strconv.Atoi(surgeValue(fields[2]))
	server := strings.Trim(surgeValue(fields[1]), "[]")
	if err != nil || port < 1 || port > 65535 || server == "" {
		return zero, errors.New("invalid Surge proxy server or port")
	}
	opts := make(surgeOptions)
	for _, field := range fields[3:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return zero, errors.New("invalid Surge proxy parameter")
		}
		opts[strings.ToLower(strings.TrimSpace(key))] = surgeValue(value)
	}
	flags := make(map[string]bool)
	for _, key := range []string{"tls", "skip-cert-verify", "ws", "ws-http-upgrade", "grpc", "tfo", "udp-relay", "vmess-aead", "reuse"} {
		if value, exists := opts[key]; exists {
			flag, err := strconv.ParseBool(value)
			if err != nil {
				return zero, fmt.Errorf("invalid Surge %s flag", key)
			}
			flags[key] = flag
			delete(opts, key)
		}
	}
	obj := map[string]any{"type": typ, "server": server, "server_port": port}
	switch typ {
	case "shadowsocks":
		obj["method"], obj["password"] = opts.take("encrypt-method"), opts.take("password")
		if mode := opts.take("obfs"); mode != "" {
			values := map[string]any{"mode": mode}
			if host := opts.take("obfs-host"); host != "" {
				values["host"] = host
			}
			plugin, options, err := clashPlugin("obfs", values)
			if err != nil {
				return zero, errors.New("unsupported Surge Shadowsocks obfuscation")
			}
			obj["plugin"], obj["plugin_opts"] = plugin, options
		}
	case "vmess":
		obj["uuid"] = opts.take("username")
		method := cmp.Or(opts.take("encrypt-method"), "aes-128-gcm")
		if method == "chacha20-ietf-poly1305" {
			method = "chacha20-poly1305"
		}
		obj["security"], obj["alter_id"] = method, 1
		if flags["vmess-aead"] {
			obj["alter_id"] = 0
		}
	case "vless":
		obj["uuid"] = opts.take("username")
		if flow := opts.take("flow"); flow != "" {
			obj["flow"] = flow
		}
		if encryption := opts.take("encryption"); encryption != "" && encryption != "none" {
			return zero, errors.New("unsupported Surge VLESS encryption")
		}
	case "trojan", "hysteria2", "anytls":
		obj["password"] = opts.take("password")
	}
	if typ == "hysteria2" {
		if err := surgeHysteria2(obj, opts); err != nil {
			return zero, err
		}
	}
	if typ == "anytls" {
		if reuse, exists := flags["reuse"]; exists && !reuse {
			return zero, errors.New("Surge AnyTLS reuse=false cannot be translated")
		}
	}
	if udp, exists := flags["udp-relay"]; (exists && !udp || !exists && typ == "shadowsocks") && typ != "anytls" {
		obj["network"] = "tcp"
	}
	if flags["tfo"] {
		obj["tcp_fast_open"] = true
	}
	if iface := opts.take("interface"); iface != "" {
		obj["bind_interface"] = iface
	}
	if version := opts.take("ip-version"); version != "" && version != "dual" {
		strategy := map[string]string{"v4-only": "ipv4_only", "v6-only": "ipv6_only", "prefer-v4": "prefer_ipv4", "prefer-v6": "prefer_ipv6"}[version]
		if strategy == "" {
			return zero, errors.New("unsupported Surge IP version")
		}
		obj["domain_resolver"] = map[string]any{"server": "bootstrap", "strategy": strategy}
	}
	if err := surgeTLS(obj, opts, flags); err != nil {
		return zero, err
	}
	if err := surgeTransport(obj, opts, flags); err != nil {
		return zero, err
	}
	for key := range opts {
		switch key {
		case "test-url", "test-timeout", "test-udp", "no-error-alert", "hidden":
		default:
			return zero, errors.New("unsupported Surge proxy option")
		}
	}
	return makeNode(surgeValue(name), obj)
}

func surgeTLS(obj map[string]any, opts surgeOptions, flags map[string]bool) error {
	typ := obj["type"]
	security := "none"
	if flags["tls"] || typ == "trojan" || typ == "hysteria2" || typ == "anytls" {
		security = "tls"
	}
	q := url.Values{"sni": {opts.take("sni")}, "alpn": {opts.take("alpn")}}
	if flags["skip-cert-verify"] {
		q.Set("allowInsecure", "true")
	}
	if key := opts.take("reality-public-key"); key != "" {
		if typ != "vless" {
			return errors.New("Surge Reality requires VLESS")
		}
		security = "reality"
		q.Set("pbk", key)
		q.Set("sid", opts.take("reality-short-id"))
	}
	if security != "none" && typ == "shadowsocks" {
		return errors.New("Surge Shadowsocks TLS requires a supported obfuscation layer")
	}
	tls, err := uriTLS(q, security)
	if err != nil {
		return err
	}
	if tls != nil {
		if q.Get("sni") == "off" {
			delete(tls, "server_name")
			tls["disable_sni"] = true
		}
		obj["tls"] = tls
	}
	return nil
}

func surgeTransport(obj map[string]any, opts surgeOptions, flags map[string]bool) error {
	if !flags["ws"] && !flags["grpc"] {
		if flags["ws-http-upgrade"] {
			return errors.New("Surge HTTP upgrade requires ws=true")
		}
		return nil
	}
	if flags["grpc"] && (flags["ws"] || flags["ws-http-upgrade"]) {
		return errors.New("conflicting Surge transports")
	}
	if obj["type"] != "vmess" && obj["type"] != "vless" && obj["type"] != "trojan" {
		return errors.New("unsupported Surge transport for this protocol")
	}
	if flags["grpc"] {
		if mode := opts.take("grpc-mode"); mode != "" && mode != "gun" {
			return errors.New("unsupported Surge gRPC mode")
		}
		obj["transport"] = map[string]any{"type": "grpc", "service_name": opts.take("grpc-service-name")}
		return nil
	}
	transport := map[string]any{"type": "ws", "path": cmp.Or(opts.take("ws-path"), "/")}
	headers := make(map[string]string)
	if raw := opts.take("ws-headers"); raw != "" {
		for _, pair := range strings.Split(raw, "|") {
			key, value, ok := strings.Cut(pair, ":")
			if !ok || strings.TrimSpace(key) == "" {
				return errors.New("invalid Surge WebSocket headers")
			}
			headers[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
		transport["headers"] = headers
	}
	if flags["ws-http-upgrade"] {
		transport["type"] = "httpupgrade"
		path, err := url.Parse(transport["path"].(string))
		if err != nil {
			return errors.New("invalid Surge HTTP upgrade path")
		}
		query, err := url.ParseQuery(path.RawQuery)
		if err != nil {
			return errors.New("invalid Surge HTTP upgrade query")
		}
		if query.Has("ed") {
			query.Del("ed")
			path.RawQuery = query.Encode()
		}
		transport["path"] = path.String()
		for key, value := range headers {
			if strings.EqualFold(key, "Host") {
				transport["host"] = value
			}
		}
	}
	obj["transport"] = transport
	return nil
}

func surgeHysteria2(obj map[string]any, opts surgeOptions) error {
	if bandwidth := opts.take("download-bandwidth"); bandwidth != "" {
		value, err := strconv.Atoi(bandwidth)
		if err != nil || value < 0 {
			return errors.New("invalid Surge Hysteria2 bandwidth")
		}
		obj["down_mbps"] = value
	}
	for _, mode := range []string{"salamander", "gecko"} {
		if password := opts.take(mode + "-password"); password != "" {
			if obj["obfs"] != nil {
				return errors.New("conflicting Surge Hysteria2 obfuscation")
			}
			obj["obfs"] = map[string]any{"type": mode, "password": password}
		}
	}
	if ports := opts.take("port-hopping"); ports != "" {
		var ranges []string
		for _, value := range strings.Split(ports, ";") {
			ranges = append(ranges, strings.ReplaceAll(strings.TrimSpace(value), "-", ":"))
		}
		obj["server_ports"] = ranges
		interval := cmp.Or(opts.take("port-hopping-interval"), "30")
		seconds, err := strconv.Atoi(interval)
		if err != nil || seconds <= 0 {
			return errors.New("invalid Surge port hopping interval")
		}
		obj["hop_interval"] = strconv.Itoa(seconds) + "s"
	}
	return nil
}
