// Package parser converts subscription documents into independent sing-box outbounds.
package parser

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"onesocks/internal/domain"

	"github.com/sagernet/sing-box/transport/sip003"
)

var supported = map[string]bool{"shadowsocks": true, "vless": true, "trojan": true, "vmess": true, "hysteria2": true, "anytls": true}

// Parse accepts a URI list, a base64-encoded URI list or sing-box JSON.
// Diagnostics deliberately never include URI credentials or source documents.
func Parse(data []byte) (domain.ParseResult, error) {
	var result domain.ParseResult
	data = bytes.TrimSpace(bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf}))
	if len(data) == 0 {
		return result, errors.New("subscription is empty")
	}
	if data[0] == '{' || data[0] == '[' {
		return parseJSON(data)
	}
	if !strings.Contains(string(data), "://") {
		decoded, err := decode64(string(data))
		if err != nil || !bytes.Contains(decoded, []byte("://")) {
			return result, errors.New("unrecognized subscription format")
		}
		data = bytes.TrimSpace(bytes.TrimPrefix(decoded, []byte{0xef, 0xbb, 0xbf}))
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	first := true
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// A URI-list document starts with a URI, rather than arbitrary config
		// text that happens to contain URLs or a nested multiline URI value.
		if first && !hasURIScheme(line) {
			return result, errors.New("unrecognized subscription format")
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

func parseJSON(data []byte) (domain.ParseResult, error) {
	var result domain.ParseResult
	resolverReplacements := 0
	var entries []json.RawMessage
	if data[0] == '[' {
		if json.Unmarshal(data, &entries) != nil {
			return result, errors.New("invalid subscription JSON")
		}
	} else {
		var doc map[string]json.RawMessage
		if json.Unmarshal(data, &doc) != nil {
			return result, errors.New("invalid subscription JSON")
		}
		if raw, ok := doc["outbounds"]; ok {
			if json.Unmarshal(raw, &entries) != nil {
				return result, errors.New("invalid outbounds list")
			}
		} else if _, ok := doc["type"]; ok {
			entries = []json.RawMessage{data}
		} else {
			return result, errors.New("JSON has no outbounds")
		}
	}
	for i, entry := range entries {
		var obj map[string]any
		var n domain.NodeSpec
		err := json.Unmarshal(entry, &obj)
		if err != nil {
			err = errors.New("invalid outbound object")
		} else {
			name := text(obj["tag"])
			delete(obj, "tag")
			delete(obj, "name")
			adapted := false
			if supported[text(obj["type"])] {
				adapted = adaptDomainResolver(obj)
			}
			n, err = makeNode(name, obj)
			if err == nil && adapted {
				resolverReplacements++
			}
		}
		appendNode(&result, n, err, i)
	}
	if resolverReplacements > 0 {
		result.Warnings = append(result.Warnings, fmt.Sprintf("domain_resolver references replaced with OneSocks bootstrap for %d nodes; source DNS and routing configuration were not imported", resolverReplacements))
	}
	return finish(result)
}

func parseURI(raw string) (domain.NodeSpec, error) {
	if strings.HasPrefix(raw, "ss://") {
		return ssURI(raw)
	}
	if strings.HasPrefix(raw, "vmess://") {
		return vmessURI(raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid node URI")
	}
	typ := u.Scheme
	if typ == "hy2" {
		typ = "hysteria2"
	}
	if !supported[typ] {
		return domain.NodeSpec{}, errors.New("unsupported URI protocol")
	}
	if u.Path != "" && u.Path != "/" {
		return domain.NodeSpec{}, errors.New("unexpected URI path")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return domain.NodeSpec{}, errors.New("invalid server port")
		}
	}
	if u.User == nil {
		return domain.NodeSpec{}, errors.New("missing node credentials")
	}
	obj := map[string]any{"type": typ, "server": u.Hostname(), "server_port": port}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid URI parameters")
	}
	if typ == "anytls" {
		for _, field := range []string{"idle_session_check_interval", "idle_session_timeout", "min_idle_session"} {
			value := first(q.Get(field), q.Get(strings.ReplaceAll(field, "_", "-")))
			if value != "" {
				obj[field] = value
			}
		}
	}
	if typ == "vless" {
		if _, present := u.User.Password(); present {
			return domain.NodeSpec{}, errors.New("invalid VLESS URI credentials")
		}
		obj["uuid"] = u.User.Username()
		if flow := q.Get("flow"); flow != "" {
			obj["flow"] = flow
		}
		// This share-link extension has no equivalent in sing-box's VLESS
		// options; accepting it would discard requested wire encryption.
		if encryption := q.Get("encryption"); encryption != "" && encryption != "none" {
			return domain.NodeSpec{}, errors.New("unsupported VLESS URI encryption")
		}
		if encoding := q.Get("packetEncoding"); encoding != "" {
			obj["packet_encoding"] = encoding
		}
	} else {
		password := u.User.Username()
		if suffix, ok := u.User.Password(); ok {
			password += ":" + suffix
		}
		obj["password"] = password
	}
	if q.Get("pinSHA256") != "" {
		return domain.NodeSpec{}, errors.New("certificate pinning URI parameter cannot be translated")
	}
	security := q.Get("security")
	if security == "" {
		if typ == "vless" {
			security = "none"
		} else {
			security = "tls"
		}
	}
	tls, err := uriTLS(q, security)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	if tls != nil {
		obj["tls"] = tls
	}
	transport, err := uriTransport(q)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	if transport != nil {
		obj["transport"] = transport
	}
	if typ == "hysteria2" && (q.Get("obfs") != "" || q.Get("obfs-password") != "") {
		obj["obfs"] = map[string]any{"type": q.Get("obfs"), "password": q.Get("obfs-password")}
	}
	return makeNode(first(u.Fragment, q.Get("remarks"), q.Get("name")), obj)
}

func ssURI(raw string) (domain.NodeSpec, error) {
	rest := strings.TrimPrefix(raw, "ss://")
	name := ""
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		var err error
		name, err = url.PathUnescape(rest[i+1:])
		if err != nil {
			return domain.NodeSpec{}, errors.New("invalid node name encoding")
		}
		rest = rest[:i]
	}
	query := ""
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		query = rest[i+1:]
		rest = rest[:i]
	}
	q, err := url.ParseQuery(query)
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid Shadowsocks parameters")
	}
	if !strings.Contains(rest, "@") {
		decoded, err := decode64(strings.TrimSuffix(rest, "/"))
		if err != nil {
			return domain.NodeSpec{}, errors.New("invalid Shadowsocks base64")
		}
		rest = string(decoded)
	}
	i := strings.LastIndexByte(rest, '@')
	if i < 1 {
		return domain.NodeSpec{}, errors.New("invalid Shadowsocks credentials")
	}
	credentials, address := rest[:i], strings.TrimSuffix(rest[i+1:], "/")
	credentials, err = url.PathUnescape(credentials)
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid Shadowsocks credential encoding")
	}
	if !strings.Contains(credentials, ":") {
		decoded, err := decode64(credentials)
		if err != nil {
			return domain.NodeSpec{}, errors.New("invalid Shadowsocks credentials")
		}
		credentials = string(decoded)
	}
	method, password, ok := strings.Cut(credentials, ":")
	if !ok {
		return domain.NodeSpec{}, errors.New("missing Shadowsocks password")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid Shadowsocks server address")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid server port")
	}
	obj := map[string]any{"type": "shadowsocks", "server": host, "server_port": port, "method": method, "password": password}
	if plugin := q.Get("plugin"); plugin != "" {
		pluginName, options, _ := strings.Cut(plugin, ";")
		obj["plugin"], obj["plugin_opts"] = pluginName, options
	}
	return makeNode(name, obj)
}

func vmessURI(raw string) (domain.NodeSpec, error) {
	b, err := decode64(strings.TrimPrefix(raw, "vmess://"))
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid VMess base64")
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return domain.NodeSpec{}, errors.New("invalid VMess JSON")
	}
	port, err := number(v["port"])
	if err != nil {
		return domain.NodeSpec{}, errors.New("invalid server port")
	}
	obj := map[string]any{"type": "vmess", "server": text(v["add"]), "server_port": port, "uuid": text(v["id"]), "security": first(text(v["scy"]), "auto")}
	if text(v["aid"]) != "" {
		aid, err := number(v["aid"])
		if err != nil {
			return domain.NodeSpec{}, errors.New("invalid VMess alter ID")
		}
		obj["alter_id"] = aid
	}
	if text(v["packetEncoding"]) != "" {
		obj["packet_encoding"] = text(v["packetEncoding"])
	}
	q := url.Values{}
	for _, key := range []string{"sni", "alpn", "fp", "allowInsecure", "host", "path"} {
		if s := text(v[key]); s != "" {
			q.Set(key, s)
		}
	}
	network := first(text(v["net"]), "tcp")
	q.Set("type", network)
	if network == "grpc" {
		q.Set("serviceName", text(v["path"]))
		q.Del("path")
	}
	if header := text(v["type"]); header != "" && header != "none" {
		if network != "grpc" || header != "gun" {
			return domain.NodeSpec{}, errors.New("unsupported VMess header or gRPC mode")
		}
	}
	security := text(v["tls"])
	if security == "" {
		security = "none"
	}
	tls, err := uriTLS(q, security)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	if tls != nil {
		obj["tls"] = tls
	}
	transport, err := uriTransport(q)
	if err != nil {
		return domain.NodeSpec{}, err
	}
	if transport != nil {
		obj["transport"] = transport
	}
	return makeNode(text(v["ps"]), obj)
}

func uriTLS(q url.Values, security string) (map[string]any, error) {
	if security == "none" || security == "" {
		return nil, nil
	}
	if security != "tls" && security != "reality" {
		return nil, errors.New("unsupported URI TLS security mode")
	}
	tls := map[string]any{"enabled": true}
	if name := first(q.Get("sni"), q.Get("serverName"), q.Get("peer")); name != "" {
		tls["server_name"] = name
	}
	if insecure := first(q.Get("allowInsecure"), q.Get("insecure"), q.Get("skip-cert-verify")); insecure != "" {
		enabled, err := boolean(insecure)
		if err != nil {
			return nil, errors.New("invalid insecure TLS option")
		}
		tls["insecure"] = enabled
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp := first(q.Get("fp"), q.Get("fingerprint")); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if security == "reality" {
		tls["reality"] = map[string]any{"enabled": true, "public_key": q.Get("pbk"), "short_id": q.Get("sid")}
		if tls["utls"] == nil {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		}
	}
	return tls, nil
}

func uriTransport(q url.Values) (map[string]any, error) {
	network := first(q.Get("type"), q.Get("network"), "tcp")
	if header := q.Get("headerType"); header != "" && header != "none" {
		return nil, errors.New("TCP header obfuscation cannot be translated")
	}
	switch network {
	case "tcp", "none":
		return nil, nil
	case "ws":
		transport := map[string]any{"type": "ws"}
		if path := q.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := q.Get("host"); host != "" {
			transport["headers"] = map[string]string{"Host": host}
		}
		return transport, nil
	case "grpc":
		transport := map[string]any{"type": "grpc"}
		if name := q.Get("serviceName"); name != "" {
			transport["service_name"] = name
		}
		return transport, nil
	default:
		return nil, errors.New("unsupported URI transport")
	}
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
	// Preserve the existing normalized representation used for node IDs.
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

// Source DNS tags do not exist in the independent OneSocks runtime. Retain
// policy fields and let sing-box decode them after replacing the reference.
func adaptDomainResolver(obj map[string]any) bool {
	switch resolver := obj["domain_resolver"].(type) {
	case string:
		obj["domain_resolver"] = "bootstrap"
		return resolver != "bootstrap"
	case map[string]any:
		previous := resolver["server"]
		resolver["server"] = "bootstrap"
		return previous != "bootstrap"
	default:
		return false
	}
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

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
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
func boolean(v any) (bool, error) {
	s := text(v)
	if s == "1" {
		return true, nil
	}
	if s == "0" {
		return false, nil
	}
	return strconv.ParseBool(s)
}
