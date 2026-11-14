package parser

import (
	"cmp"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"

	"onesocks/internal/domain"
)

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
			value := cmp.Or(q.Get(field), q.Get(strings.ReplaceAll(field, "_", "-")))
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
	return makeNode(cmp.Or(u.Fragment, q.Get("remarks"), q.Get("name")), obj)
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
	obj := map[string]any{"type": "vmess", "server": text(v["add"]), "server_port": port, "uuid": text(v["id"]), "security": cmp.Or(text(v["scy"]), "auto")}
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
	network := cmp.Or(text(v["net"]), "tcp")
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
	if name := cmp.Or(q.Get("sni"), q.Get("serverName"), q.Get("peer")); name != "" {
		tls["server_name"] = name
	}
	if insecure := cmp.Or(q.Get("allowInsecure"), q.Get("insecure"), q.Get("skip-cert-verify")); insecure != "" {
		enabled, err := strconv.ParseBool(insecure)
		if err != nil {
			return nil, errors.New("invalid insecure TLS option")
		}
		tls["insecure"] = enabled
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp := cmp.Or(q.Get("fp"), q.Get("fingerprint")); fp != "" {
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
	network := cmp.Or(q.Get("type"), q.Get("network"), "tcp")
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
