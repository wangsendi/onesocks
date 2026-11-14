package parser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"onesocks/internal/engine"
	"onesocks/internal/engine/singbox"
)

const testUUID = "11111111-2222-4333-8444-555555555555"

func outbound(t *testing.T, input string) (string, map[string]any) {
	t.Helper()
	r, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v (%v)", err, r.Warnings)
	}
	if len(r.Nodes) != 1 || len(r.Warnings) != 0 {
		t.Fatalf("nodes=%d warnings=%v", len(r.Nodes), r.Warnings)
	}
	var obj map[string]any
	if err := json.Unmarshal(r.Nodes[0].Outbound, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["tag"] != nil || obj["name"] != nil {
		t.Fatal("display name leaked into connection identity")
	}
	return r.Nodes[0].Name, obj
}

func TestShadowsocksShareForms(t *testing.T) {
	credential := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:secret:with:colons"))
	legacy := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:secret:with:colons@[::1]:8388"))
	for name, input := range map[string]string{
		"SIP002":    "ss://" + credential + "@[::1]:8388#%E9%A6%99%E6%B8%AF",
		"legacy":    "ss://" + legacy + "#%E9%A6%99%E6%B8%AF",
		"plaintext": "ss://aes-128-gcm:secret%3Awith%3Acolons@[::1]:8388#%E9%A6%99%E6%B8%AF",
	} {
		t.Run(name, func(t *testing.T) {
			n, obj := outbound(t, input)
			if n != "香港" || obj["password"] != "secret:with:colons" || obj["server"] != "::1" || obj["server_port"] != float64(8388) {
				t.Fatalf("unexpected result: name=%q obj=%v", n, obj)
			}
		})
	}
}

func TestBase64SubscriptionVariants(t *testing.T) {
	document := "# comments\r\nvless://" + testUUID + "@example.com:443?security=tls&sni=example.com#A\r\n"
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		_, obj := outbound(t, enc.EncodeToString([]byte(document)))
		if obj["type"] != "vless" {
			t.Fatalf("wrong protocol %v", obj)
		}
	}
}

func TestSubscriptionBeyondFormerNodeLimit(t *testing.T) {
	uri := "trojan://fixture@example.com:443#node"
	for format, data := range map[string]string{
		"URI":  strings.Repeat(uri+"\n", 10001),
		"JSON": `{"outbounds":[` + strings.TrimSuffix(strings.Repeat(`{"type":"trojan","tag":"node","server":"example.com","server_port":443,"password":"fixture"},`, 10001), ",") + `]}`,
	} {
		t.Run(format, func(t *testing.T) {
			result, err := Parse([]byte(data))
			if err != nil || len(result.Nodes) != 10001 {
				t.Fatalf("parsed %d nodes, error=%v", len(result.Nodes), err)
			}
		})
	}
}

func TestRealityAndTransports(t *testing.T) {
	_, obj := outbound(t, "vless://"+testUUID+"@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=public-key&sid=abcd&flow=xtls-rprx-vision&client-note=opaque#R")
	tls := obj["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != "public-key" || reality["short_id"] != "abcd" || obj["flow"] != "xtls-rprx-vision" {
		t.Fatal("Reality fields were lost")
	}
	_, ws := outbound(t, "trojan://password@example.com:443?type=ws&host=cdn.example.com&path=%2Fsocket&allowInsecure=1#WS")
	transport := ws["transport"].(map[string]any)
	if transport["path"] != "/socket" || transport["headers"].(map[string]any)["Host"] != "cdn.example.com" || ws["tls"].(map[string]any)["insecure"] != true {
		t.Fatal("WebSocket/TLS fields were lost")
	}
	_, grpc := outbound(t, "vless://"+testUUID+"@example.com:443?security=tls&type=grpc&serviceName=proxy&mode=gun#GRPC")
	if grpc["transport"].(map[string]any)["service_name"] != "proxy" {
		t.Fatal("gRPC service name lost")
	}
}

func TestVMessAndHysteria2(t *testing.T) {
	vmess := fmt.Sprintf(`{"v":"2","ps":"VM","add":"example.com","port":"443","id":%q,"aid":"0","net":"ws","type":"none","host":"cdn.example.com","path":"/ws","tls":"tls","sni":"example.com","scy":"auto","provider_info":"ignored"}`, testUUID)
	name, obj := outbound(t, "vmess://"+base64.StdEncoding.EncodeToString([]byte(vmess)))
	if name != "VM" || obj["security"] != "auto" || obj["alter_id"] != float64(0) || obj["transport"].(map[string]any)["type"] != "ws" {
		t.Fatalf("unexpected VMess config %v", obj)
	}
	_, hy2 := outbound(t, "hy2://user:pass@example.com:8443?obfs=salamander&obfs-password=obfs-secret&sni=example.com#HY2")
	if hy2["password"] != "user:pass" || hy2["obfs"].(map[string]any)["password"] != "obfs-secret" {
		t.Fatal("Hysteria2 authentication/obfuscation lost")
	}
}

func TestSingboxJSONIndependentOutbounds(t *testing.T) {
	input := fmt.Sprintf(`{"outbounds":[{"type":"vless","tag":"HK","server":"example.com","server_port":443,"uuid":%q,"tls":{"enabled":true}},{"type":"direct","tag":"direct"},{"type":"trojan","tag":"chain","server":"example.com","server_port":443,"password":"DONOTLEAK","detour":"other","tls":{"enabled":true}}]}`, testUUID)
	r, err := Parse([]byte(input))
	if err != nil || len(r.Nodes) != 1 || len(r.Warnings) != 2 || r.Nodes[0].Name != "HK" {
		t.Fatalf("result=%+v err=%v", r, err)
	}
	if strings.Contains(string(r.Nodes[0].Outbound), "tag") {
		t.Fatal("tag retained in node config")
	}
	if strings.Contains(strings.Join(r.Warnings, ""), "DONOTLEAK") {
		t.Fatal("credentials leaked")
	}
}

func TestRejectMalformedOrUnsafeNode(t *testing.T) {
	for _, input := range []string{
		"vless://" + testUUID + "@example.com:443?security=tls&type=http",
		"vless://" + testUUID + ":password@example.com:443",
		`{"outbounds":[{"type":"trojan","server":"example.com","server_port":443,"password":"DO-NOT-LEAK","tls":{"enabled":true,"client_key_path":"/sensitive"}}]}`,
	} {
		t.Run(fmt.Sprintf("case-%d", len(input)), func(t *testing.T) {
			r, err := Parse([]byte(input))
			if err == nil || len(r.Nodes) != 0 {
				t.Fatalf("accepted unsupported node, warnings=%v", r.Warnings)
			}
			if strings.Contains(err.Error()+strings.Join(r.Warnings, ""), "DO-NOT-LEAK") {
				t.Fatal("diagnostic leaked credentials")
			}
		})
	}
}

func TestEmptyAndMalformedDocuments(t *testing.T) {
	for _, data := range []string{"", "\n # only comment\n", "<html>upstream error</html>", "{bad-json}", "proxies: []", `{"outbounds":[]}`, "c29tZSB0ZXh0"} {
		if _, err := Parse([]byte(data)); err == nil {
			t.Errorf("accepted %q", data)
		}
	}
}

func TestMixedSingboxOutboundsPreserveProxyConfiguration(t *testing.T) {
	outbounds := []map[string]any{
		{"type": "selector", "tag": "fixture-selector"},
		{"type": "urltest", "tag": "fixture-urltest"},
		{"type": "direct", "tag": "fixture-direct"},
		{"type": "block", "tag": "fixture-block"},
		{
			"type": "shadowsocks", "tag": "fixture-ss", "server": "ss.example.test", "server_port": 443,
			"method": "chacha20-ietf-poly1305", "password": "fixture-password", "plugin": "obfs-local", "plugin_opts": "obfs=tls;obfs-host=cdn.example.test",
			"udp_over_tcp": true, "domain_resolver": "fixture-provider-dns",
		},
		{
			"type": "anytls", "tag": "fixture-anytls", "server": "anytls.example.test", "server_port": 443, "password": "fixture-password",
			"domain_resolver": "fixture-provider-dns", "idle_session_check_interval": "30s", "idle_session_timeout": "30s", "min_idle_session": 0,
			"tls": map[string]any{"enabled": true, "server_name": "tls.example.test", "utls": map[string]any{"enabled": true, "fingerprint": "chrome"}, "alpn": []string{"h2", "http/1.1"}},
		},
	}
	raw, _ := json.Marshal(map[string]any{"dns": map[string]any{"servers": []any{map[string]any{"tag": "fixture-provider-dns", "type": "https", "server": "dns.example.test"}}}, "outbounds": outbounds})
	result, err := Parse(raw)
	if err != nil {
		t.Fatalf("mixed outbounds document: %v", err)
	}
	if len(result.Nodes) != 2 {
		t.Fatalf("supported %d nodes, want 2; warnings=%v", len(result.Nodes), result.Warnings)
	}
	counts := make(map[string]int)
	for _, node := range result.Nodes {
		var obj map[string]any
		if err := json.Unmarshal(node.Outbound, &obj); err != nil {
			t.Fatal(err)
		}
		counts[text(obj["type"])]++
		if obj["domain_resolver"] != "bootstrap" {
			t.Fatal("source DNS reference was not adapted")
		}
		if obj["type"] == "shadowsocks" && (obj["plugin"] != "obfs-local" || obj["plugin_opts"] != "obfs=tls;obfs-host=cdn.example.test" || obj["udp_over_tcp"] != true) {
			t.Fatal("SS plugin or UoT configuration was lost")
		}
		if obj["type"] == "anytls" && (obj["idle_session_timeout"] != "30s" || obj["min_idle_session"] != float64(0) || obj["tls"].(map[string]any)["utls"] == nil) {
			t.Fatal("AnyTLS session/TLS configuration was lost")
		}
	}
	if counts["shadowsocks"] != 1 || counts["anytls"] != 1 {
		t.Fatalf("protocol counts=%v", counts)
	}
	if len(result.Warnings) != 5 || !strings.Contains(result.Warnings[len(result.Warnings)-1], "2 nodes") {
		t.Fatalf("missing DNS adaptation notice or ignored-outbound diagnostics: %v", result.Warnings)
	}
}

func TestDomainResolverAdaptationPreservesPolicy(t *testing.T) {
	for _, reference := range []string{`"source-resolver"`, `{"server":"source-resolver","strategy":"prefer_ipv4","timeout":"7s","disable_cache":true,"disable_optimistic_cache":true,"rewrite_ttl":60,"client_subnet":"192.0.2.0/24"}`} {
		raw := fmt.Sprintf(`{"type":"trojan","tag":"fixture","server":"example.test","server_port":443,"password":"fixture-password","tls":{"enabled":true},"domain_resolver":%s}`, reference)
		result, err := Parse([]byte(raw))
		if err != nil || len(result.Nodes) != 1 || len(result.Warnings) != 1 {
			t.Fatalf("result=%+v err=%v", result, err)
		}
		var obj map[string]any
		json.Unmarshal(result.Nodes[0].Outbound, &obj)
		if policy, ok := obj["domain_resolver"].(map[string]any); ok {
			if policy["server"] != "bootstrap" || policy["strategy"] != "prefer_ipv4" || policy["timeout"] != "7s" || policy["rewrite_ttl"] != float64(60) || policy["client_subnet"] != "192.0.2.0/24" || policy["disable_cache"] != true || policy["disable_optimistic_cache"] != true {
				t.Fatal("DNS resolution policy was lost")
			}
		} else if obj["domain_resolver"] != "bootstrap" {
			t.Fatal("DNS tag was not adapted")
		}
	}
}

func TestBuiltinShadowsocksPlugins(t *testing.T) {
	for _, plugin := range []string{"obfs-local;obfs=tls;obfs-host=cdn.example.test", "v2ray-plugin;tls;host=cdn.example.test;path=/proxy;mux=0"} {
		_, obj := outbound(t, "ss://chacha20-ietf-poly1305:fixture-password@example.test:443?plugin="+url.QueryEscape(plugin))
		name, options, _ := strings.Cut(plugin, ";")
		if obj["plugin"] != name || obj["plugin_opts"] != options {
			t.Fatal("SIP003 options were changed")
		}
	}
	if _, err := Parse([]byte("ss://chacha20-ietf-poly1305:fixture-password@example.test:443?plugin=" + url.QueryEscape("v2ray-plugin;cert=/private.pem"))); err == nil {
		t.Fatal("plugin was allowed to load a local certificate file")
	}
}

func TestAnyTLSURIConversion(t *testing.T) {
	_, obj := outbound(t, "anytls://fixture-password@example.test:443?sni=tls.example.test&fp=chrome&alpn=h2%2Chttp%2F1.1&idle-session-check-interval=30s&idle-session-timeout=1m&min-idle-session=2#fixture")
	if obj["type"] != "anytls" || obj["password"] != "fixture-password" || obj["idle_session_check_interval"] != "30s" || obj["idle_session_timeout"] != "1m" || obj["min_idle_session"] != float64(2) {
		t.Fatal("AnyTLS URI fields lost")
	}
	if _, err := Parse([]byte("anytls://fixture-password@example.test:443?min_idle_session=not-an-integer")); err == nil {
		t.Fatal("accepted a nonnumeric URI session count")
	}
}

func TestConfigDocumentsAreNotParsedAsURILists(t *testing.T) {
	for _, input := range []string{
		"proxies: []",
		"proxies:\n  uri: |\n    trojan://fixture-password@example.test:443#fixture\n",
		"proxies:\n  - trojan://fixture-password@example.test:443#fixture\n",
	} {
		result, err := Parse([]byte(input))
		if err == nil || len(result.Nodes) != 0 {
			t.Fatal("configuration document was accepted as a URI list")
		}
	}
}

func TestJSONPreservesKernelOptions(t *testing.T) {
	input := `{"type":"vmess","server":"example.test","server_port":"443","uuid":"custom-user","global_padding":true,"transport":{"type":"http","path":"/h2"},"domain_resolver":{"server":"source-dns","strategy":"prefer_ipv4","future_option":true},"future_outbound_option":"opaque"}`
	result, err := Parse([]byte(input))
	if err != nil || len(result.Nodes) != 1 {
		t.Fatalf("parse JSON options: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(result.Nodes[0].Outbound, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["server_port"] != float64(443) || obj["security"] != "auto" {
		t.Fatal("existing node normalization changed")
	}
	if obj["uuid"] != "custom-user" || obj["global_padding"] != true || obj["future_outbound_option"] != "opaque" || obj["transport"].(map[string]any)["type"] != "http" {
		t.Fatal("kernel options were filtered by the subscription parser")
	}
	resolver := obj["domain_resolver"].(map[string]any)
	if resolver["server"] != "bootstrap" || resolver["future_option"] != true || len(result.Warnings) != 1 {
		t.Fatal("DNS policy or adaptation diagnostic was lost")
	}
}

func TestKernelOwnsProtocolValidation(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		wantError bool
	}{
		{"AnyTLS session defaults", `{"type":"anytls","server":"127.0.0.1","server_port":443,"password":"fixture-password","tls":{"enabled":true},"idle_session_check_interval":"-1s","idle_session_timeout":"-1s","min_idle_session":-1}`, false},
		{"unknown plugin", `{"type":"shadowsocks","server":"127.0.0.1","server_port":443,"method":"aes-128-gcm","password":"fixture-password","plugin":"unknown-plugin"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := Parse([]byte(tc.raw))
			if err != nil {
				t.Fatalf("parser duplicated kernel validation: %v", err)
			}
			client, err := singbox.New(context.Background(), []engine.Node{{ID: "node", Outbound: result.Nodes[0].Outbound}})
			if client != nil {
				_ = client.Close()
			}
			if (err != nil) != tc.wantError {
				t.Fatalf("kernel error=%v, want error=%t", err, tc.wantError)
			}
		})
	}
}
