package parser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/transport/sip003"
	"onesocks/internal/engine"
	"onesocks/internal/engine/singbox"
)

func TestClashProtocols(t *testing.T) {
	for _, tc := range []struct {
		name, fields, expected string
	}{
		{"SS", "type: ss, cipher: aes-128-gcm, password: secret, udp: true", `{"type":"shadowsocks","method":"aes-128-gcm","password":"secret"}`},
		{"VMess", "type: vmess, uuid: " + testUUID + ", cipher: auto, alterId: '0', xudp: true", `{"type":"vmess","uuid":"` + testUUID + `","security":"auto","alter_id":0,"packet_encoding":"xudp"}`},
		{"VLESS", "type: vless, uuid: " + testUUID + ", udp: false", `{"type":"vless","uuid":"` + testUUID + `","network":"tcp"}`},
		{"Trojan", "type: trojan, password: secret, sni: example.com, skip-cert-verify: true, alpn: [h2, http/1.1]", `{"type":"trojan","password":"secret","tls":{"enabled":true,"server_name":"example.com","insecure":true,"alpn":["h2","http/1.1"]}}`},
		{"Hysteria2", "type: hysteria2, password: secret, obfs: salamander, obfs-password: obfs-secret, up: 20 Mbps, down: 50, sni: example.com", `{"type":"hysteria2","password":"secret","obfs":{"type":"salamander","password":"obfs-secret"},"up_mbps":20,"down_mbps":50,"tls":{"enabled":true,"server_name":"example.com"}}`},
		{"AnyTLS", "type: anytls, password: secret, idle-session-check-interval: 30, idle-session-timeout: 1m, min-idle-session: 2", `{"type":"anytls","password":"secret","min_idle_session":2,"idle_session_check_interval":"30s","idle_session_timeout":"1m","tls":{"enabled":true}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := "proxies:\n- {name: 节点, server: 127.0.0.1, port: '443', " + tc.fields + "}\n"
			name, got := outbound(t, input)
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.expected), &want); err != nil {
				t.Fatal(err)
			}
			want["server"], want["server_port"] = "127.0.0.1", float64(443)
			if name != "节点" || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v; want %v", got, want)
			}
			raw, _ := json.Marshal(got)
			client, err := singbox.New(context.Background(), []engine.Node{{ID: "node", Outbound: raw}})
			if err != nil {
				t.Fatalf("actual sing-box rejected translated Clash node: %v", err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClashDocumentFormats(t *testing.T) {
	const node = `{name: "节点 # 01", type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: "pass:#word"}`
	for name, input := range map[string]string{
		"full config":  "\ufeff# fixture\n---\nmixed-port: 7890\nproxy-groups: [{name: select, type: select, proxies: [节点]}]\nrules: [MATCH,select]\ndns: {nameserver: [https://example.com/dns-query]}\nproxies: [" + node + "]",
		"flow mapping": "{proxies: [" + node + "]}",
		"provider":     "proxies:\n- " + node,
		"base64":       base64.StdEncoding.EncodeToString([]byte("proxies: [" + node + "]")),
		"JSON":         `{"proxies":[{"name":"节点 # 01","type":"ss","server":"example.com","port":443,"cipher":"aes-128-gcm","password":"pass:#word"}]}`,
		"anchors":      "defaults: &defaults {type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: 'pass:#word'}\nproxies:\n- <<: *defaults\n  name: '节点 # 01'\n",
	} {
		t.Run(name, func(t *testing.T) {
			name, got := outbound(t, input)
			if name != "节点 # 01" || got["password"] != "pass:#word" {
				t.Fatal("YAML name or password changed")
			}
		})
	}
}

func TestClashTLSAndTransports(t *testing.T) {
	_, node := outbound(t, "global-client-fingerprint: firefox\nproxies:\n- type: vless\n  server: example.com\n  port: 443\n  uuid: "+testUUID+"\n  tls: true\n  servername: tls.example.com\n  flow: xtls-rprx-vision\n  reality-opts: {public-key: fixture-key, short-id: '0123'}\n")
	tls := node["tls"].(map[string]any)
	if tls["utls"].(map[string]any)["fingerprint"] != "firefox" || tls["reality"].(map[string]any)["short_id"] != "0123" || tls["server_name"] != "tls.example.com" || node["flow"] != "xtls-rprx-vision" {
		t.Fatal("Reality or global fingerprint lost")
	}
	_, ws := outbound(t, "proxies:\n- {type: vmess, server: example.com, port: 443, uuid: "+testUUID+", network: ws, ws-opts: {path: '/proxy?token=abc&ed=2048', headers: {Host: cdn.example.com, X-Test: fixture}}}")
	transport := ws["transport"].(map[string]any)
	if transport["type"] != "ws" || transport["path"] != "/proxy?token=abc" || transport["max_early_data"] != float64(2048) || transport["early_data_header_name"] != "Sec-WebSocket-Protocol" || transport["headers"].(map[string]any)["Host"] != "cdn.example.com" {
		t.Fatal("WebSocket headers/path/early data lost")
	}
	_, grpc := outbound(t, "proxies:\n- {type: trojan, server: example.com, port: 443, password: secret, network: grpc, grpc-opts: {grpc-service-name: my-service}}")
	if grpc["transport"].(map[string]any)["service_name"] != "my-service" {
		t.Fatal("gRPC service name lost")
	}
}

func TestClashShadowsocksPlugins(t *testing.T) {
	for _, tc := range []struct {
		plugin, options, wantPlugin string
		want                        sip003.Args
	}{
		{"obfs", "{mode: tls, host: cdn.example.com}", "obfs-local", sip003.Args{"obfs": {"tls"}, "obfs-host": {"cdn.example.com"}}},
		{"v2ray-plugin", "{mode: websocket, tls: false, mux: false, host: cdn.example.com, path: '/ws;a=b'}", "v2ray-plugin", sip003.Args{"mode": {"websocket"}, "mux": {"0"}, "host": {"cdn.example.com"}, "path": {"/ws;a=b"}}},
		{"v2ray-plugin", "{tls: true, mux: true}", "v2ray-plugin", sip003.Args{"tls": {"1"}, "mux": {"1"}}},
	} {
		t.Run(tc.plugin+tc.options, func(t *testing.T) {
			_, got := outbound(t, fmt.Sprintf("proxies:\n- {type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: secret, plugin: %s, plugin-opts: %s, udp-over-tcp: true}", tc.plugin, tc.options))
			options, err := sip003.ParsePluginOptions(got["plugin_opts"].(string))
			if err != nil || got["plugin"] != tc.wantPlugin || !reflect.DeepEqual(options, tc.want) {
				t.Fatalf("incorrect plugin translation: %v, %v", options, err)
			}
			if got["udp_over_tcp"].(map[string]any)["version"] != float64(2) {
				t.Fatal("Clash UoT version default lost")
			}
		})
	}
}

func TestClashMixedInvalidNodesAndSafeDiagnostics(t *testing.T) {
	for _, fields := range []string{
		"type: ssr", "port: 443.5", "port: 65536", "port: DO-NOT-LEAK", "password: [DO-NOT-LEAK]",
		"dialer-proxy: DO-NOT-LEAK", "network: xhttp", "fingerprint: DO-NOT-LEAK", "smux: {enabled: true}",
		"network: ws, ws-opts: {v2ray-http-upgrade-fast-open: true}",
		"plugin: v2ray-plugin, plugin-opts: {cert: /DO-NOT-LEAK}",
	} {
		t.Run(fields, func(t *testing.T) {
			input := "defaults: &defaults {type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: DO-NOT-LEAK}\nproxies:\n- <<: *defaults\n  " + strings.ReplaceAll(fields, ", ", "\n  ") + "\n- {type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: good}\n"
			result, err := Parse([]byte(input))
			if err != nil || len(result.Nodes) != 1 || len(result.Warnings) != 1 {
				t.Fatalf("result count=%d, warnings=%v, error=%v", len(result.Nodes), result.Warnings, err)
			}
			if strings.Contains(strings.Join(result.Warnings, ""), "DO-NOT-LEAK") {
				t.Fatal("diagnostic leaked source credentials")
			}
		})
	}
}

func TestClashRejectsMalformedDocuments(t *testing.T) {
	for _, input := range []string{
		"proxies: []", "proxies: {}", "proxies: [DO-NOT-LEAK]", "proxies: [\nDO-NOT-LEAK", "proxies: []\nproxies: []",
		"proxies: []\n---\nproxies: []", "defaults: &loop {nested: *loop}\nproxies: [*loop]",
		"proxy-providers: {remote: {url: https://example.com/DO-NOT-LEAK}}",
	} {
		result, err := Parse([]byte(input))
		if err == nil || len(result.Nodes) > 0 {
			t.Fatal("accepted malformed Clash document")
		}
		if strings.Contains(err.Error()+strings.Join(result.Warnings, ""), "DO-NOT-LEAK") {
			t.Fatal("YAML diagnostics leaked source")
		}
	}
}
