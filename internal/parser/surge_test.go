package parser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"onesocks/internal/engine"
	"onesocks/internal/engine/singbox"
)

func TestSurgeProtocolConversionsAndKernelConstruction(t *testing.T) {
	var nodes []engine.Node
	for _, test := range []struct {
		name, declaration string
		want              map[string]any
		tls               bool
	}{
		{"香港SS", "ss, 127.0.0.1, 8388, encrypt-method=aes-128-gcm, password=fixture-password, udp-relay=true", map[string]any{"type": "shadowsocks", "method": "aes-128-gcm", "password": "fixture-password", "server_port": float64(8388)}, false},
		{"VMess旧握手", "vmess, 127.0.0.1, 443, username=" + testUUID, map[string]any{"type": "vmess", "uuid": testUUID, "security": "aes-128-gcm", "alter_id": float64(1)}, false},
		{"VLESS", "vless, 127.0.0.1, 443, username=" + testUUID + ", tls=true", map[string]any{"type": "vless", "uuid": testUUID}, true},
		{"Trojan", "trojan, 127.0.0.1, 443, password=fixture-password", map[string]any{"type": "trojan", "password": "fixture-password"}, true},
		{"Hysteria2", "hysteria2, 127.0.0.1, 443, password=fixture-password, download-bandwidth=100, salamander-password=obfs-secret", map[string]any{"type": "hysteria2", "password": "fixture-password", "down_mbps": float64(100), "obfs": map[string]any{"type": "salamander", "password": "obfs-secret"}}, true},
		{"AnyTLS", "anytls, 127.0.0.1, 443, password=fixture-password", map[string]any{"type": "anytls", "password": "fixture-password"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			name, obj := outbound(t, test.name+" = "+test.declaration)
			if name != test.name || obj["server"] != "127.0.0.1" {
				t.Fatalf("name/server changed: name=%q outbound=%v", name, obj)
			}
			for key, expected := range test.want {
				if !reflect.DeepEqual(obj[key], expected) {
					t.Errorf("%s=%v, want %v", key, obj[key], expected)
				}
			}
			if test.tls {
				tls, ok := obj["tls"].(map[string]any)
				if !ok || tls["enabled"] != true {
					t.Fatalf("TLS not enabled for %s: %v", test.name, obj)
				}
				if _, explicit := tls["insecure"]; explicit {
					t.Fatalf("unspecified TLS verification option was inserted: %v", tls)
				}
			}
			raw, err := json.Marshal(obj)
			if err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, engine.Node{ID: fmt.Sprintf("surge-%d", len(nodes)), Outbound: raw})
		})
	}
	client, err := singbox.New(context.Background(), nodes)
	if client != nil {
		_ = client.Close()
	}
	if err != nil {
		t.Fatalf("converted Surge nodes could not construct sing-box: %v", err)
	}
}

func TestSurgeVMessHandshakeDefaultsAndAEAD(t *testing.T) {
	for _, test := range []struct {
		options  string
		alterID  float64
		security string
	}{
		{"", 1, "aes-128-gcm"},
		{", vmess-aead=false", 1, "aes-128-gcm"},
		{", vmess-aead=true", 0, "aes-128-gcm"},
		{", vmess-aead=true, encrypt-method=chacha20-ietf-poly1305", 0, "chacha20-poly1305"},
	} {
		_, obj := outbound(t, "VM = vmess, example.test, 443, username="+testUUID+test.options)
		if obj["alter_id"] != test.alterID || obj["security"] != test.security {
			t.Errorf("options %q: security=%v alter_id=%v", test.options, obj["security"], obj["alter_id"])
		}
	}
}

func TestSurgeSectionsCommentsAndBase64Documents(t *testing.T) {
	const full = `#!MANAGED-CONFIG https://subscription.example.test/list interval=3600
[General]
not-a-proxy = trojan, unwanted.example.test, 443, password=do-not-import
[Proxy]
# full-line comment
; another comment
// third comment
香港01 = ss, example.test, 8388, encrypt-method=aes-128-gcm, password=secret # trailing comment
[Proxy Group]
also-not-a-proxy = trojan, unwanted.example.test, 443, password=do-not-import
[Rule]
DOMAIN-SUFFIX,example.test,DIRECT
[Proxy]
日本02 = trojan, example.test, 443, password=secret ; trailing comment
新加坡03 = anytls, example.test, 443, password=secret // trailing comment
[Host]
still-not-a-proxy = trojan, unwanted.example.test, 443, password=do-not-import
`
	const plain = `# plain proxy list
香港01 = ss, example.test, 8388, encrypt-method=aes-128-gcm, password=secret
日本02 = trojan, example.test, 443, password=secret
新加坡03 = anytls, example.test, 443, password=secret
`
	for name, document := range map[string]string{"full": full, "plain": plain} {
		variants := map[string]string{"raw": document, "BOM-CRLF": "\xef\xbb\xbf" + strings.ReplaceAll(document, "\n", "\r\n")}
		for label, encoding := range map[string]*base64.Encoding{"std": base64.StdEncoding, "raw-std": base64.RawStdEncoding, "url": base64.URLEncoding, "raw-url": base64.RawURLEncoding} {
			variants[label] = encoding.EncodeToString([]byte(document))
		}
		for encoding, data := range variants {
			t.Run(name+"/"+encoding, func(t *testing.T) {
				result, err := Parse([]byte(data))
				if err != nil || len(result.Nodes) != 3 || len(result.Warnings) != 0 {
					t.Fatalf("nodes=%d warnings=%v error=%v", len(result.Nodes), result.Warnings, err)
				}
				for i, want := range []string{"香港01", "日本02", "新加坡03"} {
					if result.Nodes[i].Name != want || strings.Contains(string(result.Nodes[i].Outbound), "do-not-import") {
						t.Fatalf("section filtering or node order changed: %+v", result.Nodes)
					}
				}
			})
		}
	}
}

func TestSurgeQuotedCredentialsPreserveDelimiters(t *testing.T) {
	for _, test := range []struct {
		value, want string
	}{
		{`"comma,#;https://inside.example/a=b=="`, `comma,#;https://inside.example/a=b==`},
		{`"p,a#b=c\\path\"tail"`, `p,a#b=c\path"tail`},
		{`base64-padding==`, `base64-padding==`},
	} {
		name, obj := outbound(t, "香港-含特殊密码 = trojan, example.test, 443, password="+test.value+", sni=tls.example.test")
		if name != "香港-含特殊密码" || obj["password"] != test.want || obj["tls"].(map[string]any)["server_name"] != "tls.example.test" {
			t.Fatalf("quoted value lost: name=%q password=%q outbound=%v", name, obj["password"], obj)
		}
	}
	name, obj := outbound(t, `"香港 = 01,专线" = trojan, example.test, 443, password=secret`)
	if name != "香港 = 01,专线" || obj["password"] != "secret" {
		t.Fatal("quoted node name changed")
	}
}

func TestSurgeTLSAndWebSocketParameters(t *testing.T) {
	_, obj := outbound(t, `香港WS = trojan, example.test, 443, password=fixture-password, sni=tls.example.test, skip-cert-verify=true, alpn="h2,http/1.1", ws=true, ws-path="/socket?q=a,b=c", ws-headers="Host:cdn.example.test|X-Token:abc=="`)
	tls, ok := obj["tls"].(map[string]any)
	if !ok || tls["enabled"] != true || tls["server_name"] != "tls.example.test" || tls["insecure"] != true || !reflect.DeepEqual(tls["alpn"], []any{"h2", "http/1.1"}) {
		t.Fatalf("TLS parameters lost: %v", obj)
	}
	transport, ok := obj["transport"].(map[string]any)
	if !ok || transport["type"] != "ws" || transport["path"] != "/socket?q=a,b=c" {
		t.Fatalf("WebSocket parameters lost: %v", obj)
	}
	headers, ok := transport["headers"].(map[string]any)
	if !ok || headers["Host"] != "cdn.example.test" || headers["X-Token"] != "abc==" {
		t.Fatalf("WebSocket headers lost: %v", transport)
	}
	_, obj = outbound(t, "SS混淆 = ss, example.test, 443, encrypt-method=aes-128-gcm, password=secret, obfs=tls, obfs-host=cdn.example.test")
	if obj["plugin"] != "obfs-local" || !strings.Contains(text(obj["plugin_opts"]), "obfs=tls") || !strings.Contains(text(obj["plugin_opts"]), "obfs-host=cdn.example.test") {
		t.Fatalf("SS obfuscation lost: %v", obj)
	}
}

func TestSurgeVLESSTransportsRealityAndSNI(t *testing.T) {
	_, grpc := outbound(t, "gRPC = vless, example.test, 443, username="+testUUID+", tls=true, grpc=true, grpc-service-name=mygrpc, grpc-mode=gun")
	if !reflect.DeepEqual(grpc["transport"], map[string]any{"type": "grpc", "service_name": "mygrpc"}) {
		t.Fatalf("gRPC fields lost: %v", grpc)
	}
	_, reality := outbound(t, "Reality = vless, example.test, 443, username="+testUUID+", flow=xtls-rprx-vision, sni=tls.example.test, reality-public-key=fixture-public-key, reality-short-id=abcd")
	tls, ok := reality["tls"].(map[string]any)
	if !ok || tls["enabled"] != true || tls["server_name"] != "tls.example.test" || reality["flow"] != "xtls-rprx-vision" || !reflect.DeepEqual(tls["reality"], map[string]any{"enabled": true, "public_key": "fixture-public-key", "short_id": "abcd"}) || !reflect.DeepEqual(tls["utls"], map[string]any{"enabled": true, "fingerprint": "chrome"}) {
		t.Fatalf("implicit Reality TLS/uTLS fields lost: %v", reality)
	}
	_, noSNI := outbound(t, "NoSNI = trojan, example.test, 443, password=secret, sni=off")
	tls = noSNI["tls"].(map[string]any)
	if tls["disable_sni"] != true || tls["server_name"] != nil {
		t.Fatalf("sni=off sent a literal SNI hostname: %v", noSNI)
	}
	_, upgrade := outbound(t, "Upgrade = vmess, example.test, 443, username="+testUUID+`, tls=true, ws=true, ws-http-upgrade=true, ws-path="/upgrade?token=a%2Cb&ed=2048&mode=1", ws-headers=Host:cdn.example.test`)
	transport, ok := upgrade["transport"].(map[string]any)
	if !ok || transport["type"] != "httpupgrade" || transport["host"] != "cdn.example.test" {
		t.Fatalf("HTTP upgrade was translated as framed WebSocket: %v", upgrade)
	}
	path, err := url.Parse(text(transport["path"]))
	if err != nil || path.Path != "/upgrade" || path.Query().Has("ed") || path.Query().Get("token") != "a,b" || path.Query().Get("mode") != "1" {
		t.Fatalf("HTTP upgrade early data was retained or another query value changed: path=%v error=%v", transport["path"], err)
	}
}

func TestSurgeHysteria2PortHoppingAndObfuscation(t *testing.T) {
	for _, test := range []struct{ options, interval, obfs string }{
		{", salamander-password=obfs-secret", "30s", "salamander"},
		{", port-hopping-interval=17, gecko-password=obfs-secret", "17s", "gecko"},
	} {
		_, obj := outbound(t, "Hop = hysteria2, example.test, 443, password=secret, port-hopping=1234;5000-6000"+test.options)
		if !reflect.DeepEqual(obj["server_ports"], []any{"1234", "5000:6000"}) || obj["hop_interval"] != test.interval || !reflect.DeepEqual(obj["obfs"], map[string]any{"type": test.obfs, "password": "obfs-secret"}) {
			t.Fatalf("Hysteria2 hopping/obfuscation changed: %v", obj)
		}
	}
}

func TestSurgeUnsupportedEntriesDoNotDiscardValidNodesOrLeakSecrets(t *testing.T) {
	const secret = "DO-NOT-LEAK-SURGE-PASSWORD"
	for _, invalid := range []string{
		"unsupported = snell, example.test, 443, psk=" + secret,
		"chain = trojan, example.test, 443, password=" + secret + ", underlying-proxy=another",
		"pin = trojan, example.test, 443, password=" + secret + ", server-cert-fingerprint-sha256=" + strings.Repeat("a", 64),
		"client = trojan, example.test, 443, password=" + secret + ", client-cert=local-keystore",
		"transport = vless, example.test, 443, username=" + testUUID + ", network=xhttp",
		"grpc-mode = vless, example.test, 443, username=" + testUUID + ", grpc=true, grpc-mode=multi",
		"transport-conflict = vless, example.test, 443, username=" + testUUID + ", grpc=true, ws=true",
		"upgrade-conflict = vless, example.test, 443, username=" + testUUID + ", grpc=true, ws=false, ws-http-upgrade=true",
		"obfs-conflict = hysteria2, example.test, 443, password=" + secret + ", salamander-password=a, gecko-password=b",
		"session-reuse = anytls, example.test, 443, password=" + secret + ", reuse=false",
		"quote = trojan, example.test, 443, password=\"" + secret,
	} {
		t.Run(strings.SplitN(invalid, " =", 2)[0], func(t *testing.T) {
			input := "[Proxy]\nvalid-before = trojan, example.test, 443, password=ok\n" + invalid + "\nvalid-after = anytls, example.test, 443, password=ok\n"
			result, err := Parse([]byte(input))
			if err != nil || len(result.Nodes) != 2 || len(result.Warnings) != 1 || result.Nodes[0].Name != "valid-before" || result.Nodes[1].Name != "valid-after" {
				t.Fatalf("mixed document: nodes=%+v warnings=%v error=%v", result.Nodes, result.Warnings, err)
			}
			if strings.Contains(strings.Join(result.Warnings, " "), secret) {
				t.Fatal("Surge warning exposed credentials")
			}
			result, err = Parse([]byte("[Proxy]\n" + invalid))
			if err == nil || len(result.Nodes) != 0 || len(result.Warnings) == 0 || strings.Contains(err.Error()+strings.Join(result.Warnings, " "), secret) {
				t.Fatalf("unsupported-only document: nodes=%+v warnings=%v error=%v", result.Nodes, result.Warnings, err)
			}
		})
	}
	result, err := Parse([]byte("broken = trojan, example.test, 443, password=\"unterminated\nvalid = trojan, example.test, 443, password=ok\n"))
	if err != nil || len(result.Nodes) != 1 || len(result.Warnings) != 1 || result.Nodes[0].Name != "valid" {
		t.Fatalf("malformed first policy discarded the valid policy: %v, %v", result, err)
	}
}
