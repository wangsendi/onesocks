package parser

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"onesocks/internal/domain"
	"onesocks/internal/engine"
	"onesocks/internal/engine/singbox"
)

func TestV2RayProtocolsAndTransportsBuild(t *testing.T) {
	for _, tc := range []struct {
		name, protocol, settings, stream, expected string
	}{
		{
			"VMess WebSocket TLS", "vmess",
			`{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"` + testUUID + `","alterId":0,"security":"aes-128-gcm","level":0,"email":"display-only"}]}]}`,
			`{"network":"ws","security":"tls","tlsSettings":{"serverName":"tls.example.com","allowInsecure":true,"alpn":["http/1.1"],"minVersion":"1.2"},"wsSettings":{"path":"/ws?token=abc&ed=2048","headers":{"Host":"cdn.example.com","X-Test":"fixture"}}}`,
			`{"uuid":"` + testUUID + `","security":"aes-128-gcm","alter_id":0,"tls":{"enabled":true,"server_name":"tls.example.com","insecure":true,"alpn":["http/1.1"],"min_version":"1.2"},"transport":{"type":"ws","path":"/ws?token=abc","headers":{"Host":"cdn.example.com","X-Test":"fixture"},"max_early_data":2048,"early_data_header_name":"Sec-WebSocket-Protocol"}}`,
		},
		{
			"VLESS gRPC TLS", "vless",
			`{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":"` + testUUID + `","encryption":"none"}]}]}`,
			`{"network":"grpc","security":"tls","tlsSettings":{"serverName":"tls.example.com"},"grpcSettings":{"serviceName":"proxy-service","multiMode":false,"idle_timeout":30,"health_check_timeout":10,"permit_without_stream":true}}`,
			`{"uuid":"` + testUUID + `","tls":{"enabled":true,"server_name":"tls.example.com","insecure":false},"transport":{"type":"grpc","service_name":"proxy-service","idle_timeout":"30s","ping_timeout":"10s","permit_without_stream":true}}`,
		},
		{
			"Trojan TCP TLS", "trojan",
			`{"servers":[{"address":"127.0.0.1","port":443,"password":"fixture-secret","level":0}]}`,
			`{"network":"tcp","security":"tls","tcpSettings":{"header":{"type":"none"}},"tlsSettings":{"serverName":"tls.example.com","alpn":["h2","http/1.1"]}}`,
			`{"password":"fixture-secret","tls":{"enabled":true,"server_name":"tls.example.com","insecure":false,"alpn":["h2","http/1.1"]}}`,
		},
		{
			"Shadowsocks", "shadowsocks",
			`{"servers":[{"address":"127.0.0.1","port":443,"method":"aes-128-gcm","password":"fixture-secret","ota":false,"ivCheck":false}]}`,
			`{"network":"tcp","security":"none","sockopt":{}}`,
			`{"method":"aes-128-gcm","password":"fixture-secret"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := fmt.Sprintf(`{"tag":"节点","protocol":%q,"settings":%s,"streamSettings":%s,"mux":{"enabled":false,"concurrency":8}}`, tc.protocol, tc.settings, tc.stream)
			name, got := outbound(t, input)
			var want map[string]any
			if err := json.Unmarshal([]byte(tc.expected), &want); err != nil {
				t.Fatal(err)
			}
			want["type"], want["server"], want["server_port"] = tc.protocol, "127.0.0.1", float64(443)
			if name != "节点" || !reflect.DeepEqual(got, want) {
				t.Fatalf("got %v; want %v", got, want)
			}
			raw, _ := json.Marshal(got)
			assertV2RayBuilds(t, []domain.NodeSpec{{Name: name, Outbound: raw}})
		})
	}
}

func TestV2RayDocumentShapesAndMultipleConfigurations(t *testing.T) {
	const node = `{"tag":"proxy","protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"fixture-secret"}]}}`
	for name, input := range map[string]string{
		"single":    node,
		"outbounds": `{"inbounds":[],"dns":{"servers":["1.1.1.1"]},"routing":{"rules":[]},"outbounds":[` + node + `]}`,
		"array":     "[" + node + "]",
		"base64":    base64.RawURLEncoding.EncodeToString([]byte(`{"outbounds":[` + node + `]}`)),
	} {
		t.Run(name, func(t *testing.T) {
			name, obj := outbound(t, input)
			if name != "proxy" || obj["password"] != "fixture-secret" {
				t.Fatal("V2Ray outbound was not retained")
			}
		})
	}
	input := `[{"remarks":"香港","outbounds":[` + node + `]},{"outbounds":[` + node + `]}]`
	result, err := Parse([]byte(input))
	if err != nil || len(result.Nodes) != 2 || len(result.Warnings) != 0 {
		t.Fatalf("nodes=%d warnings=%v error=%v", len(result.Nodes), result.Warnings, err)
	}
	if result.Nodes[0].Name != "香港-proxy" || result.Nodes[1].Name != "config-2-proxy" {
		t.Fatalf("configuration names were lost: %v", result.Nodes)
	}
}

func TestV2RayMultipleServersAndUsersRemainDistinct(t *testing.T) {
	input := `{"protocol":"vmess","tag":"pool","settings":{"vnext":[
		{"address":"127.0.0.1","port":443,"users":[{"id":"` + testUUID + `","security":"auto"},{"id":"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee","security":"aes-128-gcm"}]},
		{"address":"127.0.0.2","port":8443,"users":[{"id":"` + testUUID + `","security":"chacha20-poly1305"}]}
	]}}`
	result, err := Parse([]byte(input))
	if err != nil || len(result.Nodes) != 3 || len(result.Warnings) != 0 {
		t.Fatalf("nodes=%d warnings=%v error=%v", len(result.Nodes), result.Warnings, err)
	}
	for i, want := range []struct{ name, address, security string }{
		{"pool-1-1", "127.0.0.1", "auto"},
		{"pool-1-2", "127.0.0.1", "aes-128-gcm"},
		{"pool-2-1", "127.0.0.2", "chacha20-poly1305"},
	} {
		var obj map[string]any
		if err := json.Unmarshal(result.Nodes[i].Outbound, &obj); err != nil {
			t.Fatal(err)
		}
		if result.Nodes[i].Name != want.name || obj["server"] != want.address || obj["security"] != want.security {
			t.Fatalf("server/user alternative lost: %v", result.Nodes[i])
		}
	}
	assertV2RayBuilds(t, result.Nodes)
}

func TestV2RayUnsupportedEntriesKeepValidNodesAndSafeWarnings(t *testing.T) {
	const good = `{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"good"}]}}`
	for _, bad := range []string{
		`{"protocol":"freedom","settings":{}}`,
		`{"protocol":"vless","settings":{"vnext":[]},"proxySettings":{"tag":"DO-NOT-LEAK"}}`,
		`{"protocol":"vmess","settings":{"vnext":[]},"mux":{"enabled":true}}`,
		`{"protocol":"trojan","settings":{"servers":[]},"streamSettings":{"network":"xhttp","security":"tls"}}`,
		`{"protocol":"trojan","settings":{"servers":[]},"streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http"}}}}`,
		`{"protocol":"trojan","settings":{"servers":[]},"streamSettings":{"security":"tls","tlsSettings":{"certificates":[{"certificateFile":"/DO-NOT-LEAK"}]}}}`,
		`{"protocol":"vless","settings":{"vnext":[]},"streamSettings":{"network":"grpc","grpcSettings":{"multiMode":true}}}`,
		`{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":"DO-NOT-LEAK","password":"DO-NOT-LEAK"}]}}`,
	} {
		result, err := Parse([]byte("[" + bad + "," + good + "]"))
		if err != nil || len(result.Nodes) != 1 || len(result.Warnings) == 0 {
			t.Fatalf("nodes=%d warnings=%v error=%v", len(result.Nodes), result.Warnings, err)
		}
		if strings.Contains(strings.Join(result.Warnings, ""), "DO-NOT-LEAK") {
			t.Fatal("V2Ray diagnostic exposed credentials or source fields")
		}
	}
	// Unsupported users and malformed servers do not discard siblings in the same outbound.
	input := `{"tag":"partial","protocol":"vless","settings":{"vnext":[
		{"address":"127.0.0.1","port":443,"users":[{"id":"` + testUUID + `","encryption":"DO-NOT-LEAK"},{"id":"` + testUUID + `","encryption":"none"}]},
		{"address":"127.0.0.2","port":0,"users":[{"id":"` + testUUID + `"}]}
	]}}`
	result, err := Parse([]byte(input))
	if err != nil || len(result.Nodes) != 1 || len(result.Warnings) != 2 {
		t.Fatalf("nodes=%d warnings=%v error=%v", len(result.Nodes), result.Warnings, err)
	}
	if strings.Contains(strings.Join(result.Warnings, ""), "DO-NOT-LEAK") {
		t.Fatal("unsupported encryption value leaked")
	}
	if result.Nodes[0].Name != "partial-1-2" {
		t.Fatalf("filtered user changed the remaining source index: %q", result.Nodes[0].Name)
	}
}

func TestV2RayReality(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
	input := fmt.Sprintf(`{"tag":"Reality","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,"users":[{"id":%q,"encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.com","fingerprint":"chrome","publicKey":%q,"shortId":"abcd","spiderX":"/"}}}`, testUUID, publicKey)
	_, obj := outbound(t, input)
	tls := obj["tls"].(map[string]any)
	reality := tls["reality"].(map[string]any)
	if reality["public_key"] != publicKey || reality["short_id"] != "abcd" || tls["server_name"] != "example.com" || obj["flow"] != "xtls-rprx-vision" {
		t.Fatal("V2Ray Reality parameters were lost")
	}
	result, err := Parse([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	client, err := singbox.New(context.Background(), []engine.Node{{ID: "reality", Outbound: result.Nodes[0].Outbound}})
	if err != nil {
		if strings.Contains(err.Error(), "uTLS") && strings.Contains(err.Error(), "not included in this build") {
			t.Skip("Reality runtime construction requires with_utls build tag")
		}
		t.Fatalf("sing-box rejected translated V2Ray Reality: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertV2RayBuilds(t *testing.T, specs []domain.NodeSpec) {
	t.Helper()
	var nodes []engine.Node
	for i, spec := range specs {
		nodes = append(nodes, engine.Node{ID: fmt.Sprintf("v2ray-%d", i), Outbound: spec.Outbound})
	}
	client, err := singbox.New(context.Background(), nodes)
	if err != nil {
		t.Fatalf("sing-box rejected translated V2Ray node: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}
