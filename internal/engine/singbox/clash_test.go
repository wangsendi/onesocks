package singbox

import (
	"context"
	"testing"

	"gopkg.in/yaml.v3"
	"onesocks/internal/engine"
	"onesocks/internal/parser"
)

func TestRealClashProtocolsAndTransports(t *testing.T) {
	certificate, key := selfSigned(t)
	for _, typ := range []string{"shadowsocks", "vless", "vmess", "trojan", "hysteria2", "anytls"} {
		transports := []string{"tcp"}
		if typ == "vless" || typ == "vmess" || typ == "trojan" {
			transports = append(transports, "ws", "ws-early-data", "httpupgrade", "grpc")
		}
		for _, transport := range transports {
			t.Run(typ+"/"+transport, func(t *testing.T) {
				port := freePort(t, typ == "hysteria2")
				inbound := map[string]any{"type": typ, "tag": "proxy", "listen": "127.0.0.1", "listen_port": port}
				proxy := map[string]any{"name": "Clash fixture", "type": typ, "server": "127.0.0.1", "port": port, "udp": true}
				switch typ {
				case "shadowsocks":
					inbound["method"], inbound["password"] = "aes-128-gcm", "clash-secret"
					proxy["type"], proxy["cipher"], proxy["password"] = "ss", "aes-128-gcm", "clash-secret"
				case "vless", "vmess":
					inbound["users"] = []any{map[string]any{"uuid": integrationUUID}}
					proxy["uuid"] = integrationUUID
				default:
					inbound["users"] = []any{map[string]any{"password": "clash-secret"}}
					inbound["tls"] = map[string]any{"enabled": true, "certificate": []string{certificate}, "key": []string{key}}
					proxy["password"], proxy["sni"], proxy["skip-cert-verify"] = "clash-secret", "localhost", true
					if typ == "hysteria2" {
						inbound["obfs"] = map[string]any{"type": "salamander", "password": "clash-obfs"}
						proxy["obfs"], proxy["obfs-password"] = "salamander", "clash-obfs"
					}
				}
				if transport != "tcp" {
					proxy["network"] = transport
					if transport != "grpc" {
						proxy["network"] = "ws"
						inbound["transport"] = map[string]any{"type": "ws", "path": "/clash"}
						proxy["ws-opts"] = map[string]any{"path": "/clash", "headers": map[string]string{"Host": "localhost"}}
						if transport == "ws-early-data" {
							inbound["transport"].(map[string]any)["max_early_data"] = 2048
							inbound["transport"].(map[string]any)["early_data_header_name"] = "Sec-WebSocket-Protocol"
							proxy["ws-opts"].(map[string]any)["path"] = "/clash?ed=2048"
						} else if transport == "httpupgrade" {
							inbound["transport"] = map[string]any{"type": "httpupgrade", "path": "/clash", "host": "localhost"}
							proxy["ws-opts"].(map[string]any)["v2ray-http-upgrade"] = true
						}
					} else {
						inbound["transport"] = map[string]any{"type": "grpc", "service_name": "clash-service"}
						proxy["grpc-opts"] = map[string]any{"grpc-service-name": "clash-service"}
					}
				}
				startProxy(t, inbound)
				raw, err := yaml.Marshal(map[string]any{"proxies": []any{proxy}})
				if err != nil {
					t.Fatal(err)
				}
				parsed, err := parser.Parse(raw)
				if err != nil || len(parsed.Nodes) != 1 || len(parsed.Warnings) != 0 {
					t.Fatalf("Clash parse: %v; warnings=%v", err, parsed.Warnings)
				}
				client, err := New(context.Background(), []engine.Node{{ID: "clash", Outbound: parsed.Nodes[0].Outbound}})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = client.Close() })
				target, _ := echoTarget(t, "tcp", "127.0.0.1:0", "")
				assertEcho(t, client, "clash", target)
				assertUDPEcho(t, client, "clash", udpEchoTarget(t, "127.0.0.1:0"))
			})
		}
	}
}
