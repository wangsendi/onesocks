//go:build with_utls

package singbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/url"
	"testing"

	"onesocks/internal/engine"
	"onesocks/internal/parser"
)

func TestParsedRealityConfigurationBuilds(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	params := url.Values{
		"security": []string{"reality"}, "sni": []string{"example.com"}, "fp": []string{"chrome"},
		"flow": []string{"xtls-rprx-vision"}, "pbk": []string{base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())}, "sid": []string{"abcd"},
	}
	inputs := map[string]string{
		"URI":   "vless://" + integrationUUID + "@127.0.0.1:443?" + params.Encode() + "#Reality",
		"Clash": fmt.Sprintf("proxies:\n- {type: vless, server: 127.0.0.1, port: 443, uuid: %s, tls: true, servername: example.com, flow: xtls-rprx-vision, reality-opts: {public-key: %s, short-id: abcd}}", integrationUUID, params.Get("pbk")),
	}
	for name, input := range inputs {
		t.Run(name, func(t *testing.T) {
			parsed, err := parser.Parse([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			client, err := New(context.Background(), []engine.Node{{ID: "reality", Outbound: parsed.Nodes[0].Outbound}})
			if err != nil {
				t.Fatalf("parser Reality output rejected by actual sing-box configuration: %v", err)
			}
			if err := client.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
