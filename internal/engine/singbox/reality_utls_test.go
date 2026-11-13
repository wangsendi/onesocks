//go:build with_utls

package singbox

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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
	parsed, err := parser.Parse([]byte("vless://" + integrationUUID + "@127.0.0.1:443?" + params.Encode() + "#Reality"))
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
}
