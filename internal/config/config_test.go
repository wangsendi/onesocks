package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadText(t *testing.T, data string) (Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestDefaultAndOverrides(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.SOCKSListen != "127.0.0.1:1080" || c.APIListen != "127.0.0.1:8080" || c.DataDir != "data" || c.ProbeConcurrency != 16 {
		t.Fatalf("defaults: %#v", c)
	}
	c, err = loadText(t, "api_listen: '[::1]:8081'\ndata_dir: custom\noutbound_interface: eth0\nprobe_concurrency: 3\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.APIListen != "[::1]:8081" || c.SOCKSListen != "127.0.0.1:1080" || c.DataDir != "custom" || c.OutboundInterface != "eth0" || c.ProbeConcurrency != 3 {
		t.Fatalf("overrides: %#v", c)
	}
	c, err = loadText(t, "unknown_field: true\nsocks_listen: 'localhost:http'\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.SOCKSListen != "localhost:http" {
		t.Fatalf("explicit settings were restricted: %#v", c)
	}
	if c, err := loadText(t, ""); err != nil || c != Default() {
		t.Fatalf("empty file should use defaults: %#v, %v", c, err)
	}
}

func TestInvalidConfig(t *testing.T) {
	for _, text := range []string{
		"api_listen: [\n", "data_dir: ''\n", "socks_listen: 'missing-port'\n",
		"probe_concurrency: 0\n", "probe_concurrency: -1\n", "probe_concurrency: 1.5\n",
		"api_listen: '127.0.0.1:8080'\n---\napi_token: secret\n",
		"socks_listen: '127.0.0.1:1080'\nsocks_listen: '127.0.0.1:1081'\n",
	} {
		if _, err := loadText(t, text); err == nil {
			t.Errorf("accepted invalid config %q", text)
		}
	}
}

func TestNetworkListeners(t *testing.T) {
	for _, address := range []string{"0.0.0.0:1080", "proxy.example:1080", ":1080"} {
		for _, secret := range []string{"", "secret"} {
			c, err := loadText(t, "socks_listen: '"+address+"'\nsocks_password: '"+secret+"'\napi_listen: '[::]:8080'\napi_token: '"+secret+"'\n")
			if err != nil {
				t.Fatal(err)
			}
			if c.APIToken != secret || c.SOCKSPassword != secret || c.SOCKSListen != address {
				t.Fatal("network listener settings not loaded")
			}
		}
	}
}

func TestExampleConfig(t *testing.T) {
	if _, err := Load("../../configs/config.example.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestSOCKSPasswordByteLimit(t *testing.T) {
	c := Default()
	c.SOCKSPassword = strings.Repeat("x", 255)
	if err := c.Validate(); err != nil {
		t.Fatalf("255-byte password: %v", err)
	}
	c.SOCKSPassword = strings.Repeat("密", 86)
	if err := c.Validate(); err == nil {
		t.Fatal("accepted password longer than 255 UTF-8 bytes")
	}
}
