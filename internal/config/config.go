// Package config loads the static service settings. Subscriptions are managed
// through the API and persisted separately in SQLite.
package config

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

const DefaultProbeConcurrency = 16

type Config struct {
	SOCKSListen       string `yaml:"socks_listen" json:"socks_listen"`
	APIListen         string `yaml:"api_listen" json:"api_listen"`
	DataDir           string `yaml:"data_dir" json:"data_dir"`
	SOCKSPassword     string `yaml:"socks_password" json:"socks_password"`
	APIToken          string `yaml:"api_token" json:"api_token"`
	OutboundInterface string `yaml:"outbound_interface" json:"outbound_interface"`
	ProbeConcurrency  int    `yaml:"probe_concurrency" json:"probe_concurrency"`
}

func Default() Config {
	return Config{
		SOCKSListen: "127.0.0.1:1080", APIListen: "127.0.0.1:8080", DataDir: "data",
		ProbeConcurrency: DefaultProbeConcurrency,
	}
}

func (c *Config) UnmarshalYAML(node *yaml.Node) error {
	type values Config
	if err := node.Decode((*values)(c)); err != nil {
		return err
	}
	// yaml.v3 truncates floating-point scalars when decoding into an int.
	// Check the original scalar type so concurrency is never silently rounded.
	var raw struct {
		ProbeConcurrency any `yaml:"probe_concurrency"`
	}
	if err := node.Decode(&raw); err != nil {
		return err
	}
	if raw.ProbeConcurrency != nil {
		if _, ok := raw.ProbeConcurrency.(int); !ok {
			return fmt.Errorf("probe_concurrency must be an integer")
		}
	}
	return nil
}

func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, c.Validate()
	}
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	dec := yaml.NewDecoder(f)
	if err := dec.Decode(&c); err != nil && err != io.EOF {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return Config{}, fmt.Errorf("config must contain exactly one YAML document")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.ProbeConcurrency <= 0 {
		return fmt.Errorf("probe_concurrency must be positive")
	}
	if len(c.SOCKSPassword) > 255 {
		return fmt.Errorf("socks_password must be at most 255 bytes")
	}
	if strings.TrimSpace(c.DataDir) == "" {
		return fmt.Errorf("data_dir must not be empty")
	}
	for _, item := range []struct{ name, address string }{
		{"socks_listen", c.SOCKSListen}, {"api_listen", c.APIListen},
	} {
		if _, _, err := net.SplitHostPort(item.address); err != nil {
			return fmt.Errorf("%s must include a host and port: %w", item.name, err)
		}
	}
	return nil
}
