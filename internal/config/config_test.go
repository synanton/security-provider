package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultsValidate(t *testing.T) {
	if err := Defaults().Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
}

func TestLoadYAMLAndEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := `
server:
  http_addr: ":8081"
  grpc_addr: ":9091"
  context_ttl: 2m
identity:
  endpoint: "https://identity.test:8443"
  mode: stub
  timeout: 2s
  cache_ttl: 30s
providers:
  - id: dev-ca
    type: mtls
    trust_bundle: /tmp/ca.pem
    allowed_san_patterns: ["spiffe://synanton/*"]
    enabled: true
`
	if err := os.WriteFile(path, []byte(yaml), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SECURITY_PROVIDER_HTTP_ADDR", ":8082")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.HTTPAddr != ":8082" {
		t.Fatalf("env override lost: %q", cfg.Server.HTTPAddr)
	}
	if cfg.Server.GRPCAddr != ":9091" || len(cfg.Providers) != 1 {
		t.Fatalf("yaml not applied: %+v", cfg.Server)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"empty http addr", func(c *Config) { c.Server.HTTPAddr = "" }},
		{"context ttl too long", func(c *Config) { c.Server.ContextTTL = time.Hour }},
		{"cache ttl past SLO", func(c *Config) { c.Identity.CacheTTL = time.Hour }},
		{"bad identity mode", func(c *Config) { c.Identity.Mode = "ldap" }},
		{"unknown provider type", func(c *Config) {
			c.Providers = []ProviderConfig{{ID: "x", Type: "saml", Enabled: true}}
		}},
		{"oidc without issuer", func(c *Config) {
			c.Providers = []ProviderConfig{{ID: "o", Type: "oidc", Audiences: []string{"a"}, AllowedAlgorithms: []string{"RS256"}, Enabled: true}}
		}},
		{"oidc without audience", func(c *Config) {
			c.Providers = []ProviderConfig{{ID: "o", Type: "oidc", Issuer: "https://idp", AllowedAlgorithms: []string{"RS256"}, Enabled: true}}
		}},
		{"duplicate provider id", func(c *Config) {
			c.Providers = []ProviderConfig{
				{ID: "d", Type: "workload", TrustDomain: "x", Enabled: true},
				{ID: "d", Type: "workload", TrustDomain: "x", Enabled: true},
			}
		}},
		{"stub fixtures with http mode", func(c *Config) {
			c.Identity.Mode = "http"
			c.Identity.StubMappings = []StubMapping{{Issuer: "x", Subject: "y"}}
		}},
	}
	for _, tc := range cases {
		cfg := Defaults()
		tc.mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: invalid config accepted", tc.name)
		}
	}
}
