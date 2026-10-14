// Package config loads Security Provider configuration from a YAML file
// with SECURITY_PROVIDER_* environment overrides. Validation fails fast
// with the cause before any listener binds.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full service configuration.
type Config struct {
	Server           ServerConfig     `yaml:"server"`
	Identity         IdentityConfig   `yaml:"identity"`
	Providers        []ProviderConfig `yaml:"providers"`
	LocalVerification LocalVerifyConfig `yaml:"local_verification"`
	Revocation       RevocationConfig `yaml:"revocation"`
	Audit            AuditConfig      `yaml:"audit"`
	LogLevel         string           `yaml:"log_level"`
}

// ServerConfig controls HTTP/gRPC listeners and TLS.
type ServerConfig struct {
	HTTPAddr       string        `yaml:"http_addr"`
	GRPCAddr       string        `yaml:"grpc_addr"`
	TLS            TLSConfig     `yaml:"tls"`
	AdminToken     string        `yaml:"admin_token"`
	ContextTTL     time.Duration `yaml:"context_ttl"`
	SigningKey     string        `yaml:"signing_key"`
	SigningKeyFile string        `yaml:"signing_key_file"`
}

// TLSConfig mirrors the proposal §configuration shape.
type TLSConfig struct {
	CertFile          string `yaml:"cert_file"`
	KeyFile           string `yaml:"key_file"`
	ClientCA          string `yaml:"client_ca"`
	RequireClientCert bool   `yaml:"require_client_cert"`
}

// IdentityConfig controls the Identity 1.29 resolution client.
type IdentityConfig struct {
	Endpoint     string            `yaml:"endpoint"`
	Mode         string            `yaml:"mode"`
	Timeout      time.Duration     `yaml:"timeout"`
	CacheTTL     time.Duration     `yaml:"cache_ttl"`
	StubMappings []StubMapping     `yaml:"stub_mappings"`
}

// StubMapping is a dev/test fixture for identity.mode stub. Production
// must use mode http; stub_mappings in production config are rejected.
type StubMapping struct {
	Issuer        string `yaml:"issuer"`
	Subject       string `yaml:"subject"`
	PrincipalID   string `yaml:"principal_id"`
	PrincipalType string `yaml:"principal_type"`
	TenantID      string `yaml:"tenant_id"`
}

// ProviderType selects the adapter: mtls, oidc, workload, apikey.
type ProviderConfig struct {
	ID                 string   `yaml:"id"`
	Type               string   `yaml:"type"`
	Issuer             string   `yaml:"issuer"`
	Audiences          []string `yaml:"audiences"`
	JWKSURI            string   `yaml:"jwks_uri"`
	JWKSCacheTTL       time.Duration `yaml:"jwks_cache_ttl"`
	AllowedAlgorithms  []string `yaml:"allowed_algorithms"`
	TrustBundle        string   `yaml:"trust_bundle"`
	AllowedSANPatterns []string `yaml:"allowed_san_patterns"`
	TrustDomain        string   `yaml:"trust_domain"`
	RequiredScopes     []string `yaml:"required_scopes"`
	CredentialFile     string   `yaml:"credential_file"`
	Enabled            bool     `yaml:"enabled"`
}

// LocalVerifyConfig is the §9.1 local-verification policy as configuration
// (owned semantically by Security 1.23, consumed here).
type LocalVerifyConfig struct {
	Enabled                 bool          `yaml:"enabled"`
	TTLHighRisk             time.Duration `yaml:"ttl_high_risk"`
	TTLStandard             time.Duration `yaml:"ttl_standard"`
	CentralizedOnlyPatterns []string      `yaml:"centralized_only_operations"`
}

// RevocationConfig holds the provisional §11.2 revocation SLO targets.
type RevocationConfig struct {
	SLOCentralized      time.Duration `yaml:"slo_centralized"`
	SLOLocalHighRisk    time.Duration `yaml:"slo_local_high_risk"`
	SLOLocalStandard    time.Duration `yaml:"slo_local_standard"`
	SLOMTLS             time.Duration `yaml:"slo_mtls"`
}

// AuditConfig controls audit event emission.
type AuditConfig struct {
	Sink              string `yaml:"sink"`
	RedactCredentials bool   `yaml:"redact_credentials"`
}

// Defaults mirrors the proposal §configuration example.
func Defaults() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPAddr:    ":8080",
			GRPCAddr:    ":9090",
			ContextTTL:  5 * time.Minute,
		},
		Identity: IdentityConfig{
			Endpoint: "https://identity.internal:8443",
			Mode:     "stub",
			Timeout:  2 * time.Second,
			CacheTTL: 30 * time.Second,
		},
		LocalVerification: LocalVerifyConfig{
			Enabled:                 true,
			TTLHighRisk:             5 * time.Minute,
			TTLStandard:             15 * time.Minute,
			CentralizedOnlyPatterns: []string{"admin.*", "tenant.*", "delegation.activate", "delegation.extend"},
		},
		Revocation: RevocationConfig{
			SLOCentralized:   60 * time.Second,
			SLOLocalHighRisk: 5 * time.Minute,
			SLOLocalStandard: 15 * time.Minute,
			SLOMTLS:          15 * time.Minute,
		},
		Audit:    AuditConfig{Sink: "stdout", RedactCredentials: true},
		LogLevel: "info",
	}
}

// Load reads path (when non-empty) then applies SECURITY_PROVIDER_*
// overrides, then validates.
func Load(path string) (*Config, error) {
	cfg := Defaults()
	if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config %q: %w", path, err)
		}
		dec := yaml.NewDecoder(strings.NewReader(string(raw)))
		dec.KnownFields(true)
		if err := dec.Decode(cfg); err != nil {
			return nil, fmt.Errorf("parse config %q: %w", path, err)
		}
	}
	applyEnv(cfg)
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func applyEnv(cfg *Config) {
	if v := os.Getenv("SECURITY_PROVIDER_HTTP_ADDR"); v != "" {
		cfg.Server.HTTPAddr = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_GRPC_ADDR"); v != "" {
		cfg.Server.GRPCAddr = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_TLS_CERT"); v != "" {
		cfg.Server.TLS.CertFile = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_TLS_KEY"); v != "" {
		cfg.Server.TLS.KeyFile = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_CLIENT_CA"); v != "" {
		cfg.Server.TLS.ClientCA = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_ADMIN_TOKEN"); v != "" {
		cfg.Server.AdminToken = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_SIGNING_KEY"); v != "" {
		cfg.Server.SigningKey = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_IDENTITY_ENDPOINT"); v != "" {
		cfg.Identity.Endpoint = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_IDENTITY_MODE"); v != "" {
		cfg.Identity.Mode = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_LOCAL_VERIFICATION_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.LocalVerification.Enabled = b
		}
	}
	if v := os.Getenv("SECURITY_PROVIDER_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("SECURITY_PROVIDER_AUDIT_SINK"); v != "" {
		cfg.Audit.Sink = v
	}
}

// Validate rejects unsafe or incoherent configuration before serving.
func (c *Config) Validate() error {
	if c.Server.HTTPAddr == "" {
		return fmt.Errorf("server.http_addr must be set")
	}
	if c.Server.ContextTTL <= 0 {
		return fmt.Errorf("server.context_ttl must be positive")
	}
	if c.Server.ContextTTL > 15*time.Minute {
		return fmt.Errorf("server.context_ttl must not exceed 15m (short-lived assertions only)")
	}
	if c.Identity.Timeout <= 0 {
		return fmt.Errorf("identity.timeout must be positive")
	}
	if c.Identity.CacheTTL <= 0 {
		return fmt.Errorf("identity.cache_ttl must be positive")
	}
	if c.Identity.CacheTTL > c.Revocation.SLOLocalStandard && c.Revocation.SLOLocalStandard > 0 {
		return fmt.Errorf("identity.cache_ttl (%v) must not exceed slo_local_standard (%v)", c.Identity.CacheTTL, c.Revocation.SLOLocalStandard)
	}
	switch c.Identity.Mode {
	case "stub", "http":
	default:
		return fmt.Errorf("identity.mode must be stub or http")
	}
	if c.Identity.Mode == "http" && len(c.Identity.StubMappings) > 0 {
		return fmt.Errorf("identity.stub_mappings are dev fixtures and must not accompany mode http")
	}
	if c.LocalVerification.TTLHighRisk <= 0 || c.LocalVerification.TTLStandard <= 0 {
		return fmt.Errorf("local_verification TTLs must be positive")
	}
	if c.LocalVerification.TTLHighRisk > c.Revocation.SLOLocalHighRisk && c.Revocation.SLOLocalHighRisk > 0 {
		return fmt.Errorf("local_verification.ttl_high_risk must not exceed slo_local_high_risk")
	}
	if c.LocalVerification.TTLStandard > c.Revocation.SLOLocalStandard && c.Revocation.SLOLocalStandard > 0 {
		return fmt.Errorf("local_verification.ttl_standard must not exceed slo_local_standard")
	}
	seen := map[string]struct{}{}
	for i, p := range c.Providers {
		if p.ID == "" {
			return fmt.Errorf("providers[%d]: id must be set", i)
		}
		if _, dup := seen[p.ID]; dup {
			return fmt.Errorf("providers[%d]: duplicate id %q", i, p.ID)
		}
		seen[p.ID] = struct{}{}
		switch p.Type {
		case "mtls", "oidc", "workload", "apikey":
		default:
			return fmt.Errorf("providers[%d] (%q): unknown type %q", i, p.ID, p.Type)
		}
		if p.Type == "oidc" {
			if p.Issuer == "" {
				return fmt.Errorf("providers[%d] (%q): issuer must be set", i, p.ID)
			}
			if len(p.Audiences) == 0 {
				return fmt.Errorf("providers[%d] (%q): at least one audience is required", i, p.ID)
			}
			if len(p.AllowedAlgorithms) == 0 {
				return fmt.Errorf("providers[%d] (%q): allowed_algorithms must be non-empty (never accept alg=none)", i, p.ID)
			}
		}
		if p.Type == "mtls" && p.TrustBundle == "" {
			return fmt.Errorf("providers[%d] (%q): trust_bundle must be set", i, p.ID)
		}
	}
	return nil
}
