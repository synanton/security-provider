package authn

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

// APIKeyAdapter validates constrained legacy API credentials. API keys
// are not the preferred default for internal service identity: each key
// is narrowly scoped, expirable, revocable, and stored as a verifier hash
// only. Never place credentials in source code, URLs, or logs.
type APIKeyAdapter struct {
	id     string
	mu     sync.RWMutex
	keys   map[string]apiKeyRecord
	loaded time.Time
}

type apiKeyRecord struct {
	ID        string    `yaml:"id"`
	Verifier  string    `yaml:"verifier"`
	Principal string    `yaml:"principal"`
	Type      string    `yaml:"principal_type"`
	Tenant    string    `yaml:"tenant_id"`
	Scopes    []string  `yaml:"scopes"`
	ExpiresAt time.Time `yaml:"expires_at"`
	Revoked   bool      `yaml:"revoked"`
}

type apiKeyFile struct {
	Keys []apiKeyRecord `yaml:"keys"`
}

// NewAPIKeyAdapter loads verifiers from the configured credential file.
func NewAPIKeyAdapter(cfg config.ProviderConfig) (*APIKeyAdapter, error) {
	if cfg.CredentialFile == "" {
		return nil, fmt.Errorf("apikey %q: credential_file must be set", cfg.ID)
	}
	raw, err := os.ReadFile(cfg.CredentialFile)
	if err != nil {
		return nil, fmt.Errorf("apikey %q: read credential file: %w", cfg.ID, err)
	}
	var file apiKeyFile
	if err := yaml.Unmarshal(raw, &file); err != nil {
		return nil, fmt.Errorf("apikey %q: parse credential file: %w", cfg.ID, err)
	}
	a := &APIKeyAdapter{id: cfg.ID, keys: map[string]apiKeyRecord{}, loaded: now()}
	for _, k := range file.Keys {
		if k.ID == "" || k.Verifier == "" {
			return nil, fmt.Errorf("apikey %q: credential entries require id and verifier", cfg.ID)
		}
		if _, dup := a.keys[k.ID]; dup {
			return nil, fmt.Errorf("apikey %q: duplicate credential id %q", cfg.ID, k.ID)
		}
		a.keys[k.ID] = k
	}
	return a, nil
}

// ID implements port.AuthenticationProvider.
func (a *APIKeyAdapter) ID() string { return a.id }

// Authenticate implements port.AuthenticationProvider. The presented
// credential has the form "<key-id>:<secret>"; only the SHA-256 verifier
// is stored, compared in constant time.
func (a *APIKeyAdapter) Authenticate(ctx context.Context, evidence port.Evidence) (domain.AuthenticationResult, error) {
	tok, ok := evidence.(port.TokenEvidence)
	if !ok || tok.EvidenceKind != domain.EvidenceAPICredential {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: apikey provider requires API credential evidence", domain.ErrInvalidCredential)
	}
	id, secret, found := strings.Cut(tok.Token, ":")
	if !found || id == "" || secret == "" {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: malformed credential", domain.ErrInvalidCredential)
	}
	a.mu.RLock()
	rec, known := a.keys[id]
	a.mu.RUnlock()
	if !known {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: unknown credential", domain.ErrInvalidCredential)
	}
	sum := sha256.Sum256([]byte(secret))
	presented := hex.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(presented), []byte(strings.ToLower(rec.Verifier))) != 1 {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: credential mismatch", domain.ErrInvalidCredential)
	}
	if rec.Revoked {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: credential revoked", domain.ErrRevokedCredential)
	}
	if !rec.ExpiresAt.IsZero() && !now().Before(rec.ExpiresAt) {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: credential expired", domain.ErrCredentialExpired)
	}
	pt := domain.PrincipalType(strings.ToUpper(rec.Type))
	if !pt.Valid() {
		pt = domain.PrincipalConnector
	}
	return domain.AuthenticationResult{
		ProviderID:      a.id,
		ExternalIssuer:  a.id,
		ExternalSubject: rec.Principal,
		PrincipalType:   pt,
		Assurance:       domain.AssuranceLow,
		Method:          domain.MethodAPIKey,
		AuthenticatedAt: now(),
		ExpiresAt:       ptrTime(expiryOf(rec.ExpiresAt)),
		CredentialID:    "apikey:" + id,
		EvidenceKind:    domain.EvidenceAPICredential,
	}, nil
}

// Health implements port.AuthenticationProvider.
func (a *APIKeyAdapter) Health(_ context.Context) port.ProviderHealth {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return port.ProviderHealth{
		ProviderID: a.id,
		Healthy:    true,
		Detail:     fmt.Sprintf("%d verifiers loaded", len(a.keys)),
		CheckedAt:  now(),
		KeyAge:     now().Sub(a.loaded),
	}
}

func expiryOf(t time.Time) time.Time {
	if t.IsZero() {
		return now().Add(15 * time.Minute)
	}
	return t
}
