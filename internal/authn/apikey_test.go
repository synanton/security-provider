package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

func verifierOf(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func apikeyAdapter(t *testing.T, keysYAML string) *APIKeyAdapter {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys.yaml")
	if err := os.WriteFile(path, []byte(keysYAML), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := NewAPIKeyAdapter(config.ProviderConfig{ID: "test-apikey", Type: "apikey", CredentialFile: path})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestAPIKeyValid(t *testing.T) {
	a := apikeyAdapter(t, fixtureYAML())
	res, err := a.Authenticate(context.Background(), port.TokenEvidence{
		EvidenceKind: domain.EvidenceAPICredential, Token: "legacy-1:s3cret-legacy",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.PrincipalType != domain.PrincipalConnector {
		t.Fatalf("type = %v", res.PrincipalType)
	}
	if res.Assurance != domain.AssuranceLow {
		t.Fatalf("API keys must normalize to LOW assurance, got %v", res.Assurance)
	}
}

func TestAPIKeyNegative(t *testing.T) {
	a := apikeyAdapter(t, fixtureYAML())
	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"unknown id", "nope:s3cret-legacy", domain.ErrInvalidCredential},
		{"wrong secret", "legacy-1:wrong", domain.ErrInvalidCredential},
		{"malformed", "no-colon-here", domain.ErrInvalidCredential},
		{"empty", "", domain.ErrInvalidCredential},
		{"revoked", "revoked-1:s3cret-revoked", domain.ErrRevokedCredential},
		{"expired", "expired-1:s3cret-expired", domain.ErrCredentialExpired},
	}
	for _, tc := range cases {
		_, err := a.Authenticate(context.Background(), port.TokenEvidence{
			EvidenceKind: domain.EvidenceAPICredential, Token: tc.token,
		})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func fixtureYAML() string {
	// Keep secrets next to their verifier computation so the fixture can
	// never drift from the hash it claims.
	return `keys:
  - id: legacy-1
    verifier: "` + verifierOf("s3cret-legacy") + `"
    principal: connector:legacy-crm
    principal_type: CONNECTOR
    tenant_id: tenant:acme
    scopes: [content.read]
    expires_at: 2030-01-01T00:00:00Z
  - id: revoked-1
    verifier: "` + verifierOf("s3cret-revoked") + `"
    principal: connector:old
    principal_type: CONNECTOR
    tenant_id: tenant:acme
    revoked: true
  - id: expired-1
    verifier: "` + verifierOf("s3cret-expired") + `"
    principal: connector:older
    principal_type: CONNECTOR
    tenant_id: tenant:acme
    expires_at: 2020-01-01T00:00:00Z
`
}
