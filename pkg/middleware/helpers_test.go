package middleware

import (
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// issueToken mints a context-shaped HS256 token for tests.
func issueToken(t *testing.T, v *HMACVerifier, tenant, principal string) string {
	t.Helper()
	return mustIssueWith(t, v, tenant, principal, time.Now().Add(5*time.Minute))
}

func mustIssue(t *testing.T, v *HMACVerifier) string {
	t.Helper()
	return mustIssueWith(t, v, "tenant:acme", "service:ingestor", time.Now().Add(5*time.Minute))
}

func mustIssueWith(t *testing.T, v *HMACVerifier, tenant, principal string, exp time.Time) string {
	t.Helper()
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, v.ExpectedIssuer)
	_ = tok.Set(jwt.SubjectKey, principal)
	_ = tok.Set(jwt.AudienceKey, "synanton-internal")
	_ = tok.Set(jwt.ExpirationKey, exp)
	_ = tok.Set(jwt.IssuedAtKey, time.Now().Add(-time.Minute))
	_ = tok.Set("principal_type", "SERVICE")
	_ = tok.Set("tenant_id", tenant)
	_ = tok.Set("auth_method", "MTLS")
	_ = tok.Set("provider_id", "test-mtls")
	_ = tok.Set("assurance_level", "HIGH")
	_ = tok.Set("authenticated_at", time.Now().Add(-time.Minute).Format(time.RFC3339Nano))
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, v.Key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}
