// Package context builds, signs, and validates the canonical security
// context. Contexts are short-lived JWTs: signature and expiry are always
// verified at trust boundaries, and any masking or representation field
// in the payload fails validation by construction.
package context

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/synanton/security-provider/internal/domain"
)

// Issuer signs and verifies security contexts.
type Issuer struct {
	key      []byte
	issuerID string
	ttl      time.Duration
	now      func() time.Time
}

// NewIssuer builds an issuer. The key is an HMAC secret for dev/test or a
// wrapped RSA/EC key reference in production; raw key material never
// leaves this package.
func NewIssuer(key []byte, issuerID string, ttl time.Duration) (*Issuer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("context: signing key must be at least 32 bytes")
	}
	if ttl <= 0 || ttl > 15*time.Minute {
		return nil, fmt.Errorf("context: ttl must be positive and at most 15m")
	}
	return &Issuer{key: key, issuerID: issuerID, ttl: ttl, now: time.Now}, nil
}

// Issue builds the minimal context from a resolution and signs it.
func (s *Issuer) Issue(_ context.Context, res domain.PrincipalResolution, auth domain.AuthenticationResult, traceID string) (string, domain.SecurityContext, error) {
	authenticatedAt := auth.AuthenticatedAt.UTC()
	if authenticatedAt.IsZero() {
		authenticatedAt = s.now().UTC()
	}
	sc := domain.SecurityContext{
		PrincipalID:   res.PrincipalID,
		PrincipalType: res.PrincipalType,
		TenantID:      res.TenantID,
		Authentication: domain.Authentication{
			Method:          auth.Method,
			ProviderID:      auth.ProviderID,
			AssuranceLevel:  auth.Assurance,
			AuthenticatedAt: authenticatedAt,
			ExpiresAt:       authenticatedAt.Add(s.ttl),
		},
		TraceID: traceID,
	}
	if err := sc.Validate(); err != nil {
		return "", domain.SecurityContext{}, err
	}
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, s.issuerID)
	_ = tok.Set(jwt.SubjectKey, sc.PrincipalID)
	_ = tok.Set(jwt.AudienceKey, "synanton-internal")
	_ = tok.Set(jwt.ExpirationKey, sc.Authentication.ExpiresAt)
	_ = tok.Set(jwt.IssuedAtKey, authenticatedAt)
	_ = tok.Set("principal_type", string(sc.PrincipalType))
	_ = tok.Set("tenant_id", sc.TenantID)
	_ = tok.Set("auth_method", string(sc.Authentication.Method))
	_ = tok.Set("provider_id", sc.Authentication.ProviderID)
	_ = tok.Set("assurance_level", string(sc.Authentication.AssuranceLevel))
	_ = tok.Set("authenticated_at", authenticatedAt.Format(time.RFC3339Nano))
	if traceID != "" {
		_ = tok.Set("trace_id", traceID)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, s.key))
	if err != nil {
		return "", domain.SecurityContext{}, fmt.Errorf("context: sign: %w", err)
	}
	return string(signed), sc, nil
}

// Verify validates signature, expiry, issuer, and shape. Unknown or
// masking-related claims fail closed.
func (s *Issuer) Verify(_ context.Context, token string) (domain.SecurityContext, error) {
	if err := rejectMaskingPayload(token); err != nil {
		return domain.SecurityContext{}, err
	}
	tok, err := jwt.ParseString(token, jwt.WithKey(jwa.HS256, s.key))
	if err != nil {
		return domain.SecurityContext{}, fmt.Errorf("%w: context signature invalid: %v", domain.ErrInvalidCredential, err)
	}
	if tok.Issuer() != s.issuerID {
		return domain.SecurityContext{}, fmt.Errorf("%w: context issuer %q", domain.ErrUntrustedIssuer, tok.Issuer())
	}
	if exp := tok.Expiration(); !exp.IsZero() && !s.now().Before(exp) {
		return domain.SecurityContext{}, fmt.Errorf("%w: context expired", domain.ErrCredentialExpired)
	}
	sc, err := fromClaims(tok)
	if err != nil {
		return domain.SecurityContext{}, err
	}
	if err := sc.Validate(); err != nil {
		return domain.SecurityContext{}, fmt.Errorf("%w: %v", domain.ErrInvalidCredential, err)
	}
	return sc, nil
}

func fromClaims(tok jwt.Token) (domain.SecurityContext, error) {
	str := func(key string) string {
		if v, ok := tok.Get(key); ok {
			if s, ok := v.(string); ok {
				return s
			}
		}
		return ""
	}
	authenticatedAt, err := time.Parse(time.RFC3339Nano, str("authenticated_at"))
	if err != nil {
		return domain.SecurityContext{}, fmt.Errorf("%w: bad authenticated_at", domain.ErrInvalidCredential)
	}
	return domain.SecurityContext{
		PrincipalID:   tok.Subject(),
		PrincipalType: domain.PrincipalType(str("principal_type")),
		TenantID:      str("tenant_id"),
		Authentication: domain.Authentication{
			Method:          domain.AuthMethod(str("auth_method")),
			ProviderID:      str("provider_id"),
			AssuranceLevel:  domain.AssuranceLevel(str("assurance_level")),
			AuthenticatedAt: authenticatedAt,
			ExpiresAt:       tok.Expiration(),
		},
		TraceID: str("trace_id"),
	}, nil
}

// forbiddenClaimSubstrings are never permitted in a context payload. The
// security context carries no masking directives, representation
// selections, or classification-derived display decisions; any token that
// smuggles them in is rejected before signature verification so the shape
// invariant holds even for attacker-crafted payloads.
var forbiddenClaimSubstrings = []string{
	"mask", "represent", "display", "classification", "redact",
}

// rejectMaskingPayload inspects the raw payload segment for forbidden
// claim names. It returns an error describing the violation, or nil.
func rejectMaskingPayload(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: malformed context token", domain.ErrInvalidCredential)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: malformed context payload", domain.ErrInvalidCredential)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fmt.Errorf("%w: malformed context claims", domain.ErrInvalidCredential)
	}
	lowered := strings.ToLower(string(raw))
	for _, bad := range forbiddenClaimSubstrings {
		if strings.Contains(lowered, `"`+bad) {
			return fmt.Errorf("%w: forbidden claim containing %q", domain.ErrInvalidCredential, bad)
		}
	}
	return nil
}
