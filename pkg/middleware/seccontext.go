// Package middleware is the importable consumer surface of the Synanton
// Security Provider (joint-plan B1-3, milestone D.1). Content-service and
// other Synanton services validate security contexts with this package:
// no sidecar, no per-request network hop for the common path.
//
// The tenant is always derived from the validated context. Caller-
// supplied tenant hints (X-Tenant-ID header, tenant_id query, tenant_id
// metadata) are cross-checked and rejected on mismatch; they never grant
// access on their own.
//
// Dependencies are deliberately light (stdlib + jwx + grpc) so consumers
// on older toolchains adopt it without a dependency cliff.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// SecurityContext is the consumer-side mirror of the canonical context.
// Field names match the wire shape in docs/design.md §7.
type SecurityContext struct {
	PrincipalID      string
	PrincipalType    string
	TenantID         string
	AuthMethod       string
	ProviderID       string
	AssuranceLevel   string
	AuthenticatedAt  time.Time
	ExpiresAt        time.Time
	InitiatedBy      string
	DelegatedBy      string
	TraceID          string
}

// Sentinel errors for validation failures.
var (
	ErrMissingContext    = errors.New("missing security context")
	ErrInvalidContext    = errors.New("invalid security context")
	ErrExpiredContext    = errors.New("expired security context")
	ErrConflictingTenant = errors.New("conflicting tenant claim")
	ErrUnsignedIdentity  = errors.New("unsigned identity claim")
)

// Verifier validates a context token without a network round trip.
type Verifier interface {
	Verify(ctx context.Context, token string) (SecurityContext, error)
}

// HMACVerifier validates HMAC-signed (HS256) context tokens issued by the
// Security Provider. Key distribution is the operator's concern (secret
// store mount, rotation via config reload); the TTL bound keeps verifiers
// inside the revocation SLO.
type HMACVerifier struct {
	Key            []byte
	ExpectedIssuer string
	Now            func() time.Time
}

func (v *HMACVerifier) clock() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

// Verify implements Verifier.
func (v *HMACVerifier) Verify(_ context.Context, token string) (SecurityContext, error) {
	if token == "" {
		return SecurityContext{}, ErrMissingContext
	}
	if err := rejectForbiddenClaims(token); err != nil {
		return SecurityContext{}, err
	}
	tok, err := jwt.ParseString(token, jwt.WithKey(jwa.HS256, v.Key))
	if err != nil {
		return SecurityContext{}, fmt.Errorf("%w: bad signature: %v", ErrInvalidContext, err)
	}
	if v.ExpectedIssuer != "" && tok.Issuer() != v.ExpectedIssuer {
		return SecurityContext{}, fmt.Errorf("%w: untrusted issuer", ErrInvalidContext)
	}
	if exp := tok.Expiration(); !exp.IsZero() && !v.clock().Before(exp) {
		return SecurityContext{}, ErrExpiredContext
	}
	sc := SecurityContext{
		PrincipalID:    tok.Subject(),
		PrincipalType:  claimString(tok, "principal_type"),
		TenantID:       claimString(tok, "tenant_id"),
		AuthMethod:     claimString(tok, "auth_method"),
		ProviderID:     claimString(tok, "provider_id"),
		AssuranceLevel: claimString(tok, "assurance_level"),
		ExpiresAt:      tok.Expiration(),
		TraceID:        claimString(tok, "trace_id"),
	}
	if raw := claimString(tok, "authenticated_at"); raw != "" {
		if t, err := time.Parse(time.RFC3339Nano, raw); err == nil {
			sc.AuthenticatedAt = t
		}
	}
	if sc.PrincipalID == "" || sc.TenantID == "" || sc.PrincipalType == "" {
		return SecurityContext{}, fmt.Errorf("%w: missing required claims", ErrInvalidContext)
	}
	return sc, nil
}

func claimString(tok jwt.Token, key string) string {
	if v, ok := tok.Get(key); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// forbiddenSubstrings mirrors the server-side shape invariant: the
// context carries no masking, representation, or classification-derived
// display decisions. Any token smuggling them in is rejected here too, so
// consumers cannot be tricked into honoring them.
var forbiddenSubstrings = []string{"mask", "represent", "display", "classification", "redact"}

func rejectForbiddenClaims(token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: malformed token", ErrInvalidContext)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("%w: malformed payload", ErrInvalidContext)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return fmt.Errorf("%w: malformed claims", ErrInvalidContext)
	}
	lowered := strings.ToLower(string(raw))
	for _, bad := range forbiddenSubstrings {
		if strings.Contains(lowered, `"`+bad) {
			return fmt.Errorf("%w: forbidden claim containing %q", ErrInvalidContext, bad)
		}
	}
	return nil
}

type contextKey int

const (
	securityContextKey contextKey = iota
)

// WithSecurityContext injects a validated context (tests, in-process calls).
func WithSecurityContext(ctx context.Context, sc SecurityContext) context.Context {
	return context.WithValue(ctx, securityContextKey, sc)
}

// SecurityContextFrom returns the validated context in ctx.
func SecurityContextFrom(ctx context.Context) (SecurityContext, error) {
	sc, ok := ctx.Value(securityContextKey).(SecurityContext)
	if !ok || sc.PrincipalID == "" {
		return SecurityContext{}, ErrMissingContext
	}
	return sc, nil
}

// TenantIDFromContext returns the tenant derived from the validated
// context. There is no other legitimate source.
func TenantIDFromContext(ctx context.Context) (string, error) {
	sc, err := SecurityContextFrom(ctx)
	if err != nil {
		return "", err
	}
	if sc.TenantID == "" {
		return "", ErrMissingContext
	}
	return sc.TenantID, nil
}

// CheckTenantHint cross-checks a caller-supplied tenant hint (header,
// query, body field) against the validated context. A present-but-
// mismatched hint is a forgery attempt: reject it. An absent hint is
// fine: the context tenant governs.
func CheckTenantHint(ctx context.Context, hint string) error {
	if hint == "" {
		return nil
	}
	tenant, err := TenantIDFromContext(ctx)
	if err != nil {
		return err
	}
	if hint != tenant {
		return fmt.Errorf("%w: hint %q != context tenant %q", ErrConflictingTenant, hint, tenant)
	}
	return nil
}

// RejectUnsignedIdentity rejects requests that carry identity-flavored
// headers (X-User-ID, X-Tenant-ID-as-authority) without a validated
// context. Unsigned identity headers are never authoritative.
func RejectUnsignedIdentity(ctx context.Context, userHeader, tenantHeader string) error {
	if _, err := SecurityContextFrom(ctx); err != nil {
		if userHeader != "" || tenantHeader != "" {
			return ErrUnsignedIdentity
		}
		return ErrMissingContext
	}
	return nil
}
