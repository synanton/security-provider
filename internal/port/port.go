// Package port declares the interfaces (ports) of the Security Provider.
// Adapters implement these interfaces; the domain never imports adapters.
// cmd/ wires concrete adapters to these ports.
package port

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/synanton/security-provider/internal/domain"
)

// Evidence is one unit of authentication evidence presented for
// validation: a bearer token string, a TLS peer connection state, a
// workload assertion, or an API credential.
type Evidence interface {
	Kind() domain.EvidenceKind
}

// TokenEvidence carries an opaque bearer token (OIDC access token or API
// credential). The raw value must never be logged.
type TokenEvidence struct {
	EvidenceKind domain.EvidenceKind
	// Token is the raw credential. Handlers must not log, metric-label, or
	// echo it.
	Token string
	// RequestedTenant is untrusted scope hint only; membership is always
	// validated against Identity 1.29 state.
	RequestedTenant string
	TraceID         string
}

// Kind implements Evidence.
func (e TokenEvidence) Kind() domain.EvidenceKind { return e.EvidenceKind }

// TLSEvidence carries the verified TLS connection state of a peer. It is
// constructed server-side from*r/tls.ConnectionState, never from headers.
type TLSEvidence struct {
	State           tls.ConnectionState
	RequestedTenant string
	TraceID         string
}

// Kind implements Evidence.
func (e TLSEvidence) Kind() domain.EvidenceKind { return domain.EvidenceMTLSPeer }

// WorkloadEvidence carries a workload assertion (e.g. a SPIFFE JWT-SVID
// or an attested assertion document).
type WorkloadEvidence struct {
	Assertion       string
	RequestedTenant string
	TraceID         string
}

// Kind implements Evidence.
func (e WorkloadEvidence) Kind() domain.EvidenceKind { return domain.EvidenceWorkload }

// AuthenticationProvider validates one evidence kind and normalizes the
// outcome. It returns no authorization decision.
type AuthenticationProvider interface {
	// ID is the stable provider identifier used in config and audit.
	ID() string
	// Authenticate validates evidence and returns the normalized result.
	// Failures are fail-closed sentinel errors from internal/domain.
	Authenticate(ctx context.Context, evidence Evidence) (domain.AuthenticationResult, error)
	// Health reports provider health (trust bundle freshness, JWKS age).
	Health(ctx context.Context) ProviderHealth
}

// ProviderHealth is an administrative view of one provider.
type ProviderHealth struct {
	ProviderID  string
	Healthy     bool
	Detail      string
	CheckedAt   time.Time
	KeyAge      time.Duration
	KeyExpiryAt *time.Time
}

// IdentityResolver is a thin adapter over Identity 1.29's
// principal-resolution API. It owns no mapping logic: every answer comes
// from Identity 1.29 or a bounded-freshness cache of its responses.
type IdentityResolver interface {
	Resolve(ctx context.Context, result domain.AuthenticationResult, requestedTenant string) (domain.PrincipalResolution, error)
}

// ContextIssuer builds and verifies signed security contexts for
// propagation across trust boundaries.
type ContextIssuer interface {
	Issue(ctx context.Context, resolution domain.PrincipalResolution, auth domain.AuthenticationResult, traceID string) (token string, sc domain.SecurityContext, err error)
	Verify(ctx context.Context, token string) (domain.SecurityContext, error)
}

// AuditSink receives structured security events. Implementations must
// never persist raw credentials, complete tokens, or private keys.
type AuditSink interface {
	Record(ctx context.Context, event AuditEvent)
}

// AuditEvent is the allowlisted audit field set.
type AuditEvent struct {
	Type        string
	ProviderID  string
	PrincipalID string
	TenantID    string
	Outcome     string
	ReasonCode  string
	TraceID     string
	Detail      string
}

// RevocationSignal reports whether credential material observed at time t
// is still fresh enough to trust: the channel behind it (push or pull) is
// monitored, and a stale channel fails closed.
type RevocationSignal interface {
	// FreshSince returns the time up to which revocation state is known.
	FreshSince(ctx context.Context) (time.Time, error)
	// Revoked reports whether credentialID was revoked at or before t.
	Revoked(ctx context.Context, credentialID string) (bool, error)
}
