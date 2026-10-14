// Package audit emits structured security audit events. The field set is
// allowlisted: raw credentials, complete tokens, private keys, and
// sensitive request payloads are never recorded. Collision and linking
// audit records are authored by Identity 1.29; this service records only
// the failure to resolve plus a reference to the Identity 1.29 response.
package audit

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/synanton/security-provider/internal/port"
)

// Sink is an audit event destination.
type Sink = port.AuditSink

// SlogSink writes one JSON log record per event. It is the "stdout" sink.
type SlogSink struct {
	log *slog.Logger
}

// NewSlogSink builds a sink writing JSON to stdout.
func NewSlogSink() *SlogSink {
	return &SlogSink{log: slog.New(slog.NewJSONHandler(os.Stdout, nil))}
}

// Record implements port.AuditSink.
func (s *SlogSink) Record(ctx context.Context, event port.AuditEvent) {
	s.log.Info("security.audit",
		"ts", time.Now().UTC().Format(time.RFC3339Nano),
		"type", event.Type,
		"provider", event.ProviderID,
		"principal", event.PrincipalID,
		"tenant", event.TenantID,
		"outcome", event.Outcome,
		"reason", event.ReasonCode,
		"trace", event.TraceID,
		"detail", event.Detail,
	)
}

// Discard drops all events. Tests only; never wire in production.
type Discard struct{}

// Record implements port.AuditSink.
func (Discard) Record(context.Context, port.AuditEvent) {}

// Reason codes are the stable vocabulary for outcome attribution.
const (
	ReasonOK                  = "OK"
	ReasonInvalidSignature    = "INVALID_SIGNATURE"
	ReasonUntrustedIssuer     = "UNTRUSTED_ISSUER"
	ReasonAudienceMismatch    = "AUDIENCE_MISMATCH"
	ReasonUnsupportedAlg      = "UNSUPPORTED_ALG"
	ReasonExpired             = "EXPIRED"
	ReasonNotYetValid         = "NOT_YET_VALID"
	ReasonRevoked             = "REVOKED"
	ReasonUnknownPrincipal    = "UNKNOWN_PRINCIPAL"
	ReasonAmbiguousPrincipal  = "AMBIGUOUS_PRINCIPAL"
	ReasonDisabledPrincipal   = "DISABLED_PRINCIPAL"
	ReasonTenantDenied        = "TENANT_DENIED"
	ReasonConflictingIdentity = "CONFLICTING_IDENTITY"
	ReasonUnsignedIdentity    = "UNSIGNED_IDENTITY"
	ReasonDependencyOutage    = "DEPENDENCY_OUTAGE"
	ReasonUnknownProvider     = "UNKNOWN_PROVIDER"
	ReasonProviderDisabled    = "PROVIDER_DISABLED"
)
