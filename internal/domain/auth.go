// Package domain holds the pure authentication-domain types of the
// Synanton Security Provider. It performs no I/O: no token fetching, no
// network calls, no clock reads outside explicitly passed timestamps.
// Adapters depend on these types; they never depend on adapters.
package domain

import (
	"errors"
	"time"
)

// EvidenceKind names the supported authentication evidence kinds.
// The set is closed: adding a kind requires an ADR (see docs/adr/).
type EvidenceKind string

const (
	EvidenceOIDCAccessToken EvidenceKind = "OIDC_ACCESS_TOKEN"
	EvidenceMTLSPeer        EvidenceKind = "MTLS_PEER"
	EvidenceWorkload        EvidenceKind = "WORKLOAD_ASSERTION"
	EvidenceAPICredential   EvidenceKind = "API_CREDENTIAL"
)

// Valid reports whether k is a known evidence kind.
func (k EvidenceKind) Valid() bool {
	switch k {
	case EvidenceOIDCAccessToken, EvidenceMTLSPeer, EvidenceWorkload, EvidenceAPICredential:
		return true
	default:
		return false
	}
}

// PrincipalType is the canonical Synanton principal type owned by
// Identity 1.29. This service consumes the values; it never invents new
// ones.
type PrincipalType string

const (
	PrincipalUser      PrincipalType = "USER"
	PrincipalService   PrincipalType = "SERVICE"
	PrincipalWorkload  PrincipalType = "WORKLOAD"
	PrincipalConnector PrincipalType = "CONNECTOR"
	PrincipalAgent     PrincipalType = "AGENT"
)

// Valid reports whether p is a known principal type.
func (p PrincipalType) Valid() bool {
	switch p {
	case PrincipalUser, PrincipalService, PrincipalWorkload, PrincipalConnector, PrincipalAgent:
		return true
	default:
		return false
	}
}

// AssuranceLevel is the normalized authentication assurance preserved in
// the security context.
type AssuranceLevel string

const (
	AssuranceLow    AssuranceLevel = "LOW"
	AssuranceMedium AssuranceLevel = "MEDIUM"
	AssuranceHigh   AssuranceLevel = "HIGH"
)

// Valid reports whether a is a known assurance level.
func (a AssuranceLevel) Valid() bool {
	switch a {
	case AssuranceLow, AssuranceMedium, AssuranceHigh:
		return true
	default:
		return false
	}
}

// AuthMethod names the mechanism that produced a security context.
type AuthMethod string

const (
	MethodMTLS     AuthMethod = "MTLS"
	MethodOIDC     AuthMethod = "OIDC"
	MethodWorkload AuthMethod = "WORKLOAD"
	MethodAPIKey   AuthMethod = "API_KEY"
)

// AuthenticationResult is the normalized outcome of validating one piece
// of authentication evidence, before principal resolution. It carries no
// authorization decision.
type AuthenticationResult struct {
	ProviderID      string
	ExternalIssuer  string
	ExternalSubject string
	PrincipalType   PrincipalType
	Assurance       AssuranceLevel
	Method          AuthMethod
	AuthenticatedAt time.Time
	ExpiresAt       *time.Time
	CredentialID    string
	EvidenceKind    EvidenceKind
}

// PrincipalResolution is the authoritative answer from Identity 1.29 for
// one authentication result. Ambiguous reports fail closed downstream.
type PrincipalResolution struct {
	PrincipalID   string
	PrincipalType PrincipalType
	TenantID      string
	Active        bool
	// Ambiguous is set when Identity 1.29 reports an unlinked, colliding,
	// or otherwise ambiguous external identity. Callers must reject.
	Ambiguous bool
	// IdentityRef is an opaque reference to the Identity 1.29 response for
	// audit correlation. It carries no credential material.
	IdentityRef string
}

// Delegation carries an explicit, auditable actor chain. It is only
// present when delegation was explicitly established and validated.
type Delegation struct {
	InitiatedBy string `json:"initiated_by"`
	DelegatedBy string `json:"delegated_by,omitempty"`
}

// Authentication is the authentication block of the security context.
type Authentication struct {
	Method          AuthMethod     `json:"method"`
	ProviderID      string         `json:"provider_id"`
	AssuranceLevel  AssuranceLevel `json:"assurance_level"`
	AuthenticatedAt time.Time      `json:"authenticated_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
}

// SecurityContext is the minimal, verifiable identity context handed to
// downstream services. By construction it contains no masking directives,
// no representation selections, and no classification-derived output
// shaping: those are applied downstream by Security 1.23 enforcement
// points and must never be added here.
type SecurityContext struct {
	PrincipalID    string         `json:"principal_id"`
	PrincipalType  PrincipalType  `json:"principal_type"`
	TenantID       string         `json:"tenant_id"`
	Authentication Authentication  `json:"authentication"`
	Delegation     *Delegation    `json:"delegation,omitempty"`
	TraceID        string         `json:"trace_id,omitempty"`
}

// Validate checks structural invariants of a resolved context. Signature
// and freshness checks live in the context package; this covers shape.
func (c SecurityContext) Validate() error {
	if c.PrincipalID == "" {
		return errors.New("security context: missing principal_id")
	}
	if !c.PrincipalType.Valid() {
		return errors.New("security context: unknown principal_type")
	}
	if c.TenantID == "" {
		return errors.New("security context: missing tenant_id")
	}
	if !c.Authentication.AssuranceLevel.Valid() {
		return errors.New("security context: unknown assurance_level")
	}
	if c.Authentication.ProviderID == "" {
		return errors.New("security context: missing provider_id")
	}
	if c.Authentication.AuthenticatedAt.IsZero() {
		return errors.New("security context: missing authenticated_at")
	}
	if !c.Authentication.ExpiresAt.After(c.Authentication.AuthenticatedAt) {
		return errors.New("security context: expires_at must be after authenticated_at")
	}
	return nil
}

// Sentinel errors for authentication and resolution failures. Callers
// compare with errors.Is and map to stable reason codes; the messages
// never include credential material.
var (
	ErrInvalidCredential  = errors.New("invalid credential")
	ErrUntrustedIssuer    = errors.New("untrusted issuer")
	ErrAudienceMismatch   = errors.New("audience mismatch")
	ErrUnsupportedAlg     = errors.New("unsupported algorithm")
	ErrCredentialExpired  = errors.New("credential expired")
	ErrCredentialNotYet   = errors.New("credential not yet valid")
	ErrRevokedCredential  = errors.New("revoked credential")
	ErrPrincipalUnknown   = errors.New("principal unknown")
	ErrPrincipalAmbiguous = errors.New("principal ambiguous")
	ErrPrincipalDisabled  = errors.New("principal disabled")
	ErrTenantDenied       = errors.New("tenant membership denied")
	ErrDelegationInvalid  = errors.New("delegation invalid")
	ErrDependencyOutage   = errors.New("security dependency unavailable")
	ErrConflictingIdentity = errors.New("conflicting identity claim")
	ErrUnsignedIdentity   = errors.New("unsigned identity claim")
)
