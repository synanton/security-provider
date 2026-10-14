// Package policy enforces the trust and local-verification policy of the
// Security Provider: which issuers are trusted, which operations must use
// centralized validation (§9.1), and the TTL bounds that keep local
// verifiers inside the revocation SLO (§11.2).
package policy

import (
	"path"
	"time"

	"github.com/synanton/security-provider/internal/config"
)

// Verifier ranks how a token may be validated for one operation.
type Verifier int

const (
	// VerifierCentralized forces a call to this service (and Identity 1.29).
	VerifierCentralized Verifier = iota
	// VerifierLocal permits a bounded-TTL local JWKS verification.
	VerifierLocal
)

// Policy is the compiled trust policy.
type Policy struct {
	cfg config.LocalVerifyConfig
}

// New compiles the local-verification policy section.
func New(cfg config.LocalVerifyConfig) *Policy {
	return &Policy{cfg: cfg}
}

// RequiresCentralized reports whether operation must bypass local
// verification. Patterns use path.Match syntax (e.g. "admin.*") and the
// list is owned by Security 1.23, consumed here as configuration.
func (p *Policy) RequiresCentralized(operation string) bool {
	for _, pattern := range p.cfg.CentralizedOnlyPatterns {
		if ok, _ := path.Match(pattern, operation); ok {
			return true
		}
	}
	return false
}

// MaxKeyAge returns the bounded TTL for cached verification keys. The
// highRisk flag selects the high-risk issuer bound. Callers must treat a
// stale revocation-signal channel as a hard failure, not a reason to
// extend the TTL.
func (p *Policy) MaxKeyAge(highRisk bool) time.Duration {
	if highRisk {
		return p.cfg.TTLHighRisk
	}
	return p.cfg.TTLStandard
}

// SelectVerifier picks the permitted verification path for operation.
func (p *Policy) SelectVerifier(operation string, localEnabled bool) Verifier {
	if !localEnabled || !p.cfg.Enabled {
		return VerifierCentralized
	}
	if p.RequiresCentralized(operation) {
		return VerifierCentralized
	}
	return VerifierLocal
}
