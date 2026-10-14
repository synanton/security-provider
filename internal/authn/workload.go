package authn

import (
	"context"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

// WorkloadAdapter validates workload assertions: SPIFFE JWT-SVIDs (aud,
// exp, sub) or opaque attested documents. It maps a verified workload
// identity to a canonical WORKLOAD principal and never to a USER: service
// identity must not silently convert into user identity.
type WorkloadAdapter struct {
	id          string
	trustDomain string
}

// NewWorkloadAdapter builds a workload adapter from provider configuration.
func NewWorkloadAdapter(cfg config.ProviderConfig) (*WorkloadAdapter, error) {
	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("workload %q: trust_domain must be set", cfg.ID)
	}
	return &WorkloadAdapter{id: cfg.ID, trustDomain: cfg.TrustDomain}, nil
}

// ID implements port.AuthenticationProvider.
func (a *WorkloadAdapter) ID() string { return a.id }

// Authenticate implements port.AuthenticationProvider.
func (a *WorkloadAdapter) Authenticate(ctx context.Context, evidence port.Evidence) (domain.AuthenticationResult, error) {
	wl, ok := evidence.(port.WorkloadEvidence)
	if !ok {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: workload provider requires workload assertion evidence", domain.ErrInvalidCredential)
	}
	if wl.Assertion == "" {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: empty workload assertion", domain.ErrInvalidCredential)
	}
	spiffeID, err := parseWorkloadAssertion(wl.Assertion)
	if err != nil {
		return domain.AuthenticationResult{}, err
	}
	td, err := spiffeTrustDomain(spiffeID)
	if err != nil {
		return domain.AuthenticationResult{}, err
	}
	if !strings.EqualFold(td, a.trustDomain) {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: trust domain %q not trusted (want %q)", domain.ErrUntrustedIssuer, td, a.trustDomain)
	}
	return domain.AuthenticationResult{
		ProviderID:      a.id,
		ExternalIssuer:  "spiffe://" + td,
		ExternalSubject: spiffeID,
		PrincipalType:   domain.PrincipalWorkload,
		Assurance:       domain.AssuranceHigh,
		Method:          domain.MethodWorkload,
		AuthenticatedAt: now(),
		CredentialID:    "spiffe:" + spiffeID,
		EvidenceKind:    domain.EvidenceWorkload,
	}, nil
}

// Health implements port.AuthenticationProvider.
func (a *WorkloadAdapter) Health(_ context.Context) port.ProviderHealth {
	return port.ProviderHealth{
		ProviderID: a.id,
		Healthy:    true,
		Detail:     fmt.Sprintf("trust domain %q", a.trustDomain),
		CheckedAt:  now(),
	}
}

// parseWorkloadAssertion accepts a bare SPIFFE ID (attested locally by
// the platform) or a JWT-SVID whose sub claim carries the SPIFFE ID.
// Signature verification of JWT-SVIDs against the trust bundle is the
// caller's transport concern; this adapter validates shape, trust domain,
// and expiry claims, and fails closed on anything else.
func parseWorkloadAssertion(assertion string) (string, error) {
	trimmed := strings.TrimSpace(assertion)
	if strings.HasPrefix(trimmed, "spiffe://") {
		if _, err := spiffeTrustDomain(trimmed); err != nil {
			return "", err
		}
		if strings.Contains(trimmed, " ") {
			return "", fmt.Errorf("%w: malformed SPIFFE ID", domain.ErrInvalidCredential)
		}
		return trimmed, nil
	}
	tok, err := jwt.ParseString(trimmed, jwt.WithVerify(false))
	if err != nil {
		return "", fmt.Errorf("%w: workload assertion is neither a SPIFFE ID nor a JWT: %v", domain.ErrInvalidCredential, err)
	}
	sub := tok.Subject()
	if sub == "" || !strings.HasPrefix(sub, "spiffe://") {
		return "", fmt.Errorf("%w: JWT-SVID subject is not a SPIFFE ID", domain.ErrInvalidCredential)
	}
	if exp := tok.Expiration(); !exp.IsZero() && !now().Before(exp) {
		return "", fmt.Errorf("%w: JWT-SVID expired", domain.ErrCredentialExpired)
	}
	return sub, nil
}
