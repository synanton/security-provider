package authn

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

// MTLSAdapter authenticates TLS peer certificates against a configured
// trust bundle. mTLS authenticates the peer and protects the channel; it
// does not by itself authorize a tenant or operation.
type MTLSAdapter struct {
	id           string
	pool         *x509.CertPool
	bundlePath   string
	bundleLoaded time.Time
	sanPatterns  []string
}

// NewMTLSAdapter builds an mTLS adapter from provider configuration.
func NewMTLSAdapter(cfg config.ProviderConfig) (*MTLSAdapter, error) {
	pemBytes, err := os.ReadFile(cfg.TrustBundle)
	if err != nil {
		return nil, fmt.Errorf("mtls %q: read trust bundle: %w", cfg.ID, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("mtls %q: no certificates parsed from trust bundle", cfg.ID)
	}
	return &MTLSAdapter{
		id:           cfg.ID,
		pool:         pool,
		bundlePath:   cfg.TrustBundle,
		bundleLoaded: now(),
		sanPatterns:  cfg.AllowedSANPatterns,
	}, nil
}

// ID implements port.AuthenticationProvider.
func (a *MTLSAdapter) ID() string { return a.id }

// Authenticate implements port.AuthenticationProvider. Evidence must be a
// port.TLSEvidence built server-side from the TLS handshake.
func (a *MTLSAdapter) Authenticate(ctx context.Context, evidence port.Evidence) (domain.AuthenticationResult, error) {
	tlsEv, ok := evidence.(port.TLSEvidence)
	if !ok {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: mtls provider requires TLS peer evidence", domain.ErrInvalidCredential)
	}
	if len(tlsEv.State.PeerCertificates) == 0 {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: no peer certificate presented", domain.ErrInvalidCredential)
	}
	leaf := tlsEv.State.PeerCertificates[0]
	opts := x509.VerifyOptions{
		Roots:         a.pool,
		Intermediates: intermediates(tlsEv.State.PeerCertificates[1:]),
		CurrentTime:   now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if _, err := leaf.Verify(opts); err != nil {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: peer certificate does not chain to trust bundle: %v", domain.ErrUntrustedIssuer, err)
	}
	identity, err := peerIdentity(leaf)
	if err != nil {
		return domain.AuthenticationResult{}, err
	}
	if !a.sanAllowed(identity) {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: peer identity %q not in allowlist", domain.ErrUntrustedIssuer, identity)
	}
	principalType := domain.PrincipalService
	if strings.HasPrefix(identity, "spiffe://") {
		principalType = domain.PrincipalWorkload
	}
	return domain.AuthenticationResult{
		ProviderID:      a.id,
		ExternalIssuer:  issuerName(leaf),
		ExternalSubject: identity,
		PrincipalType:   principalType,
		Assurance:       domain.AssuranceHigh,
		Method:          domain.MethodMTLS,
		AuthenticatedAt: now(),
		ExpiresAt:       ptrTime(leaf.NotAfter),
		CredentialID:    certFingerprint(leaf),
		EvidenceKind:    domain.EvidenceMTLSPeer,
	}, nil
}

// Health implements port.AuthenticationProvider.
func (a *MTLSAdapter) Health(_ context.Context) port.ProviderHealth {
	return port.ProviderHealth{
		ProviderID: a.id,
		Healthy:    true,
		Detail:     fmt.Sprintf("trust bundle %q loaded", a.bundlePath),
		CheckedAt:  now(),
		KeyAge:     now().Sub(a.bundleLoaded),
	}
}

// sanAllowed matches identity against the configured allowlist. An empty
// allowlist denies everything: trust without scope is not trust.
func (a *MTLSAdapter) sanAllowed(identity string) bool {
	for _, pattern := range a.sanPatterns {
		if ok, _ := path.Match(pattern, identity); ok {
			return true
		}
	}
	return false
}

func intermediates(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}

// peerIdentity extracts the peer identity: preferred SPIFFE URI SAN,
// else DNS SAN, else CommonName. SPIFFE IDs are canonicalized through
// spiffeid parsing so malformed IDs fail here, not downstream.
func peerIdentity(leaf *x509.Certificate) (string, error) {
	for _, uri := range leaf.URIs {
		if uri.Scheme != "spiffe" {
			continue
		}
		id, err := spiffeid.FromString(uri.String())
		if err != nil {
			return "", fmt.Errorf("%w: malformed SPIFFE ID %q", domain.ErrInvalidCredential, uri.String())
		}
		return id.String(), nil
	}
	if len(leaf.DNSNames) > 0 {
		return "dns:" + leaf.DNSNames[0], nil
	}
	if len(leaf.EmailAddresses) > 0 {
		return "email:" + leaf.EmailAddresses[0], nil
	}
	if leaf.Subject.CommonName != "" {
		return "cn:" + leaf.Subject.CommonName, nil
	}
	return "", fmt.Errorf("%w: peer certificate carries no usable identity", domain.ErrInvalidCredential)
}

func issuerName(leaf *x509.Certificate) string {
	if leaf.Issuer.CommonName != "" {
		return leaf.Issuer.CommonName
	}
	return leaf.Issuer.String()
}

func certFingerprint(leaf *x509.Certificate) string {
	// Subject+Serial is a stable credential identifier for audit and
	// revocation correlation. It is not secret material.
	return fmt.Sprintf("%x/%s", leaf.SerialNumber, leaf.Subject.String())
}

func ptrTime(t time.Time) *time.Time { return &t }

// spiffeTrustDomain extracts the trust domain from a SPIFFE ID string.
func spiffeTrustDomain(id string) (string, error) {
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" {
		return "", fmt.Errorf("%w: %q is not a SPIFFE ID", domain.ErrInvalidCredential, id)
	}
	trustDomain, err := spiffeid.TrustDomainFromString(u.Host)
	if err != nil {
		return "", fmt.Errorf("%w: bad trust domain in %q", domain.ErrInvalidCredential, id)
	}
	return trustDomain.String(), nil
}
