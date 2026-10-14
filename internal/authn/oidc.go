package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

// OIDCAdapter validates OAuth 2.0 / OIDC access tokens against trusted
// issuer metadata and JWKS. A token is never accepted merely because it
// can be decoded: issuer, audience, signature, permitted algorithm,
// expiry, not-before, subject, and required scopes are all enforced.
type OIDCAdapter struct {
	id          string
	issuer      string
	audiences   map[string]struct{}
	allowedAlgs map[string]struct{}
	requiredScopes []string

	mu         sync.Mutex
	jwksURI    string
	jwksTTL    time.Duration
	keySet     jwk.Set
	keyFetched time.Time
	revocation port.RevocationSignal
}

// NewOIDCAdapter builds an OIDC adapter. Discovery (oidc.NewProvider) is
// lazy so unit tests and offline environments fail closed at first use,
// not at construction.
func NewOIDCAdapter(cfg config.ProviderConfig, revocation port.RevocationSignal) (*OIDCAdapter, error) {
	auds := map[string]struct{}{}
	for _, a := range cfg.Audiences {
		auds[a] = struct{}{}
	}
	algs := map[string]struct{}{}
	for _, alg := range cfg.AllowedAlgorithms {
		if strings.EqualFold(alg, "none") {
			return nil, fmt.Errorf("oidc %q: alg=none is never permitted", cfg.ID)
		}
		algs[strings.ToUpper(alg)] = struct{}{}
	}
	ttl := cfg.JWKSCacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &OIDCAdapter{
		id:             cfg.ID,
		issuer:         cfg.Issuer,
		audiences:      auds,
		allowedAlgs:    algs,
		requiredScopes: cfg.RequiredScopes,
		jwksURI:        cfg.JWKSURI,
		jwksTTL:        ttl,
		revocation:     revocation,
	}, nil
}

// ID implements port.AuthenticationProvider.
func (a *OIDCAdapter) ID() string { return a.id }

// Authenticate implements port.AuthenticationProvider.
func (a *OIDCAdapter) Authenticate(ctx context.Context, evidence port.Evidence) (domain.AuthenticationResult, error) {
	tok, ok := evidence.(port.TokenEvidence)
	if !ok || tok.EvidenceKind != domain.EvidenceOIDCAccessToken {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: oidc provider requires OIDC access token evidence", domain.ErrInvalidCredential)
	}
	if tok.Token == "" {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: empty token", domain.ErrInvalidCredential)
	}
	// The pre-filter parse decodes without verifying: signature checks
	// happen in verifySignature, and claim validation below owns the
	// sentinel errors (so validation is disabled here, not skipped).
	parsed, err := jwt.ParseString(tok.Token, jwt.WithVerify(false), jwt.WithValidate(false))
	if err != nil {
		return domain.AuthenticationResult{}, fmt.Errorf("%w: token undecodable: %v", domain.ErrInvalidCredential, err)
	}
	if err := a.checkUntrustedClaims(parsed); err != nil {
		return domain.AuthenticationResult{}, err
	}
	if err := a.verifySignature(ctx, tok.Token); err != nil {
		return domain.AuthenticationResult{}, err
	}
	if err := a.checkScopes(parsed); err != nil {
		return domain.AuthenticationResult{}, err
	}
	if a.revocation != nil {
		if revoked, err := a.revocation.Revoked(ctx, credentialIDFor(parsed)); err != nil {
			return domain.AuthenticationResult{}, fmt.Errorf("%w: revocation check failed: %v", domain.ErrDependencyOutage, err)
		} else if revoked {
			return domain.AuthenticationResult{}, fmt.Errorf("%w: token revoked", domain.ErrRevokedCredential)
		}
	}
	exp := parsed.Expiration()
	return domain.AuthenticationResult{
		ProviderID:      a.id,
		ExternalIssuer:  parsed.Issuer(),
		ExternalSubject: parsed.Subject(),
		PrincipalType:   domain.PrincipalUser,
		Assurance:       domain.AssuranceMedium,
		Method:          domain.MethodOIDC,
		AuthenticatedAt: now(),
		ExpiresAt:       ptrTime(exp),
		CredentialID:    credentialIDFor(parsed),
		EvidenceKind:    domain.EvidenceOIDCAccessToken,
	}, nil
}

// checkUntrustedClaims enforces every claim that can be checked without
// keys: issuer trust, audience, subject presence, expiry, not-before.
func (a *OIDCAdapter) checkUntrustedClaims(tok jwt.Token) error {
	if tok.Issuer() != a.issuer {
		return fmt.Errorf("%w: got %q", domain.ErrUntrustedIssuer, tok.Issuer())
	}
	audOK := false
	for _, aud := range tok.Audience() {
		if _, ok := a.audiences[aud]; ok {
			audOK = true
			break
		}
	}
	if !audOK {
		return fmt.Errorf("%w: token audience %q not trusted", domain.ErrAudienceMismatch, tok.Audience())
	}
	if tok.Subject() == "" {
		return fmt.Errorf("%w: missing subject", domain.ErrInvalidCredential)
	}
	t := now()
	if exp := tok.Expiration(); !exp.IsZero() && !t.Before(exp.Add(clockSkewAllowance())) {
		return fmt.Errorf("%w: token expired", domain.ErrCredentialExpired)
	}
	if nbf := tok.NotBefore(); !nbf.IsZero() && t.Before(nbf.Add(-clockSkewAllowance())) {
		return fmt.Errorf("%w: token not yet valid", domain.ErrCredentialNotYet)
	}
	return nil
}

// verifySignature checks the permitted algorithm then verifies against
// the cached JWKS. Key fetch failures fail closed.
func (a *OIDCAdapter) verifySignature(ctx context.Context, raw string) error {
	rawAlg := tokenAlg(raw)
	if _, ok := a.allowedAlgs[strings.ToUpper(rawAlg)]; !ok {
		return fmt.Errorf("%w: %q not in allowed set", domain.ErrUnsupportedAlg, rawAlg)
	}
	set, err := a.keySetFor(ctx)
	if err != nil {
		return err
	}
	if _, err := jwt.ParseString(raw, jwt.WithKeySet(set)); err != nil {
		return fmt.Errorf("%w: signature verification failed: %v", domain.ErrInvalidCredential, err)
	}
	return nil
}

// keySetFor returns the cached JWKS, refreshing past the bounded TTL. A
// stale revocation-signal channel fails closed instead of serving old keys
// past the SLO: callers treat ErrDependencyOutage as a hard failure.
func (a *OIDCAdapter) keySetFor(ctx context.Context) (jwk.Set, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keySet != nil && now().Before(a.keyFetched.Add(a.jwksTTL)) {
		return a.keySet, nil
	}
	set, err := a.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	a.keySet = set
	a.keyFetched = now()
	return set, nil
}

func (a *OIDCAdapter) fetchKeys(ctx context.Context) (jwk.Set, error) {
	if a.jwksURI != "" {
		set, err := jwk.Fetch(ctx, a.jwksURI)
		if err != nil {
			return nil, fmt.Errorf("%w: JWKS fetch failed: %v", domain.ErrDependencyOutage, err)
		}
		return set, nil
	}
	// Without an explicit JWKS URI, fall back to OIDC discovery. The
	// go-oidc provider pins the discovery path; verification still goes
	// through the jwx key set above once remote keys are known.
	provider, err := oidc.NewProvider(ctx, a.issuer)
	if err != nil {
		return nil, fmt.Errorf("%w: OIDC discovery failed: %v", domain.ErrDependencyOutage, err)
	}
	var claims struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&claims); err != nil || claims.JWKSURI == "" {
		return nil, fmt.Errorf("%w: OIDC discovery exposed no jwks_uri", domain.ErrDependencyOutage)
	}
	set, err := jwk.Fetch(ctx, claims.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("%w: JWKS fetch failed: %v", domain.ErrDependencyOutage, err)
	}
	return set, nil
}

func (a *OIDCAdapter) checkScopes(tok jwt.Token) error {
	if len(a.requiredScopes) == 0 {
		return nil
	}
	have := map[string]struct{}{}
	if v, ok := tok.Get("scope"); ok {
		if s, ok := v.(string); ok {
			for _, sc := range strings.Fields(s) {
				have[sc] = struct{}{}
			}
		}
	}
	if v, ok := tok.Get("scp"); ok {
		if arr, ok := v.([]interface{}); ok {
			for _, sc := range arr {
				if s, ok := sc.(string); ok {
					have[s] = struct{}{}
				}
			}
		}
	}
	for _, need := range a.requiredScopes {
		if _, ok := have[need]; !ok {
			return fmt.Errorf("%w: missing required scope %q", domain.ErrInvalidCredential, need)
		}
	}
	return nil
}

// Health implements port.AuthenticationProvider.
func (a *OIDCAdapter) Health(_ context.Context) port.ProviderHealth {
	a.mu.Lock()
	defer a.mu.Unlock()
	h := port.ProviderHealth{ProviderID: a.id, CheckedAt: now()}
	if a.keySet == nil {
		h.Healthy = true
		h.Detail = "JWKS not yet fetched"
		return h
	}
	age := now().Sub(a.keyFetched)
	h.Healthy = age <= a.jwksTTL
	h.Detail = fmt.Sprintf("JWKS age %v (ttl %v)", age.Round(time.Second), a.jwksTTL)
	h.KeyAge = age
	return h
}

func clockSkewAllowance() time.Duration { return 60 * time.Second }

// credentialIDFor derives a stable, non-secret credential identifier for
// audit and revocation correlation (never the token itself).
func credentialIDFor(tok jwt.Token) string {
	sum := sha256.Sum256([]byte(tok.Issuer() + "|" + tok.Subject() + "|" + tok.JwtID()))
	return "oidc:" + hex.EncodeToString(sum[:16])
}

// tokenAlg extracts the alg header without verifying anything. It is
// only a pre-filter for the allowlist; the real verification happens
// against the JWKS in verifySignature.
func tokenAlg(raw string) string {
	msg, err := jws.ParseString(raw)
	if err != nil || len(msg.Signatures()) == 0 {
		return ""
	}
	return msg.Signatures()[0].ProtectedHeaders().Algorithm().String()
}
