package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

// testIdP is a minimal OIDC issuer for tests: discovery + JWKS.
type testIdP struct {
	t        *testing.T
	server   *httptest.Server
	mu       sync.Mutex
	issuer   string
	keys     map[string]*rsa.PrivateKey
	audience string
}

func newTestIdP(t *testing.T, audience string) *testIdP {
	t.Helper()
	idp := &testIdP{t: t, keys: map[string]*rsa.PrivateKey{}, audience: audience}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":   idp.server.URL,
			"jwks_uri": idp.server.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		set := jwk.NewSet()
		for kid, priv := range idp.keys {
			pub, err := jwk.FromRaw(priv.PublicKey)
			if err != nil {
				t.Error(err)
				return
			}
			_ = pub.Set(jwk.KeyIDKey, kid)
			_ = pub.Set(jwk.AlgorithmKey, jwa.RS256)
			if err := set.AddKey(pub); err != nil {
				t.Error(err)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(set)
	})
	idp.server = httptest.NewServer(mux)
	idp.issuer = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *testIdP) addKey(kid string) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		idp.t.Fatal(err)
	}
	idp.mu.Lock()
	idp.keys[kid] = priv
	idp.mu.Unlock()
	return priv
}

func (idp *testIdP) rotateTo(kid string) *rsa.PrivateKey {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		idp.t.Fatal(err)
	}
	idp.mu.Lock()
	idp.keys = map[string]*rsa.PrivateKey{kid: priv}
	idp.mu.Unlock()
	return priv
}

func mintToken(t *testing.T, priv *rsa.PrivateKey, kid, issuer, audience, subject string, exp, nbf time.Time, scope string) string {
	t.Helper()
	tok := jwt.New()
	_ = tok.Set(jwt.IssuerKey, issuer)
	_ = tok.Set(jwt.AudienceKey, []string{audience})
	_ = tok.Set(jwt.SubjectKey, subject)
	_ = tok.Set(jwt.ExpirationKey, exp)
	_ = tok.Set(jwt.IssuedAtKey, time.Now().Add(-time.Minute))
	if !nbf.IsZero() {
		_ = tok.Set(jwt.NotBeforeKey, nbf)
	}
	if scope != "" {
		_ = tok.Set("scope", scope)
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	_ = key.Set(jwk.KeyIDKey, kid)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func oidcAdapter(t *testing.T, idp *testIdP, revocation port.RevocationSignal) *OIDCAdapter {
	t.Helper()
	a, err := NewOIDCAdapter(config.ProviderConfig{
		ID: "test-oidc", Type: "oidc",
		Issuer: idp.issuer, Audiences: []string{idp.audience},
		JWKSURI: idp.server.URL + "/jwks", JWKSCacheTTL: time.Minute,
		AllowedAlgorithms: []string{"RS256"},
	}, revocation)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func oidcEvidence(token string) port.TokenEvidence {
	return port.TokenEvidence{EvidenceKind: domain.EvidenceOIDCAccessToken, Token: token}
}

func TestOIDCValid(t *testing.T) {
	idp := newTestIdP(t, "synanton-api")
	priv := idp.addKey("k1")
	a := oidcAdapter(t, idp, nil)
	token := mintToken(t, priv, "k1", idp.issuer, idp.audience, "user:alice", time.Now().Add(time.Hour), time.Time{}, "")
	res, err := a.Authenticate(context.Background(), oidcEvidence(token))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.ExternalSubject != "user:alice" || res.PrincipalType != domain.PrincipalUser {
		t.Fatalf("result = %+v", res)
	}
}

func TestOIDCNegative(t *testing.T) {
	idp := newTestIdP(t, "synanton-api")
	priv := idp.addKey("k1")
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	fresh := time.Now().Add(time.Hour)
	cases := []struct {
		name  string
		token func() string
		want  error
	}{
		{"wrong audience", func() string { return mintToken(t, priv, "k1", idp.issuer, "other-api", "user:alice", fresh, time.Time{}, "") }, domain.ErrAudienceMismatch},
		{"wrong issuer", func() string { return mintToken(t, priv, "k1", "https://evil.example", idp.audience, "user:alice", fresh, time.Time{}, "") }, domain.ErrUntrustedIssuer},
		{"expired", func() string { return mintToken(t, priv, "k1", idp.issuer, idp.audience, "user:alice", time.Now().Add(-time.Hour), time.Time{}, "") }, domain.ErrCredentialExpired},
		{"not yet valid", func() string { return mintToken(t, priv, "k1", idp.issuer, idp.audience, "user:alice", fresh, time.Now().Add(time.Hour), "") }, domain.ErrCredentialNotYet},
		{"missing subject", func() string { return mintToken(t, priv, "k1", idp.issuer, idp.audience, "", fresh, time.Time{}, "") }, domain.ErrInvalidCredential},
		{"wrong key", func() string { return mintToken(t, other, "k9", idp.issuer, idp.audience, "user:alice", fresh, time.Time{}, "") }, domain.ErrInvalidCredential},
		{"garbage", func() string { return "not-a-jwt" }, domain.ErrInvalidCredential},
		{"empty", func() string { return "" }, domain.ErrInvalidCredential},
	}
	for _, tc := range cases {
		// Fresh adapter per case: failures must never poison the key cache.
		a := oidcAdapter(t, idp, nil)
		if _, err := a.Authenticate(context.Background(), oidcEvidence(tc.token())); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestOIDCAlgConfusionRejected(t *testing.T) {
	idp := newTestIdP(t, "synanton-api")
	idp.addKey("k1")
	a := oidcAdapter(t, idp, nil)
	// Unsigned (alg=none) tokens are rejected before any key lookup.
	noneTok := "eyJhbGciOiJub25lIn0.eyJpc3MiOiJ4In0."
	if _, err := a.Authenticate(context.Background(), oidcEvidence(noneTok)); err == nil {
		t.Fatal("alg=none token accepted")
	}
}

func TestOIDCRequiredScopes(t *testing.T) {
	idp := newTestIdP(t, "synanton-api")
	priv := idp.addKey("k1")
	a, err := NewOIDCAdapter(config.ProviderConfig{
		ID: "test-oidc", Type: "oidc",
		Issuer: idp.issuer, Audiences: []string{idp.audience},
		JWKSURI: idp.server.URL + "/jwks", JWKSCacheTTL: time.Minute,
		AllowedAlgorithms: []string{"RS256"}, RequiredScopes: []string{"content.write"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	without := mintToken(t, priv, "k1", idp.issuer, idp.audience, "user:alice", time.Now().Add(time.Hour), time.Time{}, "content.read")
	if _, err := a.Authenticate(context.Background(), oidcEvidence(without)); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("token without required scope: got %v", err)
	}
	with := mintToken(t, priv, "k1", idp.issuer, idp.audience, "user:alice", time.Now().Add(time.Hour), time.Time{}, "content.read content.write")
	if _, err := a.Authenticate(context.Background(), oidcEvidence(with)); err != nil {
		t.Fatalf("token with required scope: %v", err)
	}
}

func TestOIDCKeyRotation(t *testing.T) {
	idp := newTestIdP(t, "synanton-api")
	priv1 := idp.addKey("k1")
	a := oidcAdapter(t, idp, nil)
	tok1 := mintToken(t, priv1, "k1", idp.issuer, idp.audience, "user:alice", time.Now().Add(time.Hour), time.Time{}, "")
	if _, err := a.Authenticate(context.Background(), oidcEvidence(tok1)); err != nil {
		t.Fatalf("pre-rotation: %v", err)
	}
	// Rotate: server now serves only k2. The cached k1 set must reject k2
	// tokens until the bounded TTL forces a refresh (white-box reset here
	// instead of sleeping through the TTL).
	priv2 := idp.rotateTo("k2")
	tok2 := mintToken(t, priv2, "k2", idp.issuer, idp.audience, "user:alice", time.Now().Add(time.Hour), time.Time{}, "")
	if _, err := a.Authenticate(context.Background(), oidcEvidence(tok2)); err == nil {
		t.Fatal("post-rotation token validated against stale key set")
	}
	a.mu.Lock()
	a.keySet = nil
	a.mu.Unlock()
	if _, err := a.Authenticate(context.Background(), oidcEvidence(tok2)); err != nil {
		t.Fatalf("post-refresh: %v", err)
	}
}

type fakeRevocation struct {
	revoked map[string]bool
	fail    bool
}

func (f *fakeRevocation) FreshSince(context.Context) (time.Time, error) {
	return time.Now(), nil
}

func (f *fakeRevocation) Revoked(_ context.Context, id string) (bool, error) {
	if f.fail {
		return false, errors.New("signal down")
	}
	return f.revoked[id], nil
}

func TestOIDCRevocation(t *testing.T) {
	idp := newTestIdP(t, "synanton-api")
	priv := idp.addKey("k1")
	rev := &fakeRevocation{revoked: map[string]bool{}}
	a := oidcAdapter(t, idp, rev)
	token := mintToken(t, priv, "k1", idp.issuer, idp.audience, "user:alice", time.Now().Add(time.Hour), time.Time{}, "")
	if _, err := a.Authenticate(context.Background(), oidcEvidence(token)); err != nil {
		t.Fatalf("unrevoked: %v", err)
	}
	// Revoke by the credential ID the adapter derives.
	rev.revoked[credentialIDFor(mustParse(t, token))] = true
	if _, err := a.Authenticate(context.Background(), oidcEvidence(token)); !errors.Is(err, domain.ErrRevokedCredential) {
		t.Fatalf("revoked token: got %v", err)
	}
	rev.fail = true
	if _, err := a.Authenticate(context.Background(), oidcEvidence(token)); !errors.Is(err, domain.ErrDependencyOutage) {
		t.Fatalf("revocation outage must fail closed, got %v", err)
	}
}

func mustParse(t *testing.T, token string) jwt.Token {
	t.Helper()
	tok, err := jwt.ParseString(token, jwt.WithVerify(false))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}
