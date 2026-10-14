package http

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/synanton/security-provider/internal/audit"
	"github.com/synanton/security-provider/internal/authn"
	"github.com/synanton/security-provider/internal/config"
	ctxpkg "github.com/synanton/security-provider/internal/context"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/identity"
	"github.com/synanton/security-provider/internal/observability"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	secret := "handler-secret"
	sum := sha256.Sum256([]byte(secret))
	keysYAML := "keys:\n  - id: k1\n    verifier: \"" + hex.EncodeToString(sum[:]) + "\"\n" +
		"    principal: connector:crm\n    principal_type: CONNECTOR\n    tenant_id: tenant:acme\n" +
		"    expires_at: 2030-01-01T00:00:00Z\n"
	credPath := filepath.Join(t.TempDir(), "keys.yaml")
	if err := os.WriteFile(credPath, []byte(keysYAML), 0600); err != nil {
		t.Fatal(err)
	}
	provider, err := authn.NewAPIKeyAdapter(config.ProviderConfig{ID: "legacy", Type: "apikey", CredentialFile: credPath})
	if err != nil {
		t.Fatal(err)
	}
	registry := authn.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	resolver := identity.NewClient(config.IdentityConfig{Mode: "stub", Timeout: time.Second, CacheTTL: time.Minute})
	resolver.AddStubMapping("legacy", "connector:crm", domain.PrincipalResolution{
		PrincipalID: "connector:crm", PrincipalType: domain.PrincipalConnector,
		TenantID: "tenant:acme", Active: true, IdentityRef: "ref-h",
	})
	issuer, err := ctxpkg.NewIssuer([]byte("handler-signing-key-at-least-32B!!"), "synanton-security-provider", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.New(prometheus.NewRegistry())
	srv := New(registry, resolver, issuer, audit.Discard{}, metrics, "admin-token", slog.Default())
	srv.SeedProviders([]ProviderView{{ID: "legacy", Type: "apikey", Enabled: true}})
	return srv
}

func postJSON(t *testing.T, handler http.Handler, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAuthenticateFlow(t *testing.T) {
	srv := testServer(t)
	rec := postJSON(t, srv.Handler(), "/v1/authenticate", map[string]string{
		"provider_id": "legacy", "evidence_kind": "API_CREDENTIAL",
		"credential": "k1:handler-secret", "requested_tenant_id": "tenant:acme",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var out struct {
		ContextToken    string                  `json:"context_token"`
		SecurityContext domain.SecurityContext `json:"security_context"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ContextToken == "" {
		t.Fatal("no context token issued")
	}
	if out.SecurityContext.TenantID != "tenant:acme" {
		t.Fatalf("tenant = %q", out.SecurityContext.TenantID)
	}
	// The issued token validates at the trust boundary.
	rec = postJSON(t, srv.Handler(), "/v1/security-context/validate", map[string]string{
		"context_token": out.ContextToken,
	}, nil)
	var vout struct {
		Valid bool `json:"valid"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &vout); err != nil || !vout.Valid {
		t.Fatalf("validate: %s / %v", rec.Body.String(), err)
	}
}

func TestAuthenticateNegative(t *testing.T) {
	srv := testServer(t)
	cases := []struct {
		name       string
		body       map[string]string
		wantStatus int
	}{
		{"wrong secret", map[string]string{"provider_id": "legacy", "evidence_kind": "API_CREDENTIAL", "credential": "k1:wrong"}, http.StatusUnauthorized},
		{"unknown provider", map[string]string{"provider_id": "ghost", "evidence_kind": "API_CREDENTIAL", "credential": "k1:handler-secret"}, http.StatusNotFound},
		{"unknown evidence", map[string]string{"provider_id": "legacy", "evidence_kind": "SAML_ASSERTION"}, http.StatusBadRequest},
		{"tenant mismatch", map[string]string{"provider_id": "legacy", "evidence_kind": "API_CREDENTIAL", "credential": "k1:handler-secret", "requested_tenant_id": "tenant:evil"}, http.StatusForbidden},
	}
	for _, tc := range cases {
		rec := postJSON(t, srv.Handler(), "/v1/authenticate", tc.body, nil)
		if rec.Code != tc.wantStatus {
			t.Errorf("%s: status = %d, want %d (%s)", tc.name, rec.Code, tc.wantStatus, rec.Body.String())
		}
	}
}

func TestHealth(t *testing.T) {
	srv := testServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("live = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready = %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestProviderAdminGated(t *testing.T) {
	srv := testServer(t)
	rec := postJSON(t, srv.Handler(), "/v1/providers", map[string]string{"id": "x", "type": "oidc"}, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("ungated admin: %d", rec.Code)
	}
	rec = postJSON(t, srv.Handler(), "/v1/providers", map[string]string{"id": "x", "type": "oidc"},
		map[string]string{"Authorization": "Bearer admin-token"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("admin create: %d (%s)", rec.Code, rec.Body.String())
	}
}
