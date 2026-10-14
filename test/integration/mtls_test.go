//go:build integration

// Package integration exercises the Security Provider end to end without
// Docker: a real TLS handshake with client certificates, the HTTP
// surface, stub Identity 1.29 resolution, and the consumer middleware.
// Run with: make test-integration
package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/synanton/security-provider/internal/audit"
	"github.com/synanton/security-provider/internal/authn"
	"github.com/synanton/security-provider/internal/config"
	ctxpkg "github.com/synanton/security-provider/internal/context"
	"github.com/synanton/security-provider/internal/domain"
	httphandler "github.com/synanton/security-provider/internal/adapter/http"
	"github.com/synanton/security-provider/internal/identity"
	"github.com/synanton/security-provider/internal/observability"
	"github.com/synanton/security-provider/internal/testcert"
	"github.com/synanton/security-provider/pkg/middleware"
)

func stack(t *testing.T, ca *testcert.CA) (http.Handler, *middleware.HMACVerifier) {
	t.Helper()
	provider, err := authn.NewMTLSAdapter(config.ProviderConfig{
		ID: "workload-ca", Type: "mtls",
		TrustBundle: ca.BundleFile(t), AllowedSANPatterns: []string{"spiffe://synanton/*"},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry := authn.NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	resolver := identity.NewClient(config.IdentityConfig{Mode: "stub", Timeout: time.Second, CacheTTL: time.Minute})
	// The stub key is the issuing CA common name (see testcert.NewCA).
	resolver.AddStubMapping("test-ca", "spiffe://synanton/ingestor", domain.PrincipalResolution{
		PrincipalID: "service:content-ingestor", PrincipalType: domain.PrincipalService,
		TenantID: "tenant:acme", Active: true, IdentityRef: "ref-it",
	})
	key := []byte("integration-signing-key-at-least-32B!")
	issuer, err := ctxpkg.NewIssuer(key, "synanton-security-provider", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	srv := httphandler.New(registry, resolver, issuer, audit.Discard{}, observability.New(prometheus.NewRegistry()), "", slog.Default())
	return srv.Handler(), &middleware.HMACVerifier{Key: key, ExpectedIssuer: "synanton-security-provider"}
}

func mtlsServer(t *testing.T, h http.Handler, ca *testcert.CA, serverCert tls.Certificate) *httptest.Server {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func mtlsClient(t *testing.T, ca *testcert.CA, clientCert tls.Certificate) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.PEM)
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{clientCert},
	}}}
}

func authenticate(t *testing.T, client *http.Client, url string) (string, domain.SecurityContext) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"provider_id": "workload-ca", "evidence_kind": "MTLS_PEER",
		"requested_tenant_id": "tenant:acme",
	})
	resp, err := client.Post(url+"/v1/authenticate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticate status = %d", resp.StatusCode)
	}
	var out struct {
		ContextToken    string                  `json:"context_token"`
		SecurityContext domain.SecurityContext `json:"security_context"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.ContextToken, out.SecurityContext
}

// TestMTLSEndToEnd is the Phase 1 vertical slice: mTLS workload identity
// in, validated security context out, middleware handshake green.
func TestMTLSEndToEnd(t *testing.T) {
	ca := testcert.NewCA(t)
	h, verifier := stack(t, ca)
	serverCert := ca.Leaf(t, testcert.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	srv := mtlsServer(t, h, ca, serverCert)

	clientCert := ca.Leaf(t, testcert.LeafOptions{URIs: []string{"spiffe://synanton/ingestor"}})
	token, sc := authenticate(t, mtlsClient(t, ca, clientCert), srv.URL)
	if sc.TenantID != "tenant:acme" || sc.PrincipalID != "service:content-ingestor" {
		t.Fatalf("context = %+v", sc)
	}
	got, err := verifier.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("middleware verify: %v", err)
	}
	if got.TenantID != "tenant:acme" {
		t.Fatalf("middleware tenant = %q", got.TenantID)
	}
}

// TestMTLSUnknownWorkloadFailsClosed proves an unallowlisted workload
// cannot authenticate even with a CA-signed certificate.
func TestMTLSUnknownWorkloadFailsClosed(t *testing.T) {
	ca := testcert.NewCA(t)
	h, _ := stack(t, ca)
	serverCert := ca.Leaf(t, testcert.LeafOptions{IPs: []net.IP{net.ParseIP("127.0.0.1")}})
	srv := mtlsServer(t, h, ca, serverCert)

	intruder := ca.Leaf(t, testcert.LeafOptions{URIs: []string{"spiffe://synanton/intruder"}})
	body, _ := json.Marshal(map[string]string{
		"provider_id": "workload-ca", "evidence_kind": "MTLS_PEER",
	})
	resp, err := mtlsClient(t, ca, intruder).Post(srv.URL+"/v1/authenticate", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("unallowlisted workload authenticated")
	}
}
