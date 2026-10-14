package authn

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
	"github.com/synanton/security-provider/internal/testcert"
)

func mtlsAdapter(t *testing.T, ca *testcert.CA, patterns ...string) *MTLSAdapter {
	t.Helper()
	a, err := NewMTLSAdapter(config.ProviderConfig{
		ID: "test-mtls", Type: "mtls",
		TrustBundle: ca.BundleFile(t), AllowedSANPatterns: patterns,
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestMTLSValidSPIFFE(t *testing.T) {
	ca := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/*")
	leaf := ca.Leaf(t, testcert.LeafOptions{URIs: []string{"spiffe://synanton/ingestor"}})
	res, err := a.Authenticate(context.Background(), port.TLSEvidence{State: tlsState(t, ca, leaf)})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.ExternalSubject != "spiffe://synanton/ingestor" {
		t.Fatalf("subject = %q", res.ExternalSubject)
	}
	if res.PrincipalType != domain.PrincipalWorkload {
		t.Fatalf("principal type = %v", res.PrincipalType)
	}
	if res.Assurance != domain.AssuranceHigh {
		t.Fatalf("assurance = %v", res.Assurance)
	}
}

func TestMTLSSANMismatchFailsClosed(t *testing.T) {
	ca := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/ingestor")
	leaf := ca.Leaf(t, testcert.LeafOptions{URIs: []string{"spiffe://synanton/other"}})
	if _, err := a.Authenticate(context.Background(), port.TLSEvidence{State: tlsState(t, ca, leaf)}); !errors.Is(err, domain.ErrUntrustedIssuer) {
		t.Fatalf("SAN mismatch: got %v", err)
	}
}

func TestMTLSExpiredCertFailsClosed(t *testing.T) {
	ca := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/*")
	leaf := ca.Leaf(t, testcert.LeafOptions{
		URIs:     []string{"spiffe://synanton/ingestor"},
		NotAfter: time.Now().Add(-time.Minute),
	})
	if _, err := a.Authenticate(context.Background(), port.TLSEvidence{State: tlsState(t, ca, leaf)}); err == nil {
		t.Fatal("expired certificate accepted")
	}
}

func TestMTLSUnknownCAFailsClosed(t *testing.T) {
	ca := testcert.NewCA(t)
	other := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/*")
	leaf := other.Leaf(t, testcert.LeafOptions{URIs: []string{"spiffe://synanton/ingestor"}})
	if _, err := a.Authenticate(context.Background(), port.TLSEvidence{State: tlsState(t, other, leaf)}); !errors.Is(err, domain.ErrUntrustedIssuer) {
		t.Fatalf("unknown CA: got %v", err)
	}
}

func TestMTLSNoPeerCertFailsClosed(t *testing.T) {
	ca := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/*")
	if _, err := a.Authenticate(context.Background(), port.TLSEvidence{}); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("missing peer: got %v", err)
	}
}

func TestMTLSWrongEvidenceKind(t *testing.T) {
	ca := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/*")
	ev := port.TokenEvidence{EvidenceKind: domain.EvidenceOIDCAccessToken, Token: "x"}
	if _, err := a.Authenticate(context.Background(), ev); !errors.Is(err, domain.ErrInvalidCredential) {
		t.Fatalf("wrong evidence: got %v", err)
	}
}

func TestMTLSHealth(t *testing.T) {
	ca := testcert.NewCA(t)
	a := mtlsAdapter(t, ca, "spiffe://synanton/*")
	h := a.Health(context.Background())
	if !h.Healthy || h.ProviderID != "test-mtls" {
		t.Fatalf("health = %+v", h)
	}
}
