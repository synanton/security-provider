package authn

import (
	"context"
	"errors"
	"testing"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/port"
)

func workloadAdapter(t *testing.T) *WorkloadAdapter {
	t.Helper()
	a, err := NewWorkloadAdapter(config.ProviderConfig{ID: "test-workload", Type: "workload", TrustDomain: "synanton"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestWorkloadBareSPIFFEID(t *testing.T) {
	a := workloadAdapter(t)
	res, err := a.Authenticate(context.Background(), port.WorkloadEvidence{
		Assertion: "spiffe://synanton/ns/default/sa/ingestor",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if res.PrincipalType != domain.PrincipalWorkload {
		t.Fatalf("type = %v", res.PrincipalType)
	}
	if res.ExternalSubject != "spiffe://synanton/ns/default/sa/ingestor" {
		t.Fatalf("subject = %q", res.ExternalSubject)
	}
}

func TestWorkloadNegative(t *testing.T) {
	a := workloadAdapter(t)
	cases := []struct {
		name      string
		assertion string
		want      error
	}{
		{"empty", "", domain.ErrInvalidCredential},
		{"garbage", "not-an-assertion", domain.ErrInvalidCredential},
		{"foreign trust domain", "spiffe://evil.example/workload", domain.ErrUntrustedIssuer},
		{"non-spiffe JWT subject", "header.payload.signature", domain.ErrInvalidCredential},
	}
	for _, tc := range cases {
		_, err := a.Authenticate(context.Background(), port.WorkloadEvidence{Assertion: tc.assertion})
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestWorkloadNeverBecomesUser(t *testing.T) {
	a := workloadAdapter(t)
	res, err := a.Authenticate(context.Background(), port.WorkloadEvidence{
		Assertion: "spiffe://synanton/user-impersonation-attempt",
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.PrincipalType == domain.PrincipalUser {
		t.Fatal("workload assertion normalized to USER")
	}
}
