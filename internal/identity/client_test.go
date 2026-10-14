package identity

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/synanton/security-provider/internal/config"
	"github.com/synanton/security-provider/internal/domain"
)

func authResult(issuer, subject string) domain.AuthenticationResult {
	return domain.AuthenticationResult{
		ProviderID: "test-mtls", ExternalIssuer: issuer, ExternalSubject: subject,
		PrincipalType: domain.PrincipalWorkload, Assurance: domain.AssuranceHigh,
	}
}

func TestStubResolve(t *testing.T) {
	stub := NewStubResolver()
	stub.Add("ca", "spiffe://synanton/ingestor", domain.PrincipalResolution{
		PrincipalID: "service:ingestor", PrincipalType: domain.PrincipalService,
		TenantID: "tenant:acme", Active: true, IdentityRef: "ref-1",
	})
	res, err := stub.Resolve(context.Background(), authResult("ca", "spiffe://synanton/ingestor"), "tenant:acme")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.PrincipalID != "service:ingestor" || res.TenantID != "tenant:acme" {
		t.Fatalf("resolution = %+v", res)
	}
}

func TestStubNegative(t *testing.T) {
	stub := NewStubResolver()
	stub.Add("ca", "known", domain.PrincipalResolution{PrincipalID: "s:known", PrincipalType: domain.PrincipalService, TenantID: "tenant:acme", Active: true})
	stub.Add("ca", "ambiguous", domain.PrincipalResolution{Ambiguous: true})
	stub.Add("ca", "disabled", domain.PrincipalResolution{PrincipalID: "s:off", PrincipalType: domain.PrincipalService, TenantID: "tenant:acme", Active: false})
	cases := []struct {
		name    string
		subject string
		tenant  string
		want    error
	}{
		{"unknown", "ghost", "", domain.ErrPrincipalUnknown},
		{"ambiguous", "ambiguous", "", domain.ErrPrincipalAmbiguous},
		{"disabled", "disabled", "", domain.ErrPrincipalDisabled},
		{"tenant mismatch", "known", "tenant:other", domain.ErrTenantDenied},
	}
	for _, tc := range cases {
		if _, err := stub.Resolve(context.Background(), authResult("ca", tc.subject), tc.tenant); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestClientCachesSuccesses(t *testing.T) {
	c := NewClient(config.IdentityConfig{Mode: "stub", Timeout: time.Second, CacheTTL: time.Minute})
	c.stub.Add("ca", "w", domain.PrincipalResolution{PrincipalID: "s:w", PrincipalType: domain.PrincipalService, TenantID: "tenant:acme", Active: true})
	first, err := c.Resolve(context.Background(), authResult("ca", "w"), "")
	if err != nil {
		t.Fatal(err)
	}
	// Remove the fixture: a cached success must still resolve inside TTL.
	c.stub = NewStubResolver()
	second, err := c.Resolve(context.Background(), authResult("ca", "w"), "")
	if err != nil {
		t.Fatalf("cached resolve: %v", err)
	}
	if first.PrincipalID != second.PrincipalID {
		t.Fatal("cache returned different resolution")
	}
	// Invalidate drops the entry; the stub is now empty so it fails closed.
	c.Invalidate(authResult("ca", "w"), "")
	if _, err := c.Resolve(context.Background(), authResult("ca", "w"), ""); !errors.Is(err, domain.ErrPrincipalUnknown) {
		t.Fatalf("post-invalidate: got %v", err)
	}
}

func TestCacheExpiry(t *testing.T) {
	c := newCache(0)
	c.set("k", domain.PrincipalResolution{PrincipalID: "s:x"})
	if _, ok := c.get("k"); ok {
		t.Fatal("zero-TTL entry must expire immediately")
	}
}
