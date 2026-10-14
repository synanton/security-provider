package policy

import (
	"testing"
	"time"

	"github.com/synanton/security-provider/internal/config"
)

func testPolicy() *Policy {
	return New(config.LocalVerifyConfig{
		Enabled:                 true,
		TTLHighRisk:             5 * time.Minute,
		TTLStandard:             15 * time.Minute,
		CentralizedOnlyPatterns: []string{"admin.*", "tenant.*", "delegation.activate", "delegation.extend"},
	})
}

func TestRequiresCentralized(t *testing.T) {
	p := testPolicy()
	cases := []struct {
		op   string
		want bool
	}{
		{"admin.rotate-key", true},
		{"tenant.assign", true},
		{"delegation.activate", true},
		{"delegation.extend", true},
		{"content.read", false},
		{"content.write", false},
		{"admin", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := p.RequiresCentralized(tc.op); got != tc.want {
			t.Errorf("RequiresCentralized(%q) = %v, want %v", tc.op, got, tc.want)
		}
	}
}

func TestSelectVerifier(t *testing.T) {
	p := testPolicy()
	if got := p.SelectVerifier("content.read", true); got != VerifierLocal {
		t.Errorf("ordinary op should allow local verification, got %v", got)
	}
	if got := p.SelectVerifier("admin.rotate-key", true); got != VerifierCentralized {
		t.Errorf("admin op must use centralized validation, got %v", got)
	}
	if got := p.SelectVerifier("content.read", false); got != VerifierCentralized {
		t.Errorf("disabled local verification must centralize, got %v", got)
	}
	off := New(config.LocalVerifyConfig{Enabled: false, TTLHighRisk: time.Minute, TTLStandard: time.Minute})
	if got := off.SelectVerifier("content.read", true); got != VerifierCentralized {
		t.Errorf("policy-disabled local verification must centralize, got %v", got)
	}
}

func TestMaxKeyAge(t *testing.T) {
	p := testPolicy()
	if got := p.MaxKeyAge(true); got != 5*time.Minute {
		t.Errorf("high-risk TTL = %v", got)
	}
	if got := p.MaxKeyAge(false); got != 15*time.Minute {
		t.Errorf("standard TTL = %v", got)
	}
}
