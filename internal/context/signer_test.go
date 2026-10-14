package context

import (
	"context"
	"strings"
	"testing"
	"time"
)

func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	iss, err := NewIssuer([]byte("test-signing-key-at-least-32-bytes!!"), "test-issuer", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return iss
}

func TestIssueVerifyRoundtrip(t *testing.T) {
	iss := testIssuer(t)
	token, sc, err := iss.Issue(context.Background(), testResolution(), testAuthResult(), "trace-1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if token == "" {
		t.Fatal("empty token")
	}
	got, err := iss.Verify(context.Background(), token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.PrincipalID != sc.PrincipalID || got.TenantID != sc.TenantID {
		t.Fatalf("roundtrip mismatch: %+v vs %+v", got, sc)
	}
	if got.TraceID != "trace-1" {
		t.Fatalf("trace lost: %q", got.TraceID)
	}
}

func TestVerifyRejectsTampered(t *testing.T) {
	iss := testIssuer(t)
	token, _, err := iss.Issue(context.Background(), testResolution(), testAuthResult(), "")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	parts[2] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err := iss.Verify(context.Background(), strings.Join(parts, ".")); err == nil {
		t.Fatal("tampered signature accepted")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	iss := testIssuer(t)
	for _, bad := range []string{"", "a.b", "not-a-token", "a.b.c.d"} {
		if _, err := iss.Verify(context.Background(), bad); err == nil {
			t.Fatalf("garbage %q accepted", bad)
		}
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	iss := testIssuer(t)
	past := testAuthResult()
	past.AuthenticatedAt = time.Now().Add(-time.Hour)
	token, _, err := iss.Issue(context.Background(), testResolution(), past, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(context.Background(), token); err == nil {
		t.Fatal("expired context accepted")
	}
}

func TestVerifyRejectsMaskingClaims(t *testing.T) {
	iss := testIssuer(t)
	token, _, err := iss.Issue(context.Background(), testResolution(), testAuthResult(), "")
	if err != nil {
		t.Fatal(err)
	}
	// Splice a masking claim into the payload without re-signing: the
	// shape check must fire before signature verification matters.
	parts := strings.Split(token, ".")
	payload := parts[1]
	raw := decodeSegment(t, payload)
	raw = strings.TrimSuffix(raw, "}") + `,"masking":"redact"}`
	parts[1] = encodeSegment(raw)
	forged := strings.Join(parts, ".")
	if _, err := iss.Verify(context.Background(), forged); err == nil {
		t.Fatal("masking claim smuggled into context")
	}
	for _, field := range []string{"representation", "display_format", "classification_level", "redaction"} {
		raw2 := strings.TrimSuffix(decodeSegment(t, payload), "}") + `,"` + field + `":"x"}`
		parts[1] = encodeSegment(raw2)
		if _, err := iss.Verify(context.Background(), strings.Join(parts, ".")); err == nil {
			t.Fatalf("forbidden field %q smuggled into context", field)
		}
	}
}

func TestNewIssuerRejectsWeakKey(t *testing.T) {
	if _, err := NewIssuer([]byte("short"), "iss", time.Minute); err == nil {
		t.Fatal("weak signing key accepted")
	}
	if _, err := NewIssuer([]byte("test-signing-key-at-least-32-bytes!!"), "iss", time.Hour); err == nil {
		t.Fatal("over-long TTL accepted")
	}
}
