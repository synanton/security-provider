package context

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/synanton/security-provider/internal/domain"
)

func testResolution() domain.PrincipalResolution {
	return domain.PrincipalResolution{
		PrincipalID:   "service:content-ingestor",
		PrincipalType: domain.PrincipalService,
		TenantID:      "tenant:acme",
		Active:        true,
	}
}

func testAuthResult() domain.AuthenticationResult {
	return domain.AuthenticationResult{
		ProviderID:      "test-ca",
		ExternalIssuer:  "test-ca",
		ExternalSubject: "spiffe://synanton/ingestor",
		PrincipalType:   domain.PrincipalService,
		Assurance:       domain.AssuranceHigh,
		Method:          domain.MethodMTLS,
		AuthenticatedAt: time.Now(),
		EvidenceKind:    domain.EvidenceMTLSPeer,
	}
}

func decodeSegment(t *testing.T, seg string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func encodeSegment(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
