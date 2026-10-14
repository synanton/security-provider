package grpc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	securityv1 "github.com/synanton/security-provider/gen/security/v1"
	"github.com/synanton/security-provider/internal/audit"
	"github.com/synanton/security-provider/internal/authn"
	"github.com/synanton/security-provider/internal/config"
	ctxpkg "github.com/synanton/security-provider/internal/context"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/identity"
	"github.com/synanton/security-provider/internal/observability"
)

func testServer(t *testing.T) securityv1.SecurityProviderServiceClient {
	t.Helper()
	sum := sha256.Sum256([]byte("grpc-secret"))
	credPath := filepath.Join(t.TempDir(), "keys.yaml")
	yaml := "keys:\n  - id: k1\n    verifier: \"" + hex.EncodeToString(sum[:]) + "\"\n" +
		"    principal: connector:crm\n    principal_type: CONNECTOR\n    tenant_id: tenant:acme\n" +
		"    expires_at: 2030-01-01T00:00:00Z\n"
	if err := os.WriteFile(credPath, []byte(yaml), 0600); err != nil {
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
		TenantID: "tenant:acme", Active: true,
	})
	issuer, err := ctxpkg.NewIssuer([]byte("grpc-signing-key-at-least-32-bytes!"), "synanton-security-provider", 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	securityv1.RegisterSecurityProviderServiceServer(srv, New(registry, resolver, issuer, audit.Discard{}))
	_ = observability.New
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return securityv1.NewSecurityProviderServiceClient(conn)
}

func TestGRPCAuthenticateAndValidate(t *testing.T) {
	client := testServer(t)
	ctx := context.Background()
	resp, err := client.Authenticate(ctx, &securityv1.AuthenticateRequest{
		ProviderId: "legacy",
		EvidenceKind: securityv1.EvidenceKind_EVIDENCE_KIND_API_CREDENTIAL,
		Credential: "k1:grpc-secret", RequestedTenantId: "tenant:acme",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if resp.GetContextToken() == "" {
		t.Fatal("no context token")
	}
	if resp.GetSecurityContext().GetTenantId() != "tenant:acme" {
		t.Fatalf("tenant = %q", resp.GetSecurityContext().GetTenantId())
	}
	vresp, err := client.ValidateContext(ctx, &securityv1.ValidateContextRequest{ContextToken: resp.GetContextToken()})
	if err != nil || !vresp.GetValid() {
		t.Fatalf("ValidateContext: valid=%v err=%v", vresp.GetValid(), err)
	}
	bad, err := client.ValidateContext(ctx, &securityv1.ValidateContextRequest{ContextToken: "garbage"})
	if err != nil || bad.GetValid() {
		t.Fatalf("forged context validated: %v %v", bad.GetValid(), err)
	}
	if _, err := client.Authenticate(ctx, &securityv1.AuthenticateRequest{
		ProviderId: "legacy",
		EvidenceKind: securityv1.EvidenceKind_EVIDENCE_KIND_API_CREDENTIAL,
		Credential: "k1:wrong",
	}); err == nil {
		t.Fatal("wrong secret authenticated")
	}
}
