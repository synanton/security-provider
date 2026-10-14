// Package grpc adapts the Security Provider to gRPC for internal
// platform RPC. The contract is proto/security/v1/security.proto; stubs
// are regenerated with `make proto`. This surface is internal only.
package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	securityv1 "github.com/synanton/security-provider/gen/security/v1"
	"github.com/synanton/security-provider/internal/audit"
	"github.com/synanton/security-provider/internal/authn"
	ctxpkg "github.com/synanton/security-provider/internal/context"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/identity"
	"github.com/synanton/security-provider/internal/port"
)

// Server implements SecurityProviderServiceServer.
type Server struct {
	securityv1.UnimplementedSecurityProviderServiceServer
	registry *authn.Registry
	resolver *identity.Client
	issuer   *ctxpkg.Issuer
	auditor  port.AuditSink
}

// New builds a Server.
func New(
	registry *authn.Registry,
	resolver *identity.Client,
	issuer *ctxpkg.Issuer,
	auditor port.AuditSink,
) *Server {
	return &Server{registry: registry, resolver: resolver, issuer: issuer, auditor: auditor}
}

// Authenticate implements SecurityProviderServiceServer. mTLS peers are
// taken from the gRPC transport credentials, never from the request.
func (s *Server) Authenticate(ctx context.Context, req *securityv1.AuthenticateRequest) (*securityv1.AuthenticateResponse, error) {
	provider, ok := s.registry.Get(req.GetProviderId())
	if !ok {
		return nil, status.Error(codes.NotFound, audit.ReasonUnknownProvider)
	}
	// Only token-carrying evidence kinds cross gRPC; mTLS and workload
	// assertions arrive on their own transports.
	kind := toDomainKind(req.GetEvidenceKind())
	evidence := port.TokenEvidence{
		EvidenceKind: kind, Token: req.GetCredential(),
		RequestedTenant: req.GetRequestedTenantId(), TraceID: req.GetTraceId(),
	}
	result, err := provider.Authenticate(ctx, evidence)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, reasonOf(err))
	}
	resolution, err := s.resolver.Resolve(ctx, result, req.GetRequestedTenantId())
	if err != nil {
		return nil, status.Error(codes.PermissionDenied, reasonOf(err))
	}
	token, sc, err := s.issuer.Issue(ctx, resolution, result, req.GetTraceId())
	if err != nil {
		return nil, status.Error(codes.Internal, "could not issue context")
	}
	return &securityv1.AuthenticateResponse{
		ContextToken:    token,
		SecurityContext: toProto(sc),
	}, nil
}

// ValidateContext implements SecurityProviderServiceServer.
func (s *Server) ValidateContext(ctx context.Context, req *securityv1.ValidateContextRequest) (*securityv1.ValidateContextResponse, error) {
	sc, err := s.issuer.Verify(ctx, req.GetContextToken())
	if err != nil {
		return &securityv1.ValidateContextResponse{Valid: false, ReasonCode: reasonOf(err)}, nil
	}
	return &securityv1.ValidateContextResponse{Valid: true, SecurityContext: toProto(sc)}, nil
}

func toDomainKind(k securityv1.EvidenceKind) domain.EvidenceKind {
	switch k {
	case securityv1.EvidenceKind_EVIDENCE_KIND_OIDC_ACCESS_TOKEN:
		return domain.EvidenceOIDCAccessToken
	case securityv1.EvidenceKind_EVIDENCE_KIND_API_CREDENTIAL:
		return domain.EvidenceAPICredential
	default:
		return domain.EvidenceKind("UNSUPPORTED")
	}
}

func toProto(sc domain.SecurityContext) *securityv1.SecurityContextProto {
	out := &securityv1.SecurityContextProto{
		PrincipalId:     sc.PrincipalID,
		PrincipalType:   string(sc.PrincipalType),
		TenantId:        sc.TenantID,
		AuthMethod:      string(sc.Authentication.Method),
		ProviderId:      sc.Authentication.ProviderID,
		AssuranceLevel:  string(sc.Authentication.AssuranceLevel),
		AuthenticatedAt: sc.Authentication.AuthenticatedAt.Format("2006-01-02T15:04:05Z07:00"),
		ExpiresAt:       sc.Authentication.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
		TraceId:         sc.TraceID,
	}
	if sc.Delegation != nil {
		out.InitiatedBy = sc.Delegation.InitiatedBy
		out.DelegatedBy = sc.Delegation.DelegatedBy
	}
	return out
}

func reasonOf(err error) string {
	switch {
	case errors.Is(err, domain.ErrUntrustedIssuer):
		return audit.ReasonUntrustedIssuer
	case errors.Is(err, domain.ErrAudienceMismatch):
		return audit.ReasonAudienceMismatch
	case errors.Is(err, domain.ErrUnsupportedAlg):
		return audit.ReasonUnsupportedAlg
	case errors.Is(err, domain.ErrCredentialExpired):
		return audit.ReasonExpired
	case errors.Is(err, domain.ErrCredentialNotYet):
		return audit.ReasonNotYetValid
	case errors.Is(err, domain.ErrRevokedCredential):
		return audit.ReasonRevoked
	case errors.Is(err, domain.ErrPrincipalUnknown):
		return audit.ReasonUnknownPrincipal
	case errors.Is(err, domain.ErrPrincipalAmbiguous):
		return audit.ReasonAmbiguousPrincipal
	case errors.Is(err, domain.ErrPrincipalDisabled):
		return audit.ReasonDisabledPrincipal
	case errors.Is(err, domain.ErrTenantDenied):
		return audit.ReasonTenantDenied
	case errors.Is(err, domain.ErrDependencyOutage):
		return audit.ReasonDependencyOutage
	default:
		return "AUTH_FAILED"
	}
}
