// Package http adapts the Security Provider to net/http. Routing uses the
// standard library ServeMux with method patterns (Go 1.22+), matching the
// content-service convention; see docs/adr/ADR-004 for the chi decision.
//
// The endpoints are a candidate internal contract. None is public: any
// external surface must go through Platform API 1.32.
package http

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/synanton/security-provider/internal/audit"
	"github.com/synanton/security-provider/internal/authn"
	ctxpkg "github.com/synanton/security-provider/internal/context"
	"github.com/synanton/security-provider/internal/domain"
	"github.com/synanton/security-provider/internal/identity"
	"github.com/synanton/security-provider/internal/observability"
	"github.com/synanton/security-provider/internal/port"
)

// Server wires providers, resolution, context issuance, and audit to HTTP.
type Server struct {
	registry *authn.Registry
	resolver *identity.Client
	issuer   *ctxpkg.Issuer
	auditor  port.AuditSink
	metrics  *observability.Metrics
	adminToken string
	providerAdmin *ProviderAdmin
	log      *slog.Logger
}

// New builds a Server.
func New(
	registry *authn.Registry,
	resolver *identity.Client,
	issuer *ctxpkg.Issuer,
	auditor port.AuditSink,
	metrics *observability.Metrics,
	adminToken string,
	log *slog.Logger,
) *Server {
	return &Server{
		registry: registry, resolver: resolver, issuer: issuer,
		auditor: auditor, metrics: metrics, adminToken: adminToken,
		providerAdmin: NewProviderAdmin(), log: log,
	}
}

// Handler returns the full route tree.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/authenticate", s.handleAuthenticate)
	mux.HandleFunc("POST /v1/identity/resolve", s.handleResolve)
	mux.HandleFunc("POST /v1/security-context/validate", s.handleValidateContext)
	mux.HandleFunc("GET /v1/providers", s.handleListProviders)
	mux.HandleFunc("POST /v1/providers", s.handleRegisterProvider)
	mux.HandleFunc("PATCH /v1/providers/{id}", s.handlePatchProvider)
	mux.HandleFunc("GET /health/live", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

type authenticateRequest struct {
	ProviderID       string `json:"provider_id"`
	EvidenceKind     string `json:"evidence_kind"`
	Credential       string `json:"credential,omitempty"`
	RequestedTenant  string `json:"requested_tenant_id,omitempty"`
	TraceID          string `json:"trace_id,omitempty"`
}

type authenticateResponse struct {
	ContextToken    string                  `json:"context_token"`
	SecurityContext domain.SecurityContext `json:"security_context"`
}

func (s *Server) handleAuthenticate(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req authenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "undecodable request")
		return
	}
	kind := domain.EvidenceKind(req.EvidenceKind)
	if !kind.Valid() {
		writeError(w, http.StatusBadRequest, "UNKNOWN_EVIDENCE_KIND", "unknown evidence kind")
		return
	}
	provider, ok := s.registry.Get(req.ProviderID)
	if !ok {
		s.recordAuth(req, "unknown-provider", "failure", audit.ReasonUnknownProvider, start)
		writeError(w, http.StatusNotFound, audit.ReasonUnknownProvider, "unknown provider")
		return
	}
	evidence, err := evidenceFromRequest(r, req, kind)
	if err != nil {
		s.recordAuth(req, provider.ID(), "failure", audit.ReasonOK, start)
		writeError(w, http.StatusBadRequest, "BAD_EVIDENCE", err.Error())
		return
	}
	result, err := provider.Authenticate(r.Context(), evidence)
	if err != nil {
		reason := reasonFor(err)
		s.recordAuth(req, provider.ID(), "failure", reason, start)
		s.metrics.AuthAttempts.WithLabelValues(string(kind), "failure").Inc()
		writeError(w, statusFor(err), reason, "authentication failed")
		return
	}
	resolution, err := s.resolver.Resolve(r.Context(), result, req.RequestedTenant)
	if err != nil {
		reason := reasonFor(err)
		s.recordAuth(req, provider.ID(), "failure", reason, start)
		s.metrics.ResolutionFailure.WithLabelValues(reason).Inc()
		writeError(w, statusFor(err), reason, "principal resolution failed")
		return
	}
	token, sc, err := s.issuer.Issue(r.Context(), resolution, result, req.TraceID)
	if err != nil {
		s.recordAuth(req, provider.ID(), "failure", audit.ReasonOK, start)
		writeError(w, http.StatusInternalServerError, "CONTEXT_ISSUE_FAILED", "could not issue context")
		return
	}
	s.recordAuth(req, provider.ID(), "success", audit.ReasonOK, start)
	s.metrics.AuthAttempts.WithLabelValues(string(kind), "success").Inc()
	s.metrics.AuthLatency.WithLabelValues(string(kind)).Observe(time.Since(start).Seconds())
	writeJSON(w, http.StatusOK, authenticateResponse{ContextToken: token, SecurityContext: sc})
}

// evidenceFromRequest builds server-side evidence. mTLS peers come from
// the TLS handshake only; a credential body on an mTLS request is
// rejected rather than trusted.
func evidenceFromRequest(r *http.Request, req authenticateRequest, kind domain.EvidenceKind) (port.Evidence, error) {
	switch kind {
	case domain.EvidenceMTLSPeer:
		if req.Credential != "" {
			return nil, fmt.Errorf("credential body not accepted for mTLS evidence")
		}
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, fmt.Errorf("no TLS peer certificate on connection")
		}
		return port.TLSEvidence{State: *r.TLS, RequestedTenant: req.RequestedTenant, TraceID: req.TraceID}, nil
	case domain.EvidenceWorkload:
		return port.WorkloadEvidence{Assertion: req.Credential, RequestedTenant: req.RequestedTenant, TraceID: req.TraceID}, nil
	default:
		return port.TokenEvidence{EvidenceKind: kind, Token: req.Credential, RequestedTenant: req.RequestedTenant, TraceID: req.TraceID}, nil
	}
}

type resolveRequest struct {
	ProviderID      string `json:"provider_id"`
	ExternalIssuer  string `json:"external_issuer"`
	ExternalSubject string `json:"external_subject"`
	PrincipalType   string `json:"principal_type"`
	RequestedTenant string `json:"requested_tenant_id,omitempty"`
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	var req resolveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "undecodable request")
		return
	}
	pt := domain.PrincipalType(req.PrincipalType)
	if !pt.Valid() {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "unknown principal type")
		return
	}
	res, err := s.resolver.Resolve(r.Context(), domain.AuthenticationResult{
		ProviderID: req.ProviderID, ExternalIssuer: req.ExternalIssuer,
		ExternalSubject: req.ExternalSubject, PrincipalType: pt,
	}, req.RequestedTenant)
	if err != nil {
		writeError(w, statusFor(err), reasonFor(err), "resolution failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

type validateContextRequest struct {
	ContextToken string `json:"context_token"`
}

func (s *Server) handleValidateContext(w http.ResponseWriter, r *http.Request) {
	var req validateContextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ContextToken == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "context_token is required")
		return
	}
	sc, err := s.issuer.Verify(r.Context(), req.ContextToken)
	if err != nil {
		reason := reasonFor(err)
		s.metrics.ContextFailures.WithLabelValues(reason).Inc()
		writeJSON(w, http.StatusOK, map[string]any{"valid": false, "reason_code": reason})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"valid": true, "security_context": sc})
}

func (s *Server) handleLive(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "live"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	unhealthy := []string{}
	for _, h := range s.registry.Health(ctx) {
		s.metrics.ProviderUp.WithLabelValues(h.ProviderID).Set(boolToFloat(h.Healthy))
		if !h.Healthy {
			unhealthy = append(unhealthy, h.ProviderID)
		}
	}
	if len(unhealthy) > 0 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not-ready", "providers": unhealthy})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func boolToFloat(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// recordAuth emits the audit event for one authentication attempt. The
// credential itself is never included.
func (s *Server) recordAuth(req authenticateRequest, providerID, outcome, reason string, start time.Time) {
	_ = start
	s.auditor.Record(context.Background(), port.AuditEvent{
		Type: "authentication", ProviderID: providerID,
		TenantID: req.RequestedTenant, Outcome: outcome,
		ReasonCode: reason, TraceID: req.TraceID,
	})
}

func reasonFor(err error) string {
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

func statusFor(err error) int {
	switch {
	case errors.Is(err, domain.ErrDependencyOutage):
		return http.StatusBadGateway
	case errors.Is(err, domain.ErrTenantDenied),
		errors.Is(err, domain.ErrPrincipalDisabled),
		errors.Is(err, domain.ErrPrincipalAmbiguous):
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
}

// requireAdmin gates provider administration to platform operators. The
// token scheme is provisional until Platform API 1.32 defines the
// external admin surface.
func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			writeError(w, http.StatusForbidden, "ADMIN_DISABLED", "provider administration is disabled")
			return
		}
		got := r.Header.Get("Authorization")
		want := "Bearer " + s.adminToken
		if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			s.auditor.Record(r.Context(), port.AuditEvent{Type: "provider_admin", Outcome: "denied", ReasonCode: "FORBIDDEN"})
			writeError(w, http.StatusForbidden, "FORBIDDEN", "forbidden")
			return
		}
		next(w, r)
	}
}
