package middleware

import (
	"net/http"
	"strings"
)

// AuditEvent is the consumer-side audit hook payload for auth decisions.
type AuditEvent struct {
	Outcome    string
	ReasonCode string
	TenantID   string
	TraceID    string
}

// Option tunes RequireAuth.
type Option func(*options)

type options struct {
	audit         func(AuditEvent)
	tenantHeaders []string
}

// WithAudit registers an audit hook for allow/deny decisions.
func WithAudit(fn func(AuditEvent)) Option {
	return func(o *options) { o.audit = fn }
}

// WithTenantHeaders adds extra headers treated as tenant hints and
// cross-checked against the context tenant (default: X-Tenant-ID).
func WithTenantHeaders(headers ...string) Option {
	return func(o *options) { o.tenantHeaders = append(o.tenantHeaders, headers...) }
}

// RequireAuth validates the Bearer security-context token, derives the
// tenant from it, and rejects forged tenant hints and unsigned identity
// headers. Validated context is injected into the request context for
// TenantIDFromContext / SecurityContextFrom downstream.
func RequireAuth(v Verifier, opts ...Option) func(http.Handler) http.Handler {
	o := &options{tenantHeaders: []string{"X-Tenant-ID"}}
	for _, opt := range opts {
		opt(o)
	}
	emit := func(ev AuditEvent) {
		if o.audit != nil {
			o.audit(ev)
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := bearerOf(r.Header.Get("Authorization"))
			sc, err := v.Verify(r.Context(), token)
			if err != nil {
				emit(AuditEvent{Outcome: "denied", ReasonCode: reasonOf(err)})
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := WithSecurityContext(r.Context(), sc)
			for _, h := range o.tenantHeaders {
				if hint := r.Header.Get(h); hint != "" {
					if err := CheckTenantHint(ctx, hint); err != nil {
						emit(AuditEvent{Outcome: "denied", ReasonCode: "CONFLICTING_TENANT", TenantID: sc.TenantID})
						http.Error(w, "forbidden", http.StatusForbidden)
						return
					}
				}
			}
			if q := r.URL.Query().Get("tenant_id"); q != "" {
				if err := CheckTenantHint(ctx, q); err != nil {
					emit(AuditEvent{Outcome: "denied", ReasonCode: "CONFLICTING_TENANT", TenantID: sc.TenantID})
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
			}
			if userHdr := r.Header.Get("X-User-ID"); userHdr != "" && userHdr != sc.PrincipalID {
				// An unsigned user header that disagrees with the
				// validated principal is never honored.
				emit(AuditEvent{Outcome: "denied", ReasonCode: "UNSIGNED_IDENTITY", TenantID: sc.TenantID})
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			emit(AuditEvent{Outcome: "allowed", ReasonCode: "OK", TenantID: sc.TenantID, TraceID: sc.TraceID})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearerOf(header string) string {
	if header == "" {
		return ""
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func reasonOf(err error) string {
	switch err {
	case ErrMissingContext:
		return "MISSING_CONTEXT"
	case ErrExpiredContext:
		return "EXPIRED"
	default:
		return "INVALID_CONTEXT"
	}
}
