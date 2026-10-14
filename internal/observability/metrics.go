// Package observability exposes the Prometheus metrics of the Security
// Provider. Metric names are the canonical vocabulary of proposal §12;
// this package is their sole source. Labels never carry credential
// material, tokens, subjects, or tenant free text beyond bounded IDs.
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics is the service metric set.
type Metrics struct {
	AuthAttempts      *prometheus.CounterVec
	TokenFailures     *prometheus.CounterVec
	CertFailures      *prometheus.CounterVec
	ResolutionFailure *prometheus.CounterVec
	TenantDenials     prometheus.Counter
	ContextFailures   *prometheus.CounterVec
	RevocationLatency prometheus.Histogram
	AuthLatency       *prometheus.HistogramVec
	VerifierKeyAge    *prometheus.GaugeVec
	ProviderUp        *prometheus.GaugeVec
}

// New builds and registers the metric set on reg (or the default
// registry when reg is nil).
func New(reg *prometheus.Registry) *Metrics {
	f := promauto.With(reg)
	return &Metrics{
		AuthAttempts: f.NewCounterVec(prometheus.CounterOpts{
			Name: "security_provider_auth_attempts_total",
			Help: "Authentication attempts by mechanism and outcome.",
		}, []string{"mechanism", "outcome"}),
		TokenFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "security_provider_token_failures_total",
			Help: "Token validation failures by reason.",
		}, []string{"reason"}),
		CertFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "security_provider_cert_failures_total",
			Help: "Certificate validation failures by reason.",
		}, []string{"reason"}),
		ResolutionFailure: f.NewCounterVec(prometheus.CounterOpts{
			Name: "security_provider_resolution_failures_total",
			Help: "Principal-resolution failures by reason.",
		}, []string{"reason"}),
		TenantDenials: f.NewCounter(prometheus.CounterOpts{
			Name: "security_provider_tenant_denials_total",
			Help: "Tenant-membership denials.",
		}),
		ContextFailures: f.NewCounterVec(prometheus.CounterOpts{
			Name: "security_provider_context_failures_total",
			Help: "Security-context validation failures by reason.",
		}, []string{"reason"}),
		RevocationLatency: f.NewHistogram(prometheus.HistogramOpts{
			Name:    "security_provider_revocation_latency_seconds",
			Help:    "Revocation propagation latency against the SLO.",
			Buckets: prometheus.ExponentialBuckets(1, 2, 10),
		}),
		AuthLatency: f.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "security_provider_auth_latency_seconds",
			Help:    "Authentication latency by mechanism.",
			Buckets: prometheus.DefBuckets,
		}, []string{"mechanism"}),
		VerifierKeyAge: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "security_provider_verifier_key_age_seconds",
			Help: "Local-verifier cache age by provider.",
		}, []string{"provider"}),
		ProviderUp: f.NewGaugeVec(prometheus.GaugeOpts{
			Name: "security_provider_up",
			Help: "Provider health (1 healthy, 0 unhealthy).",
		}, []string{"provider"}),
	}
}
