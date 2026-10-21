# security-provider

> Spec-first Go implementation of the Synanton Security Provider — the authentication boundary and identity-context producer for the platform.

[![Go Version](https://img.shields.io/badge/go-1.23+-00ADD8?logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#status)

`security-provider` validates authentication evidence (OIDC/OAuth 2.0 tokens, mTLS peer certificates, workload assertions, and constrained API credentials), resolves the result to a canonical Synanton principal through Identity 1.29, and produces a trusted, minimal **internal security context** for downstream services. Tenant-bound browser access-token issuance is a separate planned capability ([platform #340](https://github.com/synanton/platform/issues/340); [repo #3](https://github.com/synanton/security-provider/issues/3)), not an implemented feature.

It exists so that every Synanton service — Platform API, Content Cache, AI Runtime, Eventing/Workflow, and domain services — does not reimplement authentication integrations, trust policy, or principal resolution.

**Authentication never implies authorization. Classification is not authorization. Masking is a representation transformation.**

---

## Status

**Pre-alpha.** Under active development. Not production-ready. See [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) for the phased plan and [`CONTRIBUTING.md`](CONTRIBUTING.md) for the acceptance gates.

*State reviewed 2026-10-21 — Phase 1 (joint-plan B1) is implemented: mTLS + workload + OIDC + API-key adapters, stub Identity 1.29 resolution with bounded cache, signed internal contexts, HTTP + gRPC surfaces, importable middleware; unit and HTTP integration tests are green. Content-service D.1 handshake evidence is linked in the table. This is not production identity/token-issuer acceptance.*

### Maturity

| Area | Implemented | Unit/integration tested | Conformance-validated | Benchmark-validated |
|---|---|---|---|---|
| Domain core (evidence kinds, context shape, policy) | ✅ | ✅ | ✅ (no-masking invariant) | ⬜ |
| mTLS adapter (trust bundle, SAN allowlist, SPIFFE IDs) | ✅ | ✅ (unit + `integration` tag) | ⬜ | ⬜ |
| Workload adapter (SPIFFE assertions, trust domain) | ✅ | ✅ | ⬜ | ⬜ |
| OIDC adapter (JWKS, audience/scope, rotation, revocation hook) | ✅ | ✅ (in-test IdP) | ⬜ | ⬜ |
| API-key adapter (verifier hashes, scope, expiry, revocation) | ✅ | ✅ | ⬜ | ⬜ |
| Identity 1.29 client (stub + bounded cache, fail-closed) | ✅ | ✅ | ⬜ | ⬜ |
| HTTP surface (authenticate, resolve, validate, providers, health) | ✅ | ✅ (contract tests) | ⬜ | ⬜ |
| gRPC surface (`SecurityProviderService`) | ✅ | ✅ (bufconn) | ⬜ | ⬜ |
| Consumer middleware (`pkg/middleware`, HTTP + gRPC) | ✅ | ✅ | ⬜ | ⬜ |
| Content-service handshake (D.1, in consuming repo) | ✅ | ✅ (content-service PR #14: mTLS transport + middleware validation + rejection battery, unit + testcontainers) | ⬜ | ⬜ |
| Tenant-bound browser access-token issuer (asymmetric key/JWKS, `/v1/auth/tenant`; #340, repo #3) | ⬜ | ⬜ | ⬜ | ⬜ |
| Production Identity 1.29 endpoint (mode `http`) | ⬜ (stub default) | ⬜ | ⬜ | ⬜ |
| Helm chart / production rollout | ⬜ | ⬜ | ⬜ | ⬜ |

`⬜` = not yet; nothing in this table is claimed before its evidence exists.

Explicitly out of scope for v0.1.0: tenant-bound browser token issuance (#340, repo #3); production Identity 1.29 wiring (blocked on the real resolution API — the stub is the documented interim per the joint-plan risk register); OAuth token exchange/delegation flows; Helm chart; dashboards. The issuer and production Identity rows remain outstanding, not implemented. Other ⬜ rows are deferred by decision, not pending by oversight.

---

## What It Is

`security-provider` sits between untrusted credential presentations and every Synanton service. It solves a problem domain services handle poorly: **one consistent authentication boundary with provider-neutral trust policy**, without coupling each service to a specific IdP, CA, or workload identity system.

It targets service-to-service workload authentication first (Phase 1), then external/user federation (Phase 2).

### What this service is

- A single, consistent authentication boundary for Synanton services.
- A provider-neutral adapter layer over external IdPs and workload identity systems.
- A consumer of Identity 1.29's principal-resolution contract.
- A producer of a verifiable security context that downstream services can trust.

### What this service is not

- ❌ It is not a replacement for Identity 1.29. Canonical principals, external identity mappings, tenant membership, delegation, and identity lifecycle remain owned by Identity.
- ❌ It is not an authorization engine. Authorization, classification-aware access, and masking remain owned by Security 1.23.
- ❌ It is not a password store, user-registration system, or universal IAM product.
- ❌ It does not own representation or masking decisions. The security context contains no masking fields.
- ❌ It does not implement custom cryptographic protocols or token formats.

### Authority map

| Concern | Owner | This service's role |
|---|---|---|
| Canonical principals, principal types | Identity 1.29 | Consumer |
| External identity mappings, collision/linking | Identity 1.29 | Consumer (fails closed on ambiguity) |
| Tenant membership, identity lifecycle | Identity 1.29 | Consumer |
| Delegation relationships, actor chains | Identity 1.29 | Consumer |
| Identity context contract | Identity 1.29 | Producer of validated instances |
| Authorization decisions | Security 1.23 | None |
| Classification, masking, representation | Security 1.23 | None |
| External API surface | Platform API 1.32 | Internal only unless exposed via 1.32 |
| Async propagation contract | Eventing/Workflow 1.27 | Consumer / Producer per 1.27 |

---

## Why Go

- **Single static binary** — millisecond startup, tiny container images, no JVM and none of its operational overhead
- **Standard-library TLS** — `crypto/tls` + `crypto/x509` cover the mTLS core with no extra trust surface
- **Mature identity ecosystem** — `lestrrat-go/jwx` (JOSE/JWKS), `coreos/go-oidc` (federation), `go-spiffe` (workload identity), `grpc` (internal RPC)
- **Sibling-stack consistency** — same toolchain, layout, and conventions as `content-service` and `equalix-go`, so `pkg/middleware` drops into consumers cleanly

Rust is the only alternative worth evaluating if the organization has strong existing Rust capability and a specific latency requirement; for the vast majority of Synanton deployments, Go is the correct default. See [`docs/adr/ADR-001-deployment-shape.md`](docs/adr/ADR-001-deployment-shape.md).

---

## Architecture

Hexagonal (ports and adapters):

```text
┌─────────────────────────────────────────────────┐
│             cmd/security-provider               │
│          (wiring + HTTP/gRPC + TLS)             │
└───────────────────────┬─────────────────────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
│  REST + gRPC │ │  Metrics    │ │   Health    │
│   adapters   │ │(Prometheus) │ │(live/ready) │
└───────┬──────┘ └──────┬──────┘ └──────┬──────┘
        │               │               │
        └───────────────┼───────────────┘
                        │
                ┌───────▼────────┐
                │  Authn core    │
                │  (adapters +   │
                │  trust policy) │
                └───────┬────────┘
                        │
        ┌───────────────┼───────────────┐
        │               │               │
┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
│ External IdP │ │ Workload CA │ │ Identity    │
│ (OIDC/JWKS)  │ │ (mTLS/SPIFFE│ │ 1.29 (stub/ │
│              │ │  + API keys) │ │  http)      │
└──────────────┘ └─────────────┘ └─────────────┘
```

The domain package is pure Go: no `net/http`, no `crypto/tls` server behavior, no JWKS fetching. Adapters depend on ports. `pkg/middleware` is the importable consumer surface (joint-plan B1-3).

See [`docs/architecture.md`](docs/architecture.md) for details.

---

## Quick Start

### Prerequisites

- Go 1.23+
- `buf` + `protoc-gen-go` + `protoc-gen-go-grpc` (only for `make proto`)
- Docker + Docker Compose (for the local stack)
- A development OIDC provider and/or workload CA (dev certs via `make certs`)

### Build

```bash
git clone https://github.com/synanton/security-provider.git
cd security-provider
go build -o bin/security-provider ./cmd/security-provider
```

### Run with Docker Compose

```bash
SECURITY_PROVIDER_SIGNING_KEY=$(head -c 48 /dev/urandom | base64) make docker-up
curl http://localhost:8080/health/live
curl http://localhost:8080/health/ready
```

Dev mTLS material lives in `./certs/` (gitignored, generated by `make certs`); production mounts real certificates from the secret store. Host ports are overridable: `APP_PORT`, `GRPC_PORT`.

### Minimal Configuration

```yaml
server:
  http_addr: ":8080"
  grpc_addr: ":9090"
  context_ttl: 5m

identity:
  mode: stub # http in production (Identity 1.29 resolution API)
  timeout: 2s
  cache_ttl: 30s

providers:
  - id: synanton-workload-ca
    type: mtls
    trust_bundle: /certs/client-ca.crt
    allowed_san_patterns: ["spiffe://synanton/*"]
```

Env vars (`SECURITY_PROVIDER_*`) override file keys. See `configs/dev.yaml`, `configs/local.yaml`, and [`docs/runbook.md`](docs/runbook.md) for the full reference.

---

## API

The endpoints below are a candidate **internal** contract. They are not committed to public exposure. Any external surface must go through Platform API 1.32's contract, versioning, and compatibility CI. The same contract is served over gRPC (`security.v1.SecurityProviderService`, default `:9090`, server reflection enabled) — see [`docs/api.md`](docs/api.md) and `proto/security/v1/security.proto`.

| Method | Endpoint | Purpose |
| ------ | -------- | ------- |
| `POST` | `/v1/authenticate` | Validate a supported credential exchange |
| `POST` | `/v1/identity/resolve` | Thin adapter over Identity 1.29's resolution API |
| `POST` | `/v1/security-context/validate` | Validate a signed internal context at a trust boundary |
| `GET` | `/v1/providers` | Administrative view of configured providers |
| `POST` | `/v1/providers` | Register provider configuration (privileged) |
| `PATCH` | `/v1/providers/{id}` | Rotate/update trust config or disable a provider |
| `GET` | `/health/live` | Process liveness |
| `GET` | `/health/ready` | Readiness including trust/config dependencies |

Provider administration is restricted to platform operators and fully audited. No endpoint reveals tokens, private keys, or credential material.

### Authenticate with an API credential

```bash
curl -X POST http://localhost:8080/v1/authenticate \
  -H "Content-Type: application/json" \
  -d '{"provider_id":"legacy-crm","evidence_kind":"API_CREDENTIAL",
       "credential":"key-id:secret","requested_tenant_id":"tenant:acme"}'
```

Response: `200 OK` with the signed `context_token` and the `security_context`.

### Authenticate an mTLS workload

```bash
curl --cert ./certs/workload.crt --key ./certs/workload.key \
  --cacert ./certs/ca.crt \
  -X POST https://security-provider.internal/v1/authenticate \
  -H "Content-Type: application/json" \
  -d '{"provider_id":"synanton-workload-ca","evidence_kind":"MTLS_PEER"}'
```

The peer certificate is read from the TLS handshake. A credential body on an mTLS request is rejected, not trusted.

### Validate a security context

```bash
curl -X POST https://security-provider.internal/v1/security-context/validate \
  -H "Content-Type: application/json" \
  -d @security-context.json
```

### Security context

Downstream services receive a minimal context. It contains no masking directives, no representation selections, and no classification-derived output shaping — those are applied by Security 1.23 enforcement points.

```json
{
  "principal_id": "service:content-ingestor",
  "principal_type": "SERVICE",
  "tenant_id": "tenant:acme",
  "authentication": {
    "method": "MTLS",
    "provider_id": "synanton-workload-ca",
    "assurance_level": "HIGH",
    "authenticated_at": "2026-10-14T10:00:00Z",
    "expires_at": "2026-10-14T10:05:00Z"
  },
  "delegation": {
    "initiated_by": "user:01example",
    "delegated_by": "service:platform-api"
  },
  "trace_id": "trace-example"
}
```

### Propagation rules

- Prefer authenticated RPC context and mTLS for direct internal calls.
- Use signed, short-lived assertions or token exchange across trust boundaries.
- Preserve initiator, delegator, executor, tenant, assurance, and trace context across async boundaries.
- Treat broker metadata and event payloads as untrusted unless provenance and integrity are verified.
- Never infer authority from free-form content, agent prompts, or unsigned `X-User-ID` / `X-Tenant-ID` headers.
- Do not silently convert service identity into user identity. Delegation must be explicit and audited.

---

## Content-service integration

`pkg/middleware` is the D.1 handshake surface: content-service imports it and validates contexts with no sidecar and no per-request network hop on the common path. The tenant is always derived from the validated context; `X-Tenant-ID` is cross-checked and rejected on mismatch.

```go
import "github.com/synanton/security-provider/pkg/middleware"

verifier := &middleware.HMACVerifier{Key: key, ExpectedIssuer: "synanton-security-provider"}

mux.Handle("/api/v1/artifacts", middleware.RequireAuth(verifier)(handler))

// Inside the handler: the ONLY legitimate tenant source.
tenant, err := middleware.TenantIDFromContext(r.Context())
```

gRPC consumers use `middleware.UnaryServerInterceptor(verifier)` and `middleware.UnaryClientInterceptor(middleware.StaticTokenSource(token))`. See [`docs/api.md`](docs/api.md#consumer-middleware) and the joint-plan milestones D.1–D.2.

---

## Security

Security-provider verifies identities and issues an internal signed context.
Tenant-bound access-token issuance is the approved target tracked by #340 and
security-provider #3; it is not implemented. The shared model is in
[synanton/platform docs/security/security-model.md](https://github.com/synanton/platform/blob/main/docs/security/security-model.md).

### Current state (validator/facade)

- **External OIDC validation.** Fetches provider JWKS; validates signature,
  `iss`, `aud`, `exp`, `nbf`. — **Implemented**
- **Identity resolution.** Calls Identity 1.29 for `PrincipalResolution`.
  `requested_tenant_id` is an **untrusted hint**; the resolved tenant comes
  from Identity 1.29. — **Implemented**
- **Internal context token.** HS256, audience `synanton-internal`, TTL ≤ 15m,
  service-to-service only. **Not client-holdable.** — **Implemented**
- **Service-to-service auth.** mTLS/SPIFFE for service principals; constrained
  API keys for lower-tier service access. — **Implemented**
- **Audit.** `AuditSink` for authentication and resolution events. —
  **Implemented**
- **HTTP surface.** `/v1/authenticate`, `/v1/identity/resolve`,
  `/v1/security-context/validate`, provider admin, health. **No
  `/v1/auth/tenant`.** — **Current state**

### Target state (tenant-bound issuer, #340; implementation not started)

- **New signing domain.** Tenant-bound tokens use RS256/ES256 with a published
  JWKS; rotation 90 days with 24-hour overlap; audience restricted to
  SPA-facing services. **The HS256 internal key is never published.** —
  **Design fixed** (Phase 1 not started)
- **`TokenIssuer` port** and **`POST /v1/auth/tenant`** (ADR 0007). —
  **Design fixed**
- **Claim schema.** `iss`, `aud`, `sub`, `exp`, `nbf`, `jti`, `scope`,
  `tenant_id`, `token_type=tenant_access`. — **Design fixed**
- **Revocation.** `jti` denylist plus per-identity token version; membership
  re-checked on refresh and on high-risk operations (writes, exports, admin).
  — **Design fixed**
- **Audit.** Issuance, selection, denial, and revocation events via
  `AuditSink`. — **Design fixed**
- **`TenantId` domain type and `TenantResolver`.** Reads `authorizedTenantIds`
  from Identity 1.29; falls back to `[tenant_id]` when the set field is empty
  (pre-#341). — **Design fixed**

### Boundaries to preserve

- `requested_tenant_id` remains an **untrusted hint** even when the service
  issues tokens. The tenant that gets bound is the one validated against
  Identity 1.29, not the one in the request.
- The internal `context_token` (HS256) and the tenant-bound token
  (RS256/ES256) are **separate signing domains** with separate key material.
  The internal key is never exposed via JWKS.
- Uniform 404 on selection outside the authorized set — the anti-oracle rule
  applies at issuance, not only at request time.

### What it does not own

- The set-shaped identity model — Identity 1.29 [#341]
- Data-layer enforcement — platform [#339]
- Client-side token storage and per-tab isolation — UI [ADR 0006]

### References

- UI ADR 0007 — token claim schema and error matrix
- [#340](https://github.com/synanton/platform/issues/340) — issuer ownership (Path A)
- [#341](https://github.com/synanton/platform/issues/341) — Identity 1.29 set-shaped resolution
- [#339](https://github.com/synanton/platform/issues/339) — data-layer enforcement
- This repo's [#3](https://github.com/synanton/security-provider/issues/3) — repo-anchored issuance tracker

## Configuration Reference

| Key | Default | Description |
| --- | ------- | ----------- |
| `SECURITY_PROVIDER_HTTP_ADDR` | `:8080` | HTTP listen address |
| `SECURITY_PROVIDER_GRPC_ADDR` | `:9090` | gRPC listen address |
| `SECURITY_PROVIDER_TLS_CERT` / `SECURITY_PROVIDER_TLS_KEY` | — (plain HTTP) | Server TLS certificate (dev only without them) |
| `SECURITY_PROVIDER_CLIENT_CA` | — | Client CA bundle; enables mTLS verification |
| `SECURITY_PROVIDER_SIGNING_KEY` | — (required) | Context-signing key, min 32 bytes |
| `SECURITY_PROVIDER_ADMIN_TOKEN` | — (admin disabled) | Bearer token for provider administration |
| `SECURITY_PROVIDER_IDENTITY_ENDPOINT` | `https://identity.internal:8443` | Identity 1.29 resolution endpoint |
| `SECURITY_PROVIDER_IDENTITY_MODE` | `stub` | `stub` (dev/test fixtures) \| `http` (production API) |
| `SECURITY_PROVIDER_LOCAL_VERIFICATION_ENABLED` | `true` | Local JWKS verification path (§9.1) |
| `SECURITY_PROVIDER_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `SECURITY_PROVIDER_AUDIT_SINK` | `stdout` | `stdout` \| `discard` |

File keys live under `server`, `identity`, `providers`, `local_verification`, `revocation`, `audit`. See `configs/local.yaml` and [`docs/runbook.md`](docs/runbook.md).

### Local verification policy (§9.1)

Local verification is permitted only when the issuer is trusted for it, audience/scope are within the permitted set, the key set is cached within a bounded TTL (≤ 5m high-risk, ≤ 15m standard), and a revocation-signal channel is fresh. `admin.*`, `tenant.*`, `delegation.activate`, and `delegation.extend` always use centralized validation. TTL bounds are enforced by config validation, not convention.

### Revocation SLO (§11.2, provisional)

| Path | Target |
|---|---|
| Centralized validation | ≤ 60 seconds |
| Local verification, high-risk issuer | ≤ 5 minutes |
| Local verification, standard issuer | ≤ 15 minutes |
| mTLS peer certificate | ≤ 15 minutes |

---

## Observability

### Endpoints

- `GET /health/live` — liveness (200 while serving)
- `GET /health/ready` — readiness (trust bundles parseable, providers healthy; 503 otherwise)
- `GET /metrics` — Prometheus metrics

### Metrics (Prometheus)

Wire names are canonical per proposal §12; the sole source is `internal/observability`:

- `security_provider_auth_attempts_total{mechanism,outcome}`
- `security_provider_token_failures_total{reason}`, `security_provider_cert_failures_total{reason}`
- `security_provider_resolution_failures_total{reason}`, `security_provider_tenant_denials_total`
- `security_provider_context_failures_total{reason}`
- `security_provider_revocation_latency_seconds` (histogram, measured against the SLO)
- `security_provider_auth_latency_seconds{mechanism}` (histogram)
- `security_provider_verifier_key_age_seconds{provider}` (local-verifier cache age)
- `security_provider_up{provider}` (1 healthy, 0 unhealthy)

### Logging

Structured JSON logs via `log/slog`. Audit events (`security.audit`) carry the allowlisted field set only: timestamp, type, provider, principal, tenant, outcome, reason, trace. Raw credentials, complete tokens, private keys, and sensitive payloads are never logged.

---

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup, workflow, gates, and review checklists.

Common commands:

```bash
make test              # unit tests
make test-integration  # mTLS end-to-end (httptest, no Docker needed)
make vet               # go vet
make lint              # golangci-lint
make proto             # regenerate gRPC stubs (only when .proto changes)
make certs             # dev-only mTLS material into ./certs/
```

Adding a new authentication provider:

1. Implement the `AuthenticationProvider` interface in `internal/authn/`.
2. Add configuration schema and validation in `internal/config`.
3. Add functional, security, and resilience tests.
4. Add an ADR describing the trust model, evidence kind, and failure behavior.
5. Update this README's supported mechanisms table.

---

## Roadmap

See [`docs/IMPLEMENTATION.md`](docs/IMPLEMENTATION.md) for the phased plan and the current milestone (joint-plan Track B).

- Phase 0 — Contract and threat model (ADRs published, threat model in review)
- Phase 1 — Workload authentication: mTLS, stub resolution, middleware, signed contexts (**implemented**)
- Phase 2 — OAuth/OIDC federation hardening; local-verification policy enforcement (adapter implemented, production IdP wiring open)
- Phase 3 — Platform integration (1.32, 1.29, 1.23, 1.27, 1.26, 1.30)
- Phase 4 — Production readiness (load, fault injection, review)

---

## Documentation

Developer documentation is built from `docs/` with mdBook on every merge.
The original service proposal is retained as historical context; the
implementation and accepted ADRs now govern what this repository actually
provides:

- **Using** — HTTP and gRPC API reference, operator runbook
- **Architecture** — architecture overview, implementation design, threat model
- **Developing** — implementation guide and plan, ADRs

The [documentation inventory](docs/DOCUMENTATION-INVENTORY.md) records
canonical sources, historical decisions, and current status dispositions.

Key references:

- Synanton Platform Architecture 1.0
- Synanton Design 1.23 — Security and classification-aware access
- Synanton Design 1.26 — Content Cache
- Synanton Design 1.27 — Eventing and Workflow
- Synanton Design 1.29 — Identity, federation, tenant membership, and delegation
- Synanton Design 1.30 — AI Runtime
- Synanton Design 1.32 — Platform API
- Synanton Design 1.33 — Kubernetes lifecycle
- Security Provider Service Proposal (`docs/proposal.md`)
- Joint plan: Content Service & Security Provider, v0.1 (adoption criteria AC-1..AC-5, milestones D.1–D.5)

---

## Contributing

Contributions welcome. Please read [`CONTRIBUTING.md`](CONTRIBUTING.md) before opening a PR.

1. Fork the repository
2. Create a feature branch (`git checkout -b SEC-my-change`)
3. Add tests for new behavior
4. Ensure `make test` and `go vet ./...` pass
5. Submit a pull request (merging is manual — a maintainer merges after review)

---

## License

Apache License 2.0. See [LICENSE](LICENSE).
