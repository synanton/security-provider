# Design

Normative behavior of the Security Provider implementation. The service proposal (`docs/proposal.md`) is the architecture authority; this document pins the implementation's frozen contracts. Any behavior change here requires an ADR first.

## Evidence kinds (closed set)

`OIDC_ACCESS_TOKEN`, `MTLS_PEER`, `WORKLOAD_ASSERTION`, `API_CREDENTIAL` (`internal/domain.EvidenceKind`). Adding a kind requires an ADR, config schema, and positive + negative tests.

## Provider adapters

| Type | Evidence | Trust anchor | Assurance | Principal mapping |
|---|---|---|---|---|
| `mtls` | TLS peer (handshake only) | Trust bundle + SAN allowlist (empty allowlist denies all) | HIGH | SPIFFE ID → WORKLOAD, else SERVICE |
| `oidc` | Bearer JWT | Issuer + audience + allowed algs + JWKS (bounded TTL) + required scopes | MEDIUM | USER via Identity 1.29 |
| `workload` | SPIFFE ID or JWT-SVID | Configured trust domain | HIGH | WORKLOAD (never USER) |
| `apikey` | `key-id:secret` | SHA-256 verifier file, expiry, revocation flag | LOW | Configured type (default CONNECTOR) |

Token validation enforces issuer, audience, signature + permitted algorithm (never `none`), expiry, not-before (60s skew), subject, and required scopes — in that order, so reason codes are stable. JWKS fetch or discovery failures fail closed (`DEPENDENCY_OUTAGE`).

## Security context schema (frozen)

`principal_id`, `principal_type` (USER/SERVICE/WORKLOAD/CONNECTOR/AGENT), `tenant_id`, `authentication{method, provider_id, assurance_level, authenticated_at, expires_at}`, optional `delegation{initiated_by, delegated_by}`, optional `trace_id`. Signed JWT, TTL ≤ 15m (config-validated). Payloads containing `mask*`, `represent*`, `display*`, `classification*`, or `redact*` claims are rejected before signature verification, on both the server (`internal/context`) and consumer (`pkg/middleware`) sides.

## Trust policy (§9.1 / §11.2 as configuration)

- Identity cache TTL ≤ `slo_local_standard`; key TTLs: high-risk ≤ `slo_local_high_risk`, standard ≤ `slo_local_standard` — all enforced in `Config.Validate()`.
- Centralized-only operations default to `admin.*`, `tenant.*`, `delegation.activate`, `delegation.extend` (owned semantically by Security 1.23).
- Only successful resolutions are cached; failures never are. `Invalidate` drops entries on disablement/policy change.

## Tenant rule

The tenant is derived from the validated context. Caller-supplied hints are cross-checked (`CheckTenantHint`): absent is fine, mismatched is `CONFLICTING_TENANT`/`403`. Unsigned identity headers are never authoritative.

## Config

YAML file + `SECURITY_PROVIDER_*` environment overrides, `Load()` then `Validate()`, fail fast before listeners bind. See `configs/local.yaml` and `docs/runbook.md`.
