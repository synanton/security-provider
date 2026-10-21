# Implementation Plan

Phased delivery plan for `security-provider` (Track B of the Content Service & Security Provider joint plan, v0.1). The joint plan owns cross-repo sequencing and adoption criteria AC-1..AC-5; this document owns in-repo tasks and definitions of done.

## Guiding principles

- **Contracts before dependent integration.** New cross-plane work follows Platform API 1.32 and Eventing/Workflow 1.27 gates (G0, owned by Platform Architecture). The implemented Phase 1 workload-authentication slice predates the pending 1.27 freeze and is not evidence that the dependent platform integration gates have passed.
- **Evidence before claims.** Every milestone exit requires a reproducible artifact (test, benchmark, runbook, signed report). The README maturity table is evidence-gated.
- **Fail closed by default.** Negative tests are release gates, not optional coverage.
- **Narrow first slice.** mTLS workload identity first; OIDC federation after B1 is stable.

## Phase 0 — Contract and threat model

| ID | Task | Exit criterion |
|---|---|---|
| B0-1 | Confirm boundaries with Identity 1.29 and Security 1.23 owners | Signed review note in `docs/adr/` |
| B0-2 | Define principal types, provider interface, assurance mapping | Interface frozen; ADR-002 published |
| B0-3 | Decide deployment shape (service + middleware hybrid) | ADR-001 published |
| B0-4 | Record §9.1 and §11.2 policies as ADRs | ADR-003 published |
| B0-5 | Threat model review | `docs/threat-model.md` approved by security reviewer |

Gate B0 requires all B0 tasks complete; **G0 has not passed**. The current Phase 1 code is an implemented pre-alpha slice, not evidence that the formal B0/G0 or production acceptance gates are complete.

Status reviewed 2026-10-21: B0-2 and B0-3 have accepted ADRs; B0-4 remains proposed; B0-1 boundary sign-off and B0-5 threat-model approval remain open. Phase 1 implementation proceeded before formal gate closure; that chronology does not waive G0.

## Phase 1 — mTLS workload identity (implemented)

| ID | Task | Exit criterion | Evidence |
|---|---|---|---|
| B1-1 | mTLS/workload identity adapter | Unit + negative tests (SAN mismatch, expired cert, unknown CA) | `internal/authn/mtls_test.go` |
| B1-2 | Identity 1.29 resolution client with bounded cache | Cache TTL configurable; fail-closed on outage | `internal/identity/client_test.go` |
| B1-3 | Shared Go middleware for HTTP and gRPC consumers | Importable by content-service; documented | `pkg/middleware/`, `docs/api.md` |
| B1-4 | Security context build/sign/validate | Schema frozen; signature verified in tests | `internal/context/signer_test.go` |
| B1-5 | Rotation, revocation, audit, negative tests | Revocation path verified (mock signal) | `internal/authn/oidc_test.go` |
| B1-6 | Health and readiness endpoints | Liveness/readiness separated; readiness reflects trust deps | `internal/adapter/http/handler_test.go` |

Gate B1: service-to-service calls authenticate correctly; caller cannot spoof principal or tenant; middleware importable and documented; revocation path verified.

Additionally delivered ahead of plan: OIDC adapter (Phase 2 scope) implemented with in-test IdP coverage, and the gRPC surface with bufconn tests.

## Phase 2 — OAuth/OIDC federation (adapter done, production wiring open)

| ID | Task | Exit criterion |
|---|---|---|
| B2-1 | Provider-neutral issuer config + token validation | Positive/negative token tests (done) |
| B2-2 | JWKS refresh, audience/scope checks, rotation test | Rotation test passes (done) |
| B2-3 | Deferral to Identity 1.29 for mapping/linking/collision | Ambiguous identity fails closed (done, stub-backed) |
| B2-4 | Local-verification policy with enforced TTL | TTL enforced by config validation + policy tests (done) |
| B2-5 | Production IdP wiring (real issuer, discovery, revocation channel) | Staged integration test against dev IdP |

Gate B2: external identities resolve deterministically via Identity 1.29; invalid tokens fail closed; local verification honors the revocation SLO.

## Phase 3 — Platform integration (open)

| ID | Task | Exit criterion |
|---|---|---|
| B3-1 | Integrate with Platform API 1.32 and Identity 1.29 context contract | Contract tests pass |
| B3-2 | Integrate with Security 1.23 enforcement points | No masking/representation fields in context (invariant holds) |
| B3-3 | Propagate identity and delegation through Eventing/Workflow 1.27 | Async propagation test passes |
| B3-4 | Validate Content Cache 1.26 and AI Runtime 1.30 integration | One flow tested per consumer (D.4) |

## Phase 4 — Production readiness (open)

| ID | Task | Exit criterion |
|---|---|---|
| B4-1 | Load and fault-injection tests | Published results |
| B4-2 | Dashboards, alerts, runbooks, SLOs | Runbooks reviewed by on-call |
| B4-3 | Independent security review | Signed approval |
| B4-4 | Staged rollout | Rollout plan approved |

## Current follow-ups (reviewed 2026-10-21)

1. Tenant-bound access-token issuance (asymmetric keys/JWKS, `/v1/auth/tenant`, revocation and audit) remains unimplemented; track it in [security-provider #3](https://github.com/synanton/security-provider/issues/3) and platform [#340](https://github.com/synanton/platform/issues/340).
2. Production Identity 1.29 resolution and real-issuer acceptance remain open; the current Identity client default is the stub.
3. Platform-wide tenant data-layer enforcement belongs to [platform #339](https://github.com/synanton/platform/issues/339), not this repository's demo/middleware tests.
4. The README maturity table and this plan remain the status sources for their respective scope; update both when evidence changes.

## Per-phase done criteria

A phase is done when every task row has a linked evidence artifact, `make test test-integration` pass with `-race` clean, new behavior is covered by ADRs where trust is touched, and the README freshness line names the transition.
