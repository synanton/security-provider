# Implementation Plan

Phased delivery plan for `security-provider` (Track B of the Content Service & Security Provider joint plan, v0.1). The joint plan owns cross-repo sequencing and adoption criteria AC-1..AC-5; this document owns in-repo tasks and definitions of done.

## Guiding principles

- **Contracts before code.** No Phase 1 work proceeds until Platform API 1.32 and Eventing/Workflow 1.27 are frozen (gate G0, owned by Platform Architecture).
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

Gate B0: all B0 tasks complete; G0 passed.

Status: B0-2, B0-3, B0-4 drafted as ADRs; B0-1, B0-5 in review.

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

## What to Do Today

1. Close B0-1 (boundary sign-off) and B0-5 (threat-model approval) — both block the Phase 1 gate review.
2. Wire B2-5: point one OIDC provider at a dev IdP and run the staged rotation test.
3. Drive milestone D.1 from the content-service side: import `pkg/middleware` in a test harness with an mTLS peer.
4. Keep the README maturity table and this file in sync on every phase transition.

## Per-phase done criteria

A phase is done when every task row has a linked evidence artifact, `make test test-integration` pass with `-race` clean, new behavior is covered by ADRs where trust is touched, and the README freshness line names the transition.
