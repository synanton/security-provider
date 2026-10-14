# ADR-003: Local-verification policy and revocation SLO

- Status: Proposed — pending Security Working Group ratification (Phase 0, joint-plan B0-4; joint-plan A-3/A-4)
- Date: 2026-10-14
- Deciders: Platform Architecture, Security Working Group (ratifies), Security 1.23 (owns the centralized-only list)

## Context

Proposal §9.1 permits local verification under four conditions; §11.2 sets provisional revocation SLO targets. Policy-as-convention drifts; policy-as-config can be validated in CI.

## Decision

Encode both as validated configuration (`internal/config` + `internal/policy`):

- Local verification requires: trusted-for-local issuer, permitted audience/scope, key cache within the bounded TTL, and a monitored revocation-signal channel.
- TTL bounds are hard ceilings validated at startup: high-risk ≤ `slo_local_high_risk` (default 5m), standard ≤ `slo_local_standard` (default 15m), identity cache ≤ `slo_local_standard`.
- Centralized-only operations default to `admin.*`, `tenant.*`, `delegation.activate`, `delegation.extend`, matched with `path.Match` semantics. The list content is owned by Security 1.23; this repo only consumes it.
- Revocation SLO defaults: centralized ≤ 60s, local high-risk ≤ 5m, local standard ≤ 15m, mTLS ≤ 15m — provisional until the platform SLO ratifies them.
- A stale revocation-signal channel fails closed; it never extends a TTL.

## Consequences

- Misconfigured TTLs are startup errors, not runtime drift (`TestValidateRejects`).
- The `RevocationSignal` port is the seam for push/pull revocation feeds; the OIDC adapter already consults it and treats signal outages as hard failures.
- CI verifies rotation under overlap (`TestOIDCKeyRotation`) and cache invalidation (`TestClientCachesSuccesses`) as proxies for the SLO until a staged timing harness exists (joint-plan risk 6).
