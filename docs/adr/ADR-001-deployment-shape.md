# ADR-001: Deployment shape — service plus importable middleware

- Status: Accepted (Phase 0, joint-plan B0-3)
- Date: 2026-10-14
- Deciders: Platform Architecture, Security Working Group

## Context

The proposal (§15 Phase 0, §16 item 1) asks whether the first release is a standalone service, shared library, sidecar, or hybrid, with one hard constraint: avoid a network hop for every token verification where local validation is safe and sufficient.

## Decision

Ship a hybrid:

1. **Provider-control/resolution service** (`cmd/security-provider`): owns provider configuration, trust material, Identity 1.29 resolution, signed-context issuance, and audit. Served over HTTP + gRPC, internal only.
2. **Importable verification middleware** (`pkg/middleware`): HTTP middleware + gRPC interceptors that consumers (first: content-service) embed. Common-path validation is local (bounded-TTL key set, revocation-signal freshness); high-risk operations call the service.

No sidecar in Phase 1: a sidecar adds deployment topology without changing the trust math, and the middleware already removes the per-request hop.

## Consequences

- `pkg/middleware` must stay dependency-light (stdlib + jwx + grpc) so consumers adopt it without a dependency cliff.
- The context schema is a cross-repo contract: changes require a versioned migration, not a quiet field addition.
- Centralized-only operations (§9.1) always take path 1 regardless of middleware capability.
