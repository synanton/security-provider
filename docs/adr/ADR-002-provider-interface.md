# ADR-002: Provider interface, principal types, assurance mapping

- Status: Accepted (Phase 0, joint-plan B0-2)
- Date: 2026-10-14
- Deciders: Platform Architecture, Identity 1.29 owners

## Context

Proposal §6.4 sketches a provider-neutral `AuthenticationProvider` interface. The implementation must freeze principal types, evidence kinds, and assurance semantics before adapters multiply.

## Decision

- **Principal types** are Identity 1.29's closed set: `USER`, `SERVICE`, `WORKLOAD`, `CONNECTOR`, `AGENT`. This service never invents values.
- **Evidence kinds** are a closed set: `OIDC_ACCESS_TOKEN`, `MTLS_PEER`, `WORKLOAD_ASSERTION`, `API_CREDENTIAL` (`internal/domain`). Adding one requires an ADR.
- **Interface** is `port.AuthenticationProvider`: `Authenticate(ctx, evidence) (AuthenticationResult, error)` + `Health(ctx) ProviderHealth`. The proposal's illustrative `Resolve` method lives on the `IdentityResolver` port instead, so no adapter can imply local mapping logic.
- **Assurance mapping:** mTLS/SPIFFE → HIGH, OIDC → MEDIUM, API key → LOW. Assurance travels in the context and is preserved, never upgraded, downstream.
- **Workload assertions never normalize to USER.** Service identity must not silently convert into user identity (tested in `TestWorkloadNeverBecomesUser`).

## Consequences

- Every adapter returns the same normalized shape; authorization stays out of adapters by construction.
- Identity 1.29's resolution wire shape (`resolutionRequest`/`resolutionResponse` in `internal/identity`) is the interim contract until the real API lands; `stub` mode serves fixtures and fails closed on unknown identities.
