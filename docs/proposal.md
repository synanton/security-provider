# Synanton Security Provider Service Proposal

| | |
|---|---|
| Document type | Architecture proposal |
| Status | Proposed — for architecture review |
| Version | 0.2 |
| Date | 2026-10-14 |
| Scope | Synanton Platform 1.0; Identity Design 1.29; Security Design 1.23; Platform API 1.32; Eventing/Workflow 1.27 |
| Proposed service name | `security-provider` |
| Suggested repository | `synanton/security-provider` (subject to repository naming conventions) |

## Contents

- [1. Executive summary](#1-executive-summary)
- [2. Context and architectural alignment](#2-context-and-architectural-alignment)
- [3. Goals](#3-goals)
- [4. Non-goals](#4-non-goals)
- [5. Proposed architecture](#5-proposed-architecture)
- [6. Authentication mechanisms](#6-authentication-mechanisms)
- [7. Canonical security context](#7-canonical-security-context)
- [8. Authorization boundary](#8-authorization-boundary)
- [9. Conceptual API](#9-conceptual-api)
- [10. Data ownership and persistence](#10-data-ownership-and-persistence)
- [11. Security and failure requirements](#11-security-and-failure-requirements)
- [12. Observability and audit](#12-observability-and-audit)
- [13. Deployment and operations](#13-deployment-and-operations)
- [14. Testing strategy and acceptance criteria](#14-testing-strategy-and-acceptance-criteria)
- [15. Delivery plan](#15-delivery-plan)
- [16. Decisions required](#16-decisions-required)
- [17. Recommendation](#17-recommendation)
- [References](#references)

---

## 1. Executive summary

This proposal introduces a Security Provider Service as a platform capability for validating authentication evidence and producing a trusted, canonical security context for Synanton services. It standardizes how human users, workloads, connectors, and agents establish identity across the platform without making every domain service implement its own authentication integrations.

The service is an integration and trust-boundary component, not a replacement for the platform's Identity or Authorization authorities:

- **Identity 1.29** remains authoritative for canonical principals, external identity mappings, tenant membership, delegation, identity lifecycle, and identity context.
- **Security 1.23** remains normative for authorization, classification-aware access, masking, and fail-closed security invariants.
- **Security Provider** validates credentials and authentication results, resolves trusted provider identities through the Identity contract, and returns a validated identity context to the calling service.
- **Domain services** remain responsible for enforcing authorization on each operation. Authentication never implies authorization.

The proposal recommends a provider-neutral architecture with support for OAuth 2.0/OIDC tokens, workload identity, and mTLS. It should integrate with an existing enterprise identity provider rather than immediately implement a new password store or authorization engine.

## 2. Context and architectural alignment

Synanton Platform Architecture 1.0 defines separate authorities for identity and authorization and explicitly states that security context must not weaken across asynchronous boundaries, tenant scope must be validated, and ambiguous security state must fail closed. This proposal is a direct response to that architecture's implementation sequence and normative invariants.

This proposal follows those rules and the Identity Design 1.29 requirements:

- Stable internal principal identifiers; external identifiers do not become canonical IDs by default.
- Explicit principal types: `USER`, `SERVICE`, `WORKLOAD`, `CONNECTOR`, and `AGENT`.
- External identities resolve through explicit issuer/provider and subject mappings.
- Authentication assurance is preserved in the resulting identity context.
- Tokens are validated for issuer, audience, signature, expiry, not-before, subject, required claims, and tenant mapping.
- Delegation and actor chains are explicit, scoped, time-limited where appropriate, auditable, and revocable.
- Unsigned identity headers are never authoritative.
- Ambiguous mappings, unavailable security dependencies, and invalid credentials fail closed for protected operations.

The Security Provider must not duplicate canonical identity or authorization state. Its own persistence should be limited to provider configuration, trust metadata, key/certificate metadata where required, security events, and operational state that cannot be owned by Identity.

### 2.1 Authority map

| Concern | Owning design | Security Provider role |
|---|---|---|
| Canonical principals, principal types | Identity 1.29 | Consumer |
| External identity mappings, collision/linking rules | Identity 1.29 | Consumer |
| Tenant membership, identity lifecycle | Identity 1.29 | Consumer |
| Delegation relationships, actor-chain semantics | Identity 1.29 | Consumer |
| Identity context contract | Identity 1.29 | Producer (validated instance) |
| Authorization decisions | Security 1.23 | None |
| Classification, masking, representation selection | Security 1.23 | None |
| Resource ACLs and grants | Security 1.23 | None |
| External API surface | Platform API 1.32 | Internal only unless exposed via 1.32 |
| Async propagation contract | Eventing/Workflow 1.27 | Consumer/Producer per 1.27 |

### 2.2 Implementation sequencing prerequisite

The architecture document defines a specific implementation order. This proposal explicitly acknowledges and depends on it:

1. Finalize and freeze Platform API 1.32 and common API/resource/error/Operation contracts.
2. Freeze Eventing/Workflow 1.27 as the common asynchronous contract.
3. Implement the first vertical slice (per architecture guidance).
4. Add Identity/security enforcement across that slice.

No Security Provider implementation phase may begin before 1.32 and 1.27 contracts are frozen, because the Security Provider's external surface (if any) and async propagation semantics depend on those contracts. This is recorded as an explicit gate in [§15](#15-delivery-plan).

## 3. Goals

- Provide one consistent authentication boundary for Synanton services.
- Normalize different authentication mechanisms into a provider-neutral, validated security context.
- Support service-to-service identity and external/user federation without coupling domain code to a specific IdP.
- Support OAuth 2.0 access-token validation and OIDC identity integration.
- Support mTLS/workload identity for internal service calls.
- Preserve tenant membership, principal type, assurance, delegation, and actor-chain semantics.
- Provide credential lifecycle hooks: key rotation, certificate rotation, revocation, provider disablement, and principal disablement propagation.
- Emit auditable security events without logging credentials or sensitive token contents.
- Make security policy and trust configuration testable and observable.

## 4. Non-goals

The first version does not:

- Replace Identity 1.29 or Security 1.23.
- Become a universal IAM product or enterprise directory.
- Define a new password database or user-registration system.
- Own resource-level authorization decisions for every domain service.
- Replace the stable external Platform API 1.32 contract.
- Require OAuth for every internal call where authenticated workload identity is sufficient.
- Treat possession of a valid certificate or token as permission to access every tenant.
- Store raw access tokens, private keys, passwords, or long-lived client secrets in application tables.
- Implement a custom cryptographic protocol or custom token format.
- Implement any external identity mapping, linking, or collision logic; this remains owned by Identity 1.29.
- Produce or influence representation/masking decisions; these remain owned by Security 1.23.

## 5. Proposed architecture

```text
External IdP / Enterprise IdP                 Workload Identity / CA
       OIDC / OAuth 2.0                               mTLS
              |                                          |
              +-------------------+----------------------+
                                  |
                         Security Provider
                    +---------------------------+
                    | Provider adapters         |
                    | Token/cert validation     |
                    | Trust & issuer policy     |
                    | Principal resolution      |  <-- consumer of Identity 1.29
                    | Assurance normalization   |
                    | Security audit events     |
                    +-------------+-------------+
                                  |
                       Identity 1.29 contract
                    principal / mapping / tenant
                                  |
                      Validated security context
                    (no masking/representation decisions)
                                  |
              +-------------------+--------------------+
              |                   |                    |
         Platform API         Content Cache        AI Runtime
              |                   |                    |
              +------ Authorization / Security 1.23 ---+
                    resource ACL, classification,
                    tenant policy, masking, delegation
```

### 5.1 Responsibilities

**Security Provider**

- Validate authentication evidence and provider trust.
- Normalize provider-specific identities into an internal authentication result.
- Consume Identity 1.29's principal-resolution API to obtain the canonical Synanton principal. The Security Provider does not own, cache beyond bounded freshness, or reimplement principal mapping logic.
- Build a signed or otherwise cryptographically bound internal security context where propagation across trust boundaries is required.
- Enforce authentication-level policy such as allowed issuer, audience, credential status, and minimum assurance.
- Emit security events and expose health/readiness information.
- Never produce, infer, or attach representation-selection or masking decisions to the security context.

**Identity 1.29**

- Own canonical principals and principal types.
- Own external identity mappings and collision/linking rules.
- Own tenant membership and identity lifecycle.
- Own delegation relationships and canonical identity context semantics.
- Provide the resolution API consumed by the Security Provider.

**Security 1.23 / authorization enforcement**

- Decide whether a principal can perform an operation on a resource.
- Enforce resource ACLs and classification grants.
- Enforce masking/representation selection and fail-closed rules.
- Invalidate or reprocess security-sensitive derived state when policy changes.

**Domain services**

- Validate the security context's provenance.
- Enforce authorization at the operation and resource boundary.
- Avoid trusting caller-supplied tenant IDs, roles, principal IDs, or unsigned identity headers.
- Preserve security context across events, commands, jobs, and retries.

## 6. Authentication mechanisms

### 6.1 OAuth 2.0 and OIDC

Use OAuth 2.0 access tokens for API authorization and OIDC when user authentication/federation is required. Prefer short-lived tokens and asymmetric signatures. Token validation must check at least:

- trusted issuer (`iss`);
- intended audience (`aud`);
- signature and permitted algorithm;
- expiration (`exp`) and not-before (`nbf`);
- subject (`sub`);
- required scopes/claims;
- provider-to-canonical-principal mapping;
- tenant membership and requested tenant context;
- token type and intended use, to avoid confusing ID tokens with API access tokens.

The service should support standard discovery/JWKS rotation and safe cache invalidation. It must not accept a token merely because it can decode it.

**External identity mapping ownership.** The rules that map an external (issuer, subject) to a canonical Synanton principal — including linking, collision detection, collision resolution, and audit of those events — are owned by Identity 1.29. The Security Provider calls Identity 1.29's resolution API and treats its result as authoritative. The Security Provider must not implement its own mapping table, its own collision policy, or its own linking workflow. See [§11.2](#112-credential-lifecycle) for the audit obligation that accompanies this delegation.

**Masking exclusion.** Any claims observed during token validation are used solely for authentication and identity resolution. The resulting security context never carries masking hints, representation selections, or classification-derived display decisions. Those are supplied by Security 1.23 enforcement points downstream.

### 6.2 mTLS and workload identity

Use mTLS for authenticated, encrypted service-to-service transport where practical. Verify the peer certificate against the configured trust roots and policy, including identity/SAN mapping, validity, key usage, and revocation/rotation policy. Map the verified workload identity to a canonical `SERVICE` or `WORKLOAD` principal.

mTLS authenticates the peer and protects the channel; it does not by itself authorize a tenant or operation. For higher-risk calls, use mTLS plus a scoped OAuth access token or equivalent signed delegation context.

### 6.3 API credentials

API keys are not the preferred default for internal service identity. If needed for constrained legacy integrations, store only a verifier/hash, scope them narrowly, support expiry and rotation, and provide immediate revocation. Never place credentials in source code, URLs, or logs.

### 6.4 Provider-neutral abstraction

Define interfaces around semantics rather than vendor APIs:

```go
type AuthenticationProvider interface {
    Authenticate(ctx context.Context, evidence Evidence) (AuthenticationResult, error)
    Resolve(ctx context.Context, result AuthenticationResult) (PrincipalResolution, error)
    Health(ctx context.Context) ProviderHealth
}

type Evidence interface {
    Kind() EvidenceKind // OIDC_ACCESS_TOKEN, MTLS_PEER, WORKLOAD_ASSERTION, API_CREDENTIAL
}

type AuthenticationResult struct {
    ProviderID       string
    ExternalIssuer   string
    ExternalSubject  string
    PrincipalType    PrincipalType
    Assurance        AssuranceLevel
    AuthenticatedAt  time.Time
    ExpiresAt        *time.Time
    CredentialID     string
    EvidenceKind     EvidenceKind
}
```

The `Resolve` method is a thin adapter over Identity 1.29's resolution API; it exists to keep provider adapters symmetric and does not imply local mapping logic. This is illustrative, not a final public API. Domain types should follow existing Synanton language and API conventions. Provider adapters must not return an authorization decision.

## 7. Canonical security context

After successful authentication and principal resolution, produce a minimal context such as:

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

The example is illustrative. Do not copy identity claims from arbitrary headers into this context. Fields should be included only when established by trusted evidence and the Identity contract.

**Masking and representation exclusion.** By construction, this context contains no masking directives, no representation selections, no display-format hints, and no classification-derived output shaping. Consistent with the architectural invariant that masking is a representation transformation, those concerns are applied downstream by Security 1.23 enforcement points, never by the Security Provider and never encoded into the security context.

### 7.1 Propagation rules

- Prefer authenticated RPC context and mTLS for direct internal calls.
- Use signed, short-lived assertions or token exchange when identity must cross independent trust boundaries.
- Preserve initiator, delegator, executor, tenant, assurance, and relevant trace context across asynchronous boundaries.
- Treat broker metadata and event payloads as untrusted unless their provenance and integrity are verified.
- Never let a downstream service infer authority from free-form content, an agent prompt, or an unsigned `X-User-ID`/`X-Tenant-ID` header.
- Do not silently convert service identity into user identity. Delegation or impersonation must be explicit and audited.
- Preserve the security context shape defined here; do not augment it with representation or masking fields in transit.

## 8. Authorization boundary

The Security Provider authenticates and resolves identity; it does not grant blanket access. Each service must call or enforce the applicable authorization policy before performing a protected operation.

A request is permitted only when all applicable conditions pass:

```text
trusted authentication evidence
AND canonical principal resolved
AND principal active
AND requested tenant membership/scope valid
AND operation permission granted
AND resource ACL permits access
AND classification/representation policy permits access
AND delegation is valid (when present)
```

Classification is not authorization. Resource access is not a substitute for classification checks. Search candidate selection, snippets, caches, derived representations, and background jobs must use the same effective security context.

Masking is not produced here. All representation and masking decisions occur downstream under Security 1.23. The Security Provider supplies the identity context; it does not participate in representation selection.

## 9. Conceptual API

The exact external API remains subject to Platform API 1.32. The following is a candidate internal contract, not a commitment to expose every endpoint publicly. No endpoint described here may be exposed externally except through Platform API 1.32's contract, versioning, and compatibility CI. Exposure is gated by the [§15](#15-delivery-plan) Phase 0 exit.

| Operation | Purpose |
|---|---|
| `POST /v1/authenticate` | Validate a supported credential exchange where an explicit API flow is appropriate |
| `POST /v1/identity/resolve` | Thin adapter that calls Identity 1.29's resolution API; returns the canonical principal |
| `POST /v1/security-context/validate` | Validate a signed internal context at a trust boundary |
| `GET /v1/providers` | Administrative view of configured providers |
| `POST /v1/providers` | Register provider configuration with privileged authorization |
| `PATCH /v1/providers/{id}` | Rotate/update trust configuration or disable a provider |
| `GET /health/live` | Process liveness |
| `GET /health/ready` | Readiness including required trust/config dependencies |

For ordinary API access-token validation, prefer local verification against trusted issuer metadata/JWKS where appropriate rather than a synchronous network call to this service for every request. The service can provide policy/configuration and identity-resolution capabilities while a shared library or sidecar performs safe local validation.

### 9.1 Local verification policy

Local verification is permitted only when all of the following hold:

- The issuer is configured as trusted for local verification.
- The token's audience and scope are within the set permitted for local verification.
- The verification key set is cached with a bounded TTL not to exceed the revocation SLO defined in [§11.2](#112-credential-lifecycle) (default target: ≤ 5 minutes for high-risk issuers, ≤ 15 minutes for standard issuers, subject to the Revocation SLO decision in [§16](#16-decisions-required)).
- A revocation-signal channel (push or pull) exists and is monitored for freshness.

Operations that must use centralized validation regardless of the above: privileged/admin operations, cross-tenant operations, delegation activation or extension, and any operation designated high-risk by Security 1.23. The list of such operations is owned by Security 1.23 and consumed by the Security Provider as configuration.

Provider administration must be restricted to platform operators and audited. No endpoint should reveal tokens, private keys, or sensitive credential material.

## 10. Data ownership and persistence

Keep the provider service stateless where possible. Proposed persistence is limited to:

- `provider_configs`: provider ID, type, issuer, allowed audiences, trust roots/JWKS metadata reference, enabled state, configuration version;
- `credential_registry` (only if required): credential identifier, principal reference, type, status, expiry, rotation metadata; never raw secret material;
- `trust_policy_versions`: versioned policy/configuration and activation metadata;
- `security_audit_events`: append-oriented events for authentication failures, provider changes, revocations, policy changes, and privileged operations.

Canonical principals, external identity mappings, tenant membership, and delegation remain owned by Identity 1.29. In particular, the Security Provider does not persist its own mapping table between external identities and canonical principals; every resolution goes through Identity 1.29 or a bounded-freshness cache of Identity 1.29 responses. Authorization policy remains owned by Security 1.23 or its designated policy enforcement/decision components. Avoid duplicating those tables.

Secrets and private keys should live in a dedicated secret manager or workload identity infrastructure. Public keys and JWKS can be cached with bounded freshness and rotation-aware invalidation.

## 11. Security and failure requirements

### 11.1 Fail-closed behavior

Reject protected operations when:

- credentials are invalid, expired, revoked, or intended for a different audience;
- issuer or certificate trust cannot be established;
- principal mapping is missing or ambiguous (as determined by Identity 1.29);
- tenant membership cannot be validated;
- the principal is disabled;
- a required delegation is absent or invalid;
- the policy or identity state is unavailable and no explicitly approved safe cache policy applies.

A temporary identity-provider outage must not silently convert to anonymous access or broader privileges.

### 11.2 Credential lifecycle

- Automated certificate issuance and rotation.
- JWKS and trust-bundle refresh with bounded cache lifetime.
- Provider disablement and trust-root rotation.
- Credential revocation and principal deactivation propagation.
- Session/token expiry and revocation behavior.
- Emergency response for compromised workload credentials.

**External identity linking and collision handling.** The Security Provider does not implement linking or collision resolution. It consumes Identity 1.29's resolution result. When Identity 1.29 reports an ambiguous, unlinked, or colliding external identity, the Security Provider fails the authentication closed and emits an audit event. The Security Provider's audit obligation is limited to recording that resolution failed and referencing the Identity 1.29 response; the authoritative record of the collision and its resolution remains with Identity 1.29.

**Revocation SLO.** The maximum time between a revocation event at Identity 1.29 or the credential authority and the moment the Security Provider (and any local verifier acting on its behalf) rejects the credential is the Revocation SLO. Default target values:

| Path | Target revocation SLO |
|---|---|
| Centralized validation | ≤ 60 seconds |
| Local verification, high-risk issuer | ≤ 5 minutes |
| Local verification, standard issuer | ≤ 15 minutes |
| mTLS peer certificate (via CRL/OCSP or trust-bundle refresh) | ≤ 15 minutes |

These values are provisional pending the Revocation SLO decision in [§16](#16-decisions-required). The chosen values must be published as a platform SLO and validated in CI ([§14](#14-testing-strategy-and-acceptance-criteria) Release gates).

### 11.3 Threat model

| Threat | Primary control |
|---|---|
| Token forgery or algorithm confusion | Strict signature/algorithm validation, trusted issuer keys |
| Token replay | Short lifetime, audience binding, proof-of-possession where justified |
| Tenant confusion | Resolve membership from canonical Identity state; never trust caller-selected tenant alone |
| Service impersonation | mTLS/workload identity mapping; no unsigned identity headers |
| Privilege escalation | Separate authentication and authorization; least privilege; explicit delegation |
| Stale identity cache | Bounded TTL, revocation signals, versioned policy and invalidation |
| Credential theft | Short-lived credentials, secret manager, rotation, audit |
| Confused deputy | Preserve actor chain and validate delegated authority |
| Provider compromise | Disable provider, revoke trust, invalidate caches, audit affected identities |
| Sensitive-data leakage in logs | Structured allowlisted fields; never log raw tokens or private material |
| Local-verifier drift beyond revocation SLO | Bounded TTL enforced by config; centralized validation required for high-risk operations ([§9.1](#91-local-verification-policy)) |
| Masking/representation leakage through context | Security context contains no masking or representation fields by construction ([§7](#7-canonical-security-context)) |

## 12. Observability and audit

Emit structured metrics and events such as:

- authentication attempts by mechanism and outcome;
- invalid, expired, wrong-audience, and revoked token counts;
- certificate validation failures and rotation status;
- principal-resolution failures and identity collisions (as reported by Identity 1.29);
- tenant-membership denials;
- provider health and JWKS/trust-bundle freshness;
- identity-context validation failures;
- revocation propagation latency (measured against [§11.2](#112-credential-lifecycle) SLO);
- authentication latency and dependency errors;
- local-verifier cache age and eviction events.

Audit events should include timestamp, event type, provider ID, canonical principal ID when safely resolved, principal type, tenant where established, outcome, reason code, trace ID, and actor/delegation context where applicable. Do not include raw credentials, complete tokens, private keys, or sensitive request payloads. Apply retention and access policy to audit data.

**Ownership of collision audit.** Collision and linking audit records are authored by Identity 1.29. The Security Provider's audit stream records only the failure to resolve and a reference to the Identity 1.29 response; it does not duplicate collision state.

## 13. Deployment and operations

- Deploy behind the platform's trusted network boundary; use TLS everywhere and mTLS for internal workloads where supported.
- Keep provider administration separate from ordinary authentication traffic.
- Use a managed secret store and workload identity; avoid static credentials in manifests.
- Define liveness separately from readiness. A provider outage should not cause restart loops if the process is healthy, but protected operations must still fail closed when trust cannot be established.
- Use versioned configuration and staged trust/key rotation.
- Support development/test providers without allowing test trust roots in production.
- Ensure Kubernetes readiness and rollout behavior align with Design 1.33.
- Define SLOs for local token validation, identity resolution, provider availability, and revocation propagation before production rollout. The revocation-propagation SLO must match [§11.2](#112-credential-lifecycle).
- Enforce the [§9.1](#91-local-verification-policy) local-verification TTL and centralized-validation policy as deployment configuration, not application-level convention.

## 14. Testing strategy and acceptance criteria

**Functional tests**

- Valid and invalid OIDC/OAuth tokens.
- Wrong issuer/audience, expired/not-yet-valid token, invalid signature, unsupported algorithm, missing subject/claims.
- mTLS certificate trust, SAN mapping, expiry, rotation, and unknown workload.
- External identity mapping failure paths — verifying that the Security Provider fails closed and defers to Identity 1.29 on ambiguous, unlinked, or colliding identities.
- Correct principal type and assurance normalization.
- Security context contains no masking or representation fields under any input.

**Security tests**

- Caller-supplied tenant and principal headers do not override authenticated context.
- Cross-tenant access is denied by authorization enforcement.
- Valid authentication without permission is denied.
- Delegation preserves the actor chain and cannot widen privileges.
- Disabled principals and revoked credentials lose access within the [§11.2](#112-credential-lifecycle) revocation SLO.
- Provider failure and ambiguous mapping fail closed.
- No tokens or secrets appear in logs, traces, errors, or metrics labels.
- Local-verifier cache age is bounded by [§9.1](#91-local-verification-policy) TTL; high-risk operations bypass local verification.

**Resilience and integration tests**

- Identity provider/JWKS outage and recovery.
- Identity 1.29 resolution outage and recovery — Security Provider fails closed.
- Key rotation with old and new keys during the overlap period.
- Certificate rotation without service downtime.
- Clock skew and expiry boundaries.
- Async event/workflow propagation and replay, exercising 1.27 contract.
- Cache invalidation after principal disablement or policy change.
- Integration tests with Platform API, Content Cache, Eventing/Workflow, AI Runtime, and at least one downstream consumer.

**Release gates**

1. Platform API 1.32 and Eventing/Workflow 1.27 contracts are frozen (Phase 0 exit gate).
2. Every supported credential path has positive and negative tests.
3. All trust decisions are based on cryptographically verified evidence.
4. No tenant is selected solely from untrusted request input.
5. Authentication and authorization remain distinct in service contracts.
6. Provider outages fail closed for protected operations.
7. Rotation and revocation are exercised in CI or a repeatable staging test, including verification of the [§11.2](#112-credential-lifecycle) SLO.
8. Audit events are generated for privileged changes and security-relevant failures.
9. External identity mapping, linking, and collision paths are verified to defer to Identity 1.29.
10. Security context is verified to contain no masking or representation fields.
11. Local-verification TTL policy ([§9.1](#91-local-verification-policy)) is enforced by configuration and covered by tests.
12. API and context contracts are reviewed against Identity 1.29 and Platform API 1.32.
13. A threat-model review and security review are approved before production.

## 15. Delivery plan

### Phase 0 — Contract and threat model

- Prerequisite gate: confirm that Platform API 1.32 and Eventing/Workflow 1.27 contracts are frozen, per [§2.2](#22-implementation-sequencing-prerequisite). Phase 1 may not begin until this gate passes.
- Confirm boundaries with Identity 1.29 and Security 1.23 owners.
- Define principal types, provider interface, assurance mapping, tenant context, delegation, and propagation format.
- Decide whether the first release is a service, shared library, sidecar, or a combination. Avoid a network hop for every token verification if local validation is safe and sufficient.
- Decide the revocation SLO targets ([§11.2](#112-credential-lifecycle), [§16](#16-decisions-required) item 6).
- Decide the list of operations requiring centralized validation ([§9.1](#91-local-verification-policy)).
- Record decisions in ADRs.

Exit: reviewed contracts and threat model; 1.32 and 1.27 frozen; no duplicated authority; [§9.1](#91-local-verification-policy) and [§11.2](#112-credential-lifecycle) policies recorded as ADRs.

### Phase 1 — Workload authentication

- Implement mTLS/workload identity adapter.
- Map workloads to canonical principals via Identity 1.29.
- Provide shared middleware/interceptors for HTTP and gRPC.
- Add rotation, revocation, audit, and negative tests, including [§11.2](#112-credential-lifecycle) SLO verification.

Exit: service-to-service calls authenticate correctly and cannot spoof principal or tenant identity.

### Phase 2 — OAuth/OIDC federation

- Add provider-neutral issuer configuration and OIDC/OAuth token validation.
- Add JWKS refresh, audience/scope checks, and deferral to Identity 1.29 for external identity mapping, linking, and collision handling.
- Support short-lived token exchange/delegation where required.
- Implement [§9.1](#91-local-verification-policy) local-verification policy with enforced TTL.

Exit: external identities resolve deterministically to canonical principals (via Identity 1.29); invalid tokens fail closed; local verification honors the [§11.2](#112-credential-lifecycle) revocation SLO.

### Phase 3 — Platform integration

- Integrate with Platform API 1.32 and the Identity 1.29 context contract.
- Integrate authorization enforcement consistent with Security 1.23, confirming that no representation or masking decisions flow through the security context.
- Propagate identity and delegation through Eventing/Workflow 1.27.
- Validate Content Cache 1.26 and AI Runtime 1.30 integration.

Exit: one end-to-end flow is tested across synchronous and asynchronous boundaries; security context verified free of masking fields.

### Phase 4 — Production readiness

- Complete load, fault-injection, rotation, and revocation tests.
- Publish dashboards, alerts, runbooks, and SLOs (including the [§11.2](#112-credential-lifecycle) revocation SLO).
- Conduct independent security review and staged rollout.

Exit: all release gates pass and operators can detect, contain, and recover from credential compromise.

## 16. Decisions required

Before implementation, architecture owners should decide:

1. **Deployment shape:** standalone service, shared validation library, sidecar, or hybrid. Proposed default: a provider-control/resolution service plus reusable local verification middleware where safe.
2. **Initial identity provider:** use an existing OIDC/OAuth provider; do not build a new IdP without a specific requirement.
3. **Workload identity source:** Kubernetes service-account/workload identity, internal CA, or existing mesh.
4. **Token format and profile:** define allowed issuers, audiences, claims, lifetimes, signing algorithms, and key-rotation rules.
5. **Authorization interface:** identify the canonical Security 1.23 enforcement point and avoid embedding resource policy in the provider.
6. **Revocation SLO:** ratify the default values in [§11.2](#112-credential-lifecycle) or replace them with platform-approved targets. This value is a dependency for [§9.1](#91-local-verification-policy) and for Release gate 7.
7. **Local verification policy:** ratify the [§9.1](#91-local-verification-policy) centralized validation list and TTL bounds.
8. **Public API boundary:** determine which operations, if any, are exposed through Platform API 1.32.
9. **Audit retention and ownership:** align with platform-wide audit and privacy policy; confirm that collision/linking audit ownership remains with Identity 1.29.

## 17. Recommendation

Approve the proposal for design review, with a deliberately narrow first milestone: workload identity and mTLS for internal service authentication, canonical principal resolution through Identity 1.29, and explicit authorization enforcement under Security 1.23. Add OAuth 2.0/OIDC federation in the next phase using a provider-neutral adapter.

Do not build a second identity database, a bespoke authorization engine, or a custom token format. Keep provider-specific logic behind adapters, canonical identity in Identity 1.29, and resource/classification authorization in Security 1.23.

The success criterion is not merely that services can authenticate. It is that every service receives a verifiable identity context, every protected operation enforces authorization, tenant and delegation context cannot be weakened across asynchronous boundaries, masking and representation decisions remain with Security 1.23, external identity mapping and collision handling remain with Identity 1.29, and credential compromise can be contained and audited within a published revocation SLO.

## References

- Synanton Platform Architecture 1.0
- Synanton Design 1.23 — Security and classification-aware access
- Synanton Design 1.26 — Content Cache
- Synanton Design 1.27 — Eventing and Workflow
- Synanton Design 1.29 — Identity, federation, tenant membership, and delegation
- Synanton Design 1.30 — AI Runtime
- Synanton Design 1.32 — Platform API
- Synanton Design 1.33 — Kubernetes lifecycle

