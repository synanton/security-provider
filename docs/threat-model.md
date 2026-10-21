# Threat Model — draft; security reviewer approval pending (joint-plan B0-5)

**Status reviewed:** 2026-10-21. This document is not approved; passing tests
for listed controls does not close B0-5 or establish production readiness.

Scope: the Security Provider service, its adapters, and `pkg/middleware` as consumed by content-service. Out of scope: Identity 1.29 internals, Security 1.23 enforcement, IdP/CA operations.

## Trust boundaries

1. **Untrusted network → provider endpoints.** All input is adversarial: bearer tokens, tenant hints, context tokens.
2. **Provider → Identity 1.29.** Resolution answers are authoritative but transport-untrusted: TLS + timeout + fail-closed on any error or ambiguity.
3. **Provider → IdP/JWKS/CA.** Key material is trust-critical: bounded TTL, rotation-aware refresh, fetch failures fail closed.
4. **Provider → consumers.** Only signed, short-lived contexts cross; consumers re-verify (middleware) and never trust headers.
5. **Operators → provider admin.** Privileged, bearer-gated, fully audited; disabled when no admin token is configured.

## Threats and controls

Derived from proposal §11.3; each control names its test:

| Threat | Control | Test |
|---|---|---|
| Token forgery / algorithm confusion | Allowlisted algs (never `none`), JWKS signature verification | `TestOIDCNegative`, `TestOIDCAlgConfusionRejected` |
| Wrong-issuer / wrong-audience acceptance | Explicit iss/aud checks before key use | `TestOIDCNegative` |
| Expired / not-yet-valid acceptance | exp/nbf enforcement (60s skew) | `TestOIDCNegative`, `TestVerifyRejectsExpired` |
| mTLS impersonation | Chain-to-bundle verification, SAN allowlist (empty denies all), SPIFFE ID parsing | `TestMTLS*`, `TestMTLSEndToEnd` |
| Unknown workload with valid CA cert | Allowlist is mandatory, not advisory | `TestMTLSUnknownWorkloadFailsClosed` |
| Forged tenant header | Cross-check vs validated context; mismatch → 403 | `TestRequireAuthNegative`, `TestAuthenticateNegative` |
| Unsigned identity headers | Never authoritative; disagreeing `X-User-ID` → 403 | `TestRequireAuthNegative` |
| Workload → user confusion | Workload adapters never emit USER | `TestWorkloadNeverBecomesUser` |
| Ambiguous / colliding identity | Identity 1.29 ambiguity fails closed + audited | `TestStubNegative` |
| Disabled principal / revoked credential | Resolution + revocation checks; no failure caching | `TestStubNegative`, `TestOIDCRevocation`, `TestAPIKeyNegative` |
| Stale keys past revocation SLO | Bounded TTLs validated against the SLO; stale signal fails closed | `TestOIDCKeyRotation`, `TestValidateRejects` |
| Masking smuggling via context | Forbidden-claim rejection pre-signature on server and consumer | `TestVerifyRejectsMaskingClaims`, middleware tests |
| Secret leakage in logs/metrics | Allowlisted audit fields; no credential in errors/labels | Review gate (no automated test asserts absence repo-wide — see residual risks) |
| Admin abuse | Bearer gate, disabled-by-default, audit on every call | `TestProviderAdminGated` |

## Residual risks and open work

- `identity.mode: http` against the real Identity 1.29 API is unwired (stub is the documented interim); production resolution behavior is unproven.
- Tenant-bound browser access-token issuance, asymmetric signing keys/JWKS, and its real-adapter acceptance are not implemented; current signed contexts are internal HS256 contexts. Track the issuer in [platform #340](https://github.com/synanton/platform/issues/340) and [security-provider #3](https://github.com/synanton/security-provider/issues/3). This threat model does not claim protection from an issuer that does not yet exist.
- No repo-wide automated assertion that logs/metrics stay credential-free; relies on review + the audit field allowlist.
- Timing side channels (tenant-existence oracles via latency) are out of PR gates by design, as in content-service.
- Kill-process-mid-rotation and IdP-outage-mid-handshake harnesses do not exist yet (resilience backlog, Phase 4).
