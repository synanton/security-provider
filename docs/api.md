# API Reference

Candidate **internal** contract for the Security Provider. Nothing here is public: any external exposure goes through Platform API 1.32's contract, versioning, and compatibility CI. The same contract is served over gRPC (`security.v1.SecurityProviderService`); see `proto/security/v1/security.proto`.

## Conventions

- Content type is `application/json` on all REST endpoints.
- Error shape: `{"error": "<CODE>", "message": "<human-readable>"}`. Codes are stable (`UNKNOWN_PROVIDER`, `AUTH_FAILED`, `TENANT_DENIED`, …); messages never carry credential material.
- Tenant scope: `requested_tenant_id` is an untrusted hint. Membership is validated against Identity 1.29 state; a mismatch fails closed with `TENANT_DENIED`.
- `trace_id` is opaque caller correlation, echoed into audit events and the issued context.

## Endpoints

### POST /v1/authenticate

Validate a supported credential exchange and receive a signed context.

```bash
curl -X POST http://localhost:8080/v1/authenticate \
  -H "Content-Type: application/json" \
  -d '{"provider_id":"synanton-workload-ca","evidence_kind":"MTLS_PEER",
       "requested_tenant_id":"tenant:acme","trace_id":"t-1"}'
```

| Field | Required | Notes |
|---|---|---|
| `provider_id` | yes | Must match a configured, enabled provider |
| `evidence_kind` | yes | `OIDC_ACCESS_TOKEN` \| `MTLS_PEER` \| `WORKLOAD_ASSERTION` \| `API_CREDENTIAL` |
| `credential` | for token kinds | Opaque bearer material; must be empty for `MTLS_PEER` (peer comes from the TLS handshake) |
| `requested_tenant_id` | no | Untrusted hint, validated, never authoritative |
| `trace_id` | no | Correlation id |

Response `200 OK`:

```json
{
  "context_token": "<signed JWT>",
  "security_context": {
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
    "trace_id": "t-1"
  }
}
```

### POST /v1/identity/resolve

Thin adapter over Identity 1.29's resolution API.

```bash
curl -X POST http://localhost:8080/v1/identity/resolve \
  -H "Content-Type: application/json" \
  -d '{"provider_id":"synanton-workload-ca","external_issuer":"test-ca",
       "external_subject":"spiffe://synanton/ingestor","principal_type":"WORKLOAD"}'
```

Ambiguous, unknown, disabled, or tenant-denied mappings fail with `403`/`401` and the corresponding reason code.

### POST /v1/security-context/validate

Validate a signed internal context at a trust boundary.

```bash
curl -X POST http://localhost:8080/v1/security-context/validate \
  -H "Content-Type: application/json" \
  -d '{"context_token":"<signed JWT>"}'
```

Response `200 OK` with `{"valid": true, "security_context": {...}}` or `{"valid": false, "reason_code": "<CODE>"}`. Transport status stays 200 for well-formed requests: validity is data, not transport state.

### GET /v1/providers

Administrative view: configured providers plus health (`healthy` / `unhealthy: <detail>`). No credential material.

### POST /v1/providers · PATCH /v1/providers/{id}

Privileged. Requires `Authorization: Bearer <SECURITY_PROVIDER_ADMIN_TOKEN>`; disabled entirely when no admin token is configured. Every call is audited. Used to register a provider view or rotate/disable trust configuration.

### GET /health/live · GET /health/ready

- `/health/live`: `{"status":"live"}` while serving (200 through shutdown drain).
- `/health/ready`: `{"status":"ready"}` when trust bundles load and providers report healthy; `503` with the unhealthy provider list otherwise.

## Consumer middleware

`pkg/middleware` validates contexts inside consuming services (content-service D.1 handshake). HTTP:

```go
verifier := &middleware.HMACVerifier{Key: key, ExpectedIssuer: "synanton-security-provider"}
mux.Handle("/api/v1/artifacts", middleware.RequireAuth(verifier)(handler))

tenant, err := middleware.TenantIDFromContext(r.Context()) // only legitimate source
```

Behavior: missing/invalid token → `401`; present-but-mismatched `X-Tenant-ID` (header or `?tenant_id=`) → `403`; `X-User-ID` disagreeing with the validated principal → `403`; validated context injected for downstream use.

gRPC: `middleware.UnaryServerInterceptor(verifier)` validates `authorization` metadata and cross-checks `x-tenant-id`; `middleware.UnaryClientInterceptor(middleware.StaticTokenSource(token))` attaches tokens; `middleware.PerRPCCredentials(token)` supplies transport credentials (requires TLS).
