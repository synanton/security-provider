# Architecture

Hexagonal (ports and adapters), following the content-service / equalix-go family layout.

```text
┌─────────────────────────────────────────────────────────┐
│                  cmd/security-provider                  │
│              (flag parsing + wiring only)               │
└───────────────────────────┬─────────────────────────────┘
                            │
            ┌───────────────┼───────────────┐
            │               │               │
┌───────────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
│  REST adapter    │ │ gRPC adapter│ │  Metrics +  │
│  (std ServeMux,  │ │ (generated  │ │  Health     │
│  method patterns)│ │  stubs)     │ │  (live/ready│
└───────────┬──────┘ └──────┬──────┘ └──────┬──────┘
            │               │               │
            └───────────────┼───────────────┘
                            │
                    ┌───────▼────────┐
                    │   Authn core   │
                    │  registry +    │
                    │  trust policy  │
                    └───────┬────────┘
                            │
        ┌───────────────────┼───────────────────┐
        │                   │                   │
┌───────▼──────┐    ┌───────▼──────┐    ┌───────▼──────┐
│ OIDC / JWKS  │    │ mTLS / SPIFFE│    │ Identity 1.29│
│ (jwx+go-oidc)│    │ (x509+spiffe)│    │ (stub → http)│
│ + API keys   │    │ + trust CA   │    │ + bnd cache  │
└──────────────┘    └──────────────┘    └──────────────┘
```

## What is pure vs adapter

- `internal/domain/` — pure types (`EvidenceKind`, `PrincipalType`, `SecurityContext`, sentinel errors). No I/O imports. Testable without infrastructure.
- `internal/port/` — interfaces (`AuthenticationProvider`, `IdentityResolver`, `ContextIssuer`, `AuditSink`). Adapters implement them; nothing else defines them.
- `internal/authn/`, `internal/identity/`, `internal/context/`, `internal/policy/`, `internal/audit/` — logic over ports; I/O only through injected dependencies (JWKS fetch, resolution HTTP, signing keys).
- `internal/adapter/http|grpc/` — transport only: decode, dispatch, encode, status mapping.
- `pkg/middleware/` — the consumer port: dependency-light (stdlib + jwx + grpc) so content-service imports it without the server tree.

## Phase notes

- Phase 1: `identity` runs in `stub` mode (deterministic fixtures, fail-closed on unknown). `http` mode targets the real Identity 1.29 resolution API; its wire shape is defined in `internal/identity/client.go` (`resolutionRequest`/`resolutionResponse`) and frozen by ADR-002.
- The gRPC `SecurityProviderService` contract lives in `proto/security/v1/`; `gen/` is buf output and never hand-edited.
- Routing uses stdlib `http.ServeMux` method patterns (Go 1.22+), matching content-service. chi was evaluated and deferred (ADR-004).
