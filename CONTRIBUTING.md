# Contributing to security-provider

This document explains how to set up, develop, test, and submit changes to `security-provider`. It also defines the two acceptance gates (training and production) that every contribution should be aware of.

Design references: the Security Provider Service Proposal (`docs/proposal.md`), the local `docs/design.md`, Synanton Design 1.29 (Identity), Security 1.23 (authorization/masking), and the joint Content Service & Security Provider plan (Track B, milestones D.1–D.5).

---

## Prerequisites

- **Go 1.23+**
- **Docker** and **Docker Compose** (for the local stack)
- **golangci-lint** (install via `make tools`)
- **buf** + **protoc-gen-go** + **protoc-gen-go-grpc** (only for `make proto`)
- **openssl** (only for `make certs`)

---

## Setup

```bash
git clone https://github.com/synanton/security-provider.git
cd security-provider

# Unit tests (hermetic)
make test

# Integration tests (httptest mTLS end-to-end, no Docker needed)
make test-integration

# Local stack (generates dev certs into ./certs/, gitignored)
SECURITY_PROVIDER_SIGNING_KEY=$(head -c 48 /dev/urandom | base64) make docker-up
```

> **Do not run plain `go mod tidy` blindly.** Tidy prunes the dependencies of non-default build tags from `go.mod`. Add dependencies with explicit `go get module@version` instead, then verify `make test test-integration` still pass.

---

## Repository Layout

```text
cmd/security-provider/  # server entrypoint + wiring only
internal/
  domain/               # pure auth types + sentinel errors (no I/O)
  port/                 # interfaces (AuthenticationProvider, IdentityResolver, ContextIssuer)
  authn/                # provider adapters (oidc, mtls, workload, apikey) + registry
  identity/             # Identity 1.29 client + bounded cache + stub
  context/              # security context build/sign/validate
  policy/               # trust policy, local-verification policy
  audit/                # structured audit events (allowlisted fields only)
  adapter/
    http/               # net/http REST adapter (std ServeMux, method patterns)
    grpc/               # generated stubs + server
  config/               # YAML + SECURITY_PROVIDER_* env overrides
  observability/        # Prometheus metrics (sole source of metric names)
  testcert/             # throwaway test certificates (never production trust)
pkg/
  middleware/           # importable consumer middleware (HTTP + gRPC)
proto/security/v1/      # SecurityProviderService contract
gen/security/v1/        # buf-generated stubs (never hand-edit)
test/
  integration/          # httptest mTLS end-to-end (build tag: integration)
configs/                # dev/local YAML examples
docs/                   # proposal, design, api, runbook, architecture, adr, threat-model
```

**Rule:** `internal/domain/` must not import any package that performs I/O. If you find yourself reaching for `net/http`, `crypto/tls` server behavior, or JWKS fetching inside domain, define a port instead. **`pkg/middleware/` must stay dependency-light** (stdlib + jwx + grpc): content-service imports it.

---

## Development Workflow

1. Pick a task from the current phase in `docs/IMPLEMENTATION.md`.
2. If the behavior touches trust, resolution, or context shape, write the ADR first (`docs/adr/`).
3. Write tests first: table-driven unit tests for logic, negative tests for every trust decision.
4. Implement the minimum change that satisfies the tests.
5. Run `make test test-integration` (both `-race` clean) and `go vet ./...` before committing.
6. Open a PR linking the spec section and the joint-plan task ID (e.g. `B1-3`). Prefix branches with `SEC-` (e.g. `SEC-mtls-adapter`).
7. Merging is manual — a maintainer merges after review. Do not merge your own PR without approval.
8. Freshness marker: the italic line under README Status names the latest phase-landing merge and its date. Bump it on phase transitions, not every merge.

---

## Branch Naming

All branches use the `SEC` prefix:

```text
SEC-<short-scope>        e.g. SEC-docs-foundation
SEC-<phase>-<topic>      e.g. SEC-b1-middleware
```

Do not push directly to `main`.

---

## Commit Conventions

Use conventional commits:

```text
feat(authn): add OIDC audience allowlist
fix(mtls): reject empty SAN allowlist at construction
test(integration): cover unknown-workload fail-closed
docs(runbook): pin rotation procedure to code
chore: bump go-oidc to v3.15.0
```

Commit from status-verified-clean trees: run `git status` before staging and stage explicit paths. Never `git add -A` without first confirming the status shows only intended changes.

---

## Testing Requirements

| Layer        | Tool                          | Required Coverage        |
| ------------ | ----------------------------- | ------------------------ |
| Domain core  | `go test`, table-driven       | 90%+                     |
| Adapters     | `httptest` / `bufconn`        | 80%+                     |
| Integration  | `-tags=integration` mTLS E2E  | Critical paths           |
| Security     | Negative tests                | Every trust decision     |
| Load         | `k6` or `vegeta`              | Target throughput        |

Every PR that changes trust logic must include negative tests. Every PR that changes an adapter must include integration coverage. Every PR that changes context shape must prove the no-masking invariant still holds.

---

## Training Gate

- [ ] Idiomatic Go (no getter/setter boilerplate, no framework-style DI)
- [ ] Clear interfaces at port boundaries; domain free of I/O
- [ ] Concurrency correctness (race detector clean)
- [ ] Table-driven tests; fake clocks, never `time.Sleep`
- [ ] Errors wrapped with context; sentinel errors compared with `errors.Is`
- [ ] Documentation update in `docs/` for any new behavior
- [ ] `go vet` clean (`golangci-lint` clean where configured)

---

## Production Gate

- [ ] Every credential path has positive and negative tests
- [ ] All trust decisions rest on cryptographically verified evidence
- [ ] No tenant selected solely from untrusted input (proven by test)
- [ ] Provider outages fail closed for protected operations
- [ ] Rotation and revocation exercised, including the revocation SLO
- [ ] Audit events for privileged changes and security-relevant failures
- [ ] Threat-model and security reviews approved before production

---

## Code Review Checklist

- [ ] Does the change match `docs/design.md` and the proposal section it implements?
- [ ] Is the domain core free of I/O dependencies?
- [ ] Are new ports defined as interfaces, not concrete types?
- [ ] Are errors wrapped with context (`fmt.Errorf("...: %w", err)`)?
- [ ] Are goroutines cancellable via `context.Context`?
- [ ] Are tests deterministic (no `time.Sleep`; white-box TTL resets)?
- [ ] Is the race detector clean?
- [ ] Are new metrics registered in `internal/observability` and documented in README?
- [ ] Is the change reflected in `CHANGELOG.md` if user-visible?
- [ ] Do new providers update the README mechanisms table and add an ADR?

---

## Security Rules for Contributors

- Never log, metric-label, or echo raw credentials, complete tokens, or private keys. Audit fields are allowlisted in `internal/audit`.
- Unsigned identity headers are never authoritative. Tenant comes from the validated context.
- The security context never carries masking or representation fields. Tests assert this; keep them green.
- Fail closed: when in doubt, reject. An outage must never widen privileges.

---

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
