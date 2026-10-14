# security-provider AI Rules - Index

Rules and skills for AI coding assistants (Cursor, Claude Code) working on the Synanton Security Provider (authentication boundary + identity-context producer; proposal `docs/proposal.md`).

## Top-level rules (auto-applied by glob)

| File | Glob | Description |
|------|------|-------------|
| [`go-rules.mdc`](./go-rules.mdc) | `**/*.go` | Go code generation: hexagonal arch, ports, authn adapters, testing conventions |
| [`docker-rules.mdc`](./docker-rules.mdc) | `**/docker-compose.yml` | Docker Compose: env ports, dev certs, fail-fast startup |

## Skills (invoke by name)

### Synanton Project Conventions

| Skill | Description |
|-------|-------------|
| `@211-synanton-go-conventions` | Equalix-go-style docs, commit conventions, branch naming, PR flow, maturity tables |

## Project Context

- **Service:** Security Provider — validates authentication evidence (OIDC/OAuth 2.0, mTLS, workload assertions, API credentials), resolves via Identity 1.29, produces signed security contexts
- **Design docs:** Service proposal (`docs/proposal.md`), Synanton Design 1.29 (Identity), Security 1.23 (authorization/masking), Platform API 1.32, Eventing 1.27
- **Joint delivery:** Track B of the Content Service & Security Provider joint plan; `pkg/middleware` is the D.1 handshake surface consumed by content-service
- **Build system:** Go 1.23 + `make` (`build`, `test`, `test-integration`, `vet`, `proto`)
- **Key dependencies:** `lestrrat-go/jwx/v2` (JWT/JWKS), `coreos/go-oidc/v3` (OIDC federation), `spiffe/go-spiffe/v2` (workload identity), `grpc` + `protobuf` (internal RPC)
- **Architecture:** Hexagonal (ports and adapters)
- **Module layout:** `cmd/`, `internal/` (domain, port, authn, identity, context, policy, audit, adapter, config, observability), `pkg/middleware/`, `proto/`, `gen/`, `test/integration/`, `configs/`
