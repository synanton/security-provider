# 211-synanton-go-conventions — Reference

Conventions extracted from equalix-go and applied across content-service and security-provider. New Go services in the family copy this skeleton verbatim, then fill in domain specifics.

## Docs skeleton (every service)

| File | Purpose | Non-negotiables |
|---|---|---|
| `README.md` | Identity + entry point | Badges (go, license, status); `Status` section with freshness line; maturity table (see below); What It Is; architecture diagram; quick start; API table; config reference; observability; development; roadmap |
| `CONTRIBUTING.md` | Contribution bar | Prerequisites; setup; repo layout with the I/O rule; workflow; branch naming; commit conventions; testing-requirements table; training/production gates; review checklist |
| `docs/IMPLEMENTATION.md` | What to build next | Guiding principles; phases with tasks + definitions of done; "What to Do Today"; per-phase done criteria |
| `docs/design.md` | Normative behavior | Evidence kinds, context schema, trust policy, API, security, config |
| `docs/api.md` | REST contract | Conventions (auth, tenant scope, error shape) + per-endpoint request/response + curl cookbook |
| `docs/runbook.md` | Operator guide | Startup order, shutdown, config table, health signals, failure modes, rotation/revocation ops, observability. Every claim code-pinned or observed-and-dated; guidance without provenance is a guess |
| `docs/architecture.md` | Hexagonal diagram | Ports/adapters boxes; what is pure vs adapter; phase notes |
| `CHANGELOG.md` | Keep-a-Changelog | Added/Changed/Deprecated/Removed/Fixed/Security per version; spec records why, changelog records what |
| `VERSION` | Single source of truth | Every build path stamps from here (`-ldflags -X main.version=$(VERSION)`); missing file falls back to `dev`, never fails the build |

## Maturity table rules

The README maturity table is evidence-gated:

- `⬜` = not yet; nothing is claimed before its evidence exists.
- Deferred rows are "deferred by decision, not pending by oversight" — say so explicitly.
- The italic freshness line under Status names the latest phase-landing merge and its date. Bump on phase transitions (merged epic scope or gate), **not every merge**.

## Testing-requirements table (CONTRIBUTING)

| Layer | Tool | Required Coverage |
|---|---|---|
| Domain core | `go test`, table-driven | 90%+ |
| Adapters | `httptest` / `bufconn` (+ testcontainers where datastores exist) | 80%+ |
| Conformance | Custom harness | All context-shape invariants |
| Security | Negative tests | Forged tenant, unsigned identity, cross-tenant, outage fail-closed |
| Load | `k6`/`vegeta` | Target throughput |

Every PR changing domain logic includes unit tests; every adapter PR includes integration tests; every trust-behavior PR updates conformance.

## Commits, branches, PRs

- Conventional commits: `feat(authn): ...`, `fix(oidc): ...`, `test(integration): ...`, `docs(runbook): ...`, `chore: ...`.
- Branch prefixes: `SEC-` (security-provider), `CNT-` (content-service), `EQLX-` (equalix-go). Never push directly to `main`.
- Stage explicit paths after `git status`; never blind `git add -A` on an unverified tree.
- Merging is manual — a maintainer merges after review. Do not merge your own PR without approval.
- Keep comments concise; never use comments for chain-of-thought. Doc comments on exported identifiers only.

## Authority invariants (security-provider additions)

- Authentication never implies authorization. No masking or representation fields in the security context — ever.
- Identity 1.29 owns principals, mappings, tenant membership, delegation. This repo consumes or fails closed.
- Unsigned identity headers are never authoritative. Tenant comes from the validated context.
- No raw credentials, complete tokens, or private keys in logs, traces, errors, or metric labels.

## Review checklist (minimum)

- Matches the spec (`docs/design.md` + proposal + Identity 1.29 / Security 1.23)?
- Domain free of I/O dependencies; new ports are interfaces?
- Errors wrapped with context; tenant checks on every path?
- Cross-tenant failures indistinguishable where unauthenticated, explicit where authenticated?
- Privileged changes audited with actor + reason?
- Race detector clean; new metrics registered and documented?
- CHANGELOG updated if user-visible?
