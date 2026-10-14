# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added

- Phase 1 (joint-plan B1): mTLS/workload identity adapters, stub Identity 1.29 resolution with bounded cache, signed security contexts, HTTP + gRPC surfaces, importable `pkg/middleware` (HTTP + gRPC).
- OIDC adapter (Phase 2 scope, ahead of plan): issuer/audience/algorithm/scope enforcement, JWKS refresh with bounded TTL, revocation-signal hook, rotation coverage against an in-test IdP.
- API-key adapter for constrained legacy integrations (verifier hashes, expiry, revocation).
- Local-verification policy (§9.1) and revocation SLO (§11.2) as validated configuration.
- ADRs 001–004 (deployment shape, provider interface, local-verification/SLO, HTTP routing) and draft threat model.
- Markdown reformats of `README.md` and `docs/proposal.md` (equalix-go style).

## [0.1.0] - 2026-10-14

- Initial Phase 1 deliverable: see Unreleased. First tagged snapshot of the service + middleware + docs skeleton.
