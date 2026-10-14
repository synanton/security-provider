# ADR-004: HTTP routing — standard library ServeMux

- Status: Accepted
- Date: 2026-10-14

## Context

The stack permits `go-chi/chi` or the standard library's `http.ServeMux`. Sibling services split: equalix-go uses chi v5, content-service uses stdlib method patterns (Go 1.22+).

## Decision

Use the standard library `http.ServeMux` with method patterns (`"POST /v1/authenticate"`).

- The route tree is small (nine endpoints) with no nested groups, no middleware chains beyond auth gating, and path parameters limited to `{id}` — all covered by stdlib patterns.
- One fewer dependency in the trust-sensitive path; `go.mod` stays auditable.
- Consistency with content-service, the first middleware consumer, matters more than consistency with equalix-go here.

## Consequences

- Revisit if the route tree grows nested versioned groups or per-route middleware chains that stdlib patterns express poorly. That revisit is itself an ADR.
- `PathValue("id")` is the only parameter extraction; keep it that way until the revisit.
