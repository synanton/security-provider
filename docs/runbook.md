# Runbook

Operator guide for the Security Provider. Every claim is pinned to code or an observed run; guidance without provenance is a guess.

## Startup order

1. Parse flags (`--config`), load YAML (if given), apply `SECURITY_PROVIDER_*` overrides (`internal/config.Load`).
2. Validate: TTL bounds against the revocation SLO, provider schema, signing key ≥ 32 bytes. Failure exits 1 before any listener binds.
3. Load trust bundles (mTLS `trust_bundle` must parse, else exit 1).
4. Bind HTTP (`server.http_addr`) and gRPC (`server.grpc_addr`); serve. Plain HTTP without `tls.cert_file` logs a warning and is dev-only.
5. SIGTERM/SIGINT: `grpc.GracefulStop()` + HTTP shutdown with 30s drain, then exit 0.

## Shutdown

Draining, not abrupt: in-flight HTTP completes within 30s; `/health/live` stays 200 through drain so liveness probes do not restart a deliberately-draining pod.

## Configuration table

File keys (`configs/local.yaml` is the commented reference):

| File key | Env override | Default | Notes |
|---|---|---|---|
| `server.http_addr` | `SECURITY_PROVIDER_HTTP_ADDR` | `:8080` | |
| `server.grpc_addr` | `SECURITY_PROVIDER_GRPC_ADDR` | `:9090` | |
| `server.tls.cert_file` / `key_file` | `SECURITY_PROVIDER_TLS_CERT` / `_KEY` | — | Unset = plain HTTP (dev only) |
| `server.tls.client_ca` | `SECURITY_PROVIDER_CLIENT_CA` | — | Unset = no client-cert verification |
| `server.tls.require_client_cert` | — | `false` | `true` = mTLS required on the transport |
| `server.admin_token` | `SECURITY_PROVIDER_ADMIN_TOKEN` | — | Unset = provider admin disabled |
| `server.context_ttl` | — | `5m` | Validated ≤ 15m |
| `server.signing_key` / `_file` | `SECURITY_PROVIDER_SIGNING_KEY` | — | Required, ≥ 32 bytes |
| `identity.endpoint` | `SECURITY_PROVIDER_IDENTITY_ENDPOINT` | `https://identity.internal:8443` | |
| `identity.mode` | `SECURITY_PROVIDER_IDENTITY_MODE` | `stub` | `stub` dev/test fixtures; `http` production |
| `identity.timeout` / `cache_ttl` | — | `2s` / `30s` | `cache_ttl` validated ≤ `slo_local_standard` |
| `local_verification.*` | `SECURITY_PROVIDER_LOCAL_VERIFICATION_ENABLED` | on, 5m/15m | TTLs validated against revocation SLO |
| `revocation.slo_*` | — | 60s/5m/15m/15m | Provisional §11.2 targets; platform SLO ratifies |
| `audit.sink` | `SECURITY_PROVIDER_AUDIT_SINK` | `stdout` | `stdout` \| `discard` |
| `log_level` | `SECURITY_PROVIDER_LOG_LEVEL` | `info` | |

## Health signals

- Liveness `GET /health/live` → 200 `{"status":"live"}` (process alive).
- Readiness `GET /health/ready` → 200 `{"status":"ready"}` when trust bundles load and all providers report healthy; 503 with the unhealthy list otherwise. A provider outage pages trust, not the process: no restart loop, protected operations still fail closed.
- Docker/K8s: the `healthcheck` subcommand probes `/health/ready` (`/security-provider healthcheck --addr 127.0.0.1:8080`).

## Failure modes

| Signal | Meaning | Action |
|---|---|---|
| `401 AUTH_FAILED` spike by mechanism | Credential or trust problem | Check `token_failures`/`cert_failures` reason labels; verify JWKS/trust-bundle freshness |
| `503` on `/health/ready` | Trust dependency degraded | Readiness output names the provider; protected traffic fails closed by design |
| `DEPENDENCY_OUTAGE` on authenticate | IdP/JWKS or Identity 1.29 unreachable | Do not bypass; investigate upstream, watch `revocation_latency_seconds` against the SLO |
| `TENANT_DENIED` / `CONFLICTING_TENANT` | Forged or stale tenant hint | Audit event carries trace; no operator action unless systemic |
| `verifier_key_age_seconds` near TTL | JWKS refresh lagging | Check IdP reachability before the bound bites |

## Rotation / revocation ops

- **Trust bundle:** replace the file, restart (or SIGHUP in Phase 3); readiness flips 503 until the new bundle parses. Overlap old + new CA certs in one bundle for zero-downtime rotation.
- **JWKS:** automatic refresh past the bounded TTL; rotation during overlap is exercised in `TestOIDCKeyRotation`.
- **Provider disablement:** `PATCH /v1/providers/{id}` with `{"enabled": false}` (audited), then remove from config.
- **Principal disablement:** Identity 1.29 is authoritative; call resolution `Invalidate` (or wait out the ≤ 30s cache) so access drops within the revocation SLO.
- **Signing key:** rotate via `signing_key_file` remount + restart; keep TTL (5m) in mind — old contexts die on their own quickly.

## Observability

Prometheus at `/metrics` (see README for the metric list). Logs are JSON via `log/slog`; audit events are `security.audit` records with the allowlisted field set. Never grep logs for tokens — there are none by construction.
