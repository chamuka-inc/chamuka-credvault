# Deployment

This service is twelve-factor: one stateless binary, all config via environment, logs as
JSON to stdout, processes scaled independently. It runs the same on a single VM, Docker
Compose, or Kubernetes.

## Processes

One image, selected at launch by the first argument (or `VAULT_PROCESS`):

| Command | Role | Scaling | Notes |
|---------|------|---------|-------|
| `web` | HTTP API | horizontal, stateless | Behind your gateway/load balancer. |
| `worker` | Background token refresh | horizontal, safe | Row locks (`FOR UPDATE`) make concurrent workers race-free. |
| `migrate` | Apply DB migrations | one-shot, run once per release | Release phase, before new `web`/`worker` start. |
| `rotate-keys` | Re-encrypt rows under the active key | one-shot, on demand | After adding a new key version. |
| `gen-key` / `list-providers` / `healthcheck` | Utilities | n/a | No DB required. |

Web and worker hold no local state; restart or scale either freely. Multiple workers are
safe and increase refresh throughput — each item is claimed under a row lock, so no two
workers touch the same connection at once.

## Release sequence

```
1. build & push image
2. run:  credvault migrate        # one-shot, must exit 0
3. roll: credvault web   (N replicas)
4. roll: credvault worker (M replicas)
```

Migrations own the schema; the app never `CREATE TABLE`s at boot. Forward-only
migrations are the contract — `web`/`worker` images should not run against a database
older than their migration set.

## Required configuration (production)

Generate real secrets — never ship the dev defaults in `.env.example`:

```bash
credvault gen-key      # run 3x: one for VAULT_KEYS, one for VAULT_STATE_SECRET,
                       # one for VAULT_ADMIN_TOKEN
```

Minimum prod set: `VAULT_DATABASE_URL`, `VAULT_KEYS`, `VAULT_ACTIVE_KEY`,
`VAULT_STATE_SECRET`, `VAULT_ADMIN_TOKEN`, `VAULT_PUBLIC_BASE_URL`, plus
`<PROVIDER>_CLIENT_ID` / `_SECRET` for each OAuth provider you enable. Inject these from
your platform's secret manager (Kubernetes Secrets, AWS Secrets Manager, Vault, etc.) as
environment variables — not baked into the image.

Optionally extend the provider catalog without rebuilding via `VAULT_PROVIDERS_FILE`
(a path to a JSON array) and/or `VAULT_PROVIDERS_JSON` (inline JSON). Built-ins are
always present; an entry whose `name` matches one overrides it. The catalog is parsed
and validated at startup, so a malformed config **fails the process on deploy** rather
than at first request. Only non-secret metadata goes in JSON — credentials are still
read from the `*_CLIENT_ID` / `*_CLIENT_SECRET` env vars the JSON names.

## Hardening checklist

- **Front the API with service-to-service auth.** The credential/management endpoints
  are unauthenticated by design and assume a trusted caller. Put them behind mTLS, a
  signed-JWT gateway, or a private network boundary. Only tenant creation is admin-gated
  in-process.
- **TLS everywhere.** Terminate TLS at the gateway; keep the DB connection on
  `sslmode=require` or stronger (set in `VAULT_DATABASE_URL`).
- **Least-privilege DB role.** The app needs DML on its two tables; it does not need
  superuser or schema-owner rights at runtime (only the `migrate` step does).
- **Rotate encryption keys periodically.** Add a version, flip `VAULT_ACTIVE_KEY`, run
  `rotate-keys`. Old rows remain readable via their stored version; no flag-day.
- **Run as non-root.** The image already does (`uid 10001`, no shell needed).
- **Scope provider OAuth apps narrowly.** Request only the scopes you use; they're
  declared per provider in the catalog.

## Health & observability

- `GET /healthz` — liveness, no DB. Use for container/orchestrator liveness probes.
- `GET /readyz` — readiness, runs `SELECT 1`. Use for readiness/traffic-gating probes.
- The container `HEALTHCHECK` calls the binary's own `healthcheck` subcommand (no
  curl/wget in the image).
- Logs are structured JSON on stdout; control verbosity with `RUST_LOG`
  (e.g. `info`, or `credvault=debug,info`). Ship stdout to your log pipeline. Secrets are
  never logged — the `SecretString` type makes that a property of the code, not a habit.

## Kubernetes sketch

- Two Deployments (`web`, `worker`) from the same image, differing only in `args`.
- One `Job` per release running `args: ["migrate"]`, gated before the rollouts (e.g. an
  Argo/Helm pre-upgrade hook).
- `web` Deployment: `readinessProbe` → `/readyz`, `livenessProbe` → `/healthz`.
- Secrets via a `Secret` mounted as env; config via a `ConfigMap` for the non-secret
  tunables.
- `worker` needs no Service or probes endpoint; give it a `terminationGracePeriodSeconds`
  comfortably above one refresh iteration so in-flight refreshes finish — it handles
  SIGTERM and drains gracefully.

## Backups & DR

The only durable state is Postgres. Back it up as you would any primary datastore
(PITR / snapshots). Encryption keys live **outside** the database (in `VAULT_KEYS`); a
database backup is useless without the keyring, so store and rotate the keyring with at
least the same rigor as the DB — and never in the same blast radius.
