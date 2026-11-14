# Chamuka CredVault

[![CI](https://github.com/chamuka-inc/chamuka-credvault/actions/workflows/ci.yml/badge.svg)](https://github.com/chamuka-inc/chamuka-credvault/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/credvault.svg)](https://crates.io/crates/credvault)
[![Documentation](https://docs.rs/credvault/badge.svg)](https://docs.rs/credvault)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.96+-orange.svg)](https://blog.rust-lang.org/)

Multi-tenant credential vault for AI agent integrations.

A multi-tenant, multi-provider **credential vault**, the load-bearing layer of an
integration platform. It stores per-end-user OAuth tokens and API keys for many
providers, encrypts them at rest, and keeps them alive across expiry, rotation, and
revocation so that a caller can ask for "a valid access token for user U at provider P"
and always get one back (or a clear, typed reason why not).

This is the hard, security-critical core that every integration platform has to build.
Point it at workflows and it's an automation backend; point it at an agent runtime and
it's tool-auth. The vault doesn't care.

---

## Why Rust (this codebase is maintained by AI agents)

The design constraint that dominates every other is that this code is written and
maintained by AI agents, not a standing human team. An agent's characteristic failure
mode is not laziness — it's **confident, plausible, silently-wrong** code, which for a
credential vault means the worst possible bugs: a leaked token, a cross-tenant read, a
refresh race. So the stack is chosen to **distrust the coder as much as possible** and
push correctness into machine-checkable form:

- **Secrets can't be logged.** Plaintext tokens live in `SecretString` (`src/crypto/secret.rs`).
  The type has no `Display`, and its `Debug` prints `REDACTED`. "Don't log the secret"
  is therefore not a code-review rule an agent must remember — it's a compile-time
  behavior the type enforces. Plaintext is exposed in exactly **one** function in the
  whole crate: the credentials response handler.
- **One refresh path.** Just-in-time fetch and the background worker both go through a
  single `SELECT ... FOR UPDATE` row lock (`service::refresh_locked`). There is no second
  code path to keep consistent, so the refresh race can't be reintroduced in one place
  while being fixed in another.
- **Providers are plugins, not code.** There are no built-in providers in the binary.
  Every provider is a declarative JSON manifest (a `ProviderSpec` plus `id`/`version`),
  discovered at startup from the directories named by `VAULT_PLUGIN_DIRS` — adding an
  integration is dropping a file in, never a new code path. The shipped defaults are simply
  the manifests in `plugins/default`, loaded through the exact same mechanism as any
  third-party plugin. Provider quirks (Google's offline consent params, Slack's nested
  token JSON, Notion's Basic-auth token call, Stripe's API-key model) are declarative
  fields, so they can't hide control-flow bugs. The default set spans the variations —
  Google, GitHub, Slack, Notion, Stripe, X, GitLab, Spotify, Microsoft, Zoom, SendGrid
  (POST vs HTTP Basic client auth, PKCE, refresh-token rotation, nested token paths, and
  API-key-only).
- **CI is the always-present reviewer.** `cargo fmt --check`, `clippy -D warnings`, the
  type-checked test suite, and a real-Postgres integration job all gate every change.

The README and these tests are deliberately the source of truth: an agent reliably
re-derives behavior from types and tests, and unreliably remembers prose.

---

## Architecture

```
                    ┌────────────────────────────────────────────┐
   caller  ──────►  │  web (axum)   stateless HTTP, validates,    │
   "token for U@P"  │               exposes secret in ONE place   │
                    └───────────────┬────────────────────────────┘
                                    │  service::*  (the core)
                    ┌───────────────┴────────────────────────────┐
   provider  ◄────► │  oauth engine + transport (reqwest)         │
   token endpoints  │  crypto keyring (AES-256-GCM, versioned)    │
                    └───────────────┬────────────────────────────┘
                                    │  sqlx (runtime-checked SQL)
                              ┌─────┴──────┐
                              │  Postgres  │   encrypted tokens, FOR UPDATE locks
                              └─────┬──────┘
                                    │  due_for_refresh / refresh_one
                    ┌───────────────┴────────────────────────────┐
   (own process)    │  worker   interval scan, per-item tx,       │
                    │           graceful SIGTERM shutdown         │
                    └────────────────────────────────────────────┘
```

`web` and `worker` are independent processes from one binary; migrations run as a
separate one-shot release step. Scale `web` for read traffic and `worker` for refresh
throughput, independently.

### Workspace layout

credvault is a Cargo workspace; the `credvault` crate holds the library and the
`credvault` service binary. A fuller tour lives in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
crates/
  credvault/                     the library + `credvault` service binary
    src/
      crypto/   secret.rs        SecretString (no-leak) + versioned AES-256-GCM-SIV keyring
      oauth/    pkce.rs          one generic authorize/exchange/refresh/revoke engine; RFC 7636 PKCE
      http/     api.rs auth.rs   axum router + edge validation + the one secret exposure;
                ratelimit.rs     API-key→tenant extractors; per-IP limiter;
                transport.rs     the outbound TokenTransport (reqwest impl + test double)
      service.rs                 the core: tenants, connect, the single locked refresh path
      models.rs                  Connection row, status enum, AAD derivation, public() projection
      state.rs                   signed, expiring OAuth `state` (CSRF), constant-time verify
      db.rs                      backend selection (Postgres prod / SQLite tests) behind one SQL set
      config.rs error.rs         twelve-factor config; typed errors → stable HTTP codes
      providers/                 ProviderSpec manifest + plugin-directory discovery
    migrations/  tests/
plugins/default/                 the shipped provider manifests (see plugins/README.md)
docs/                            DEPLOYMENT, ARCHITECTURE, and the docs index
```

---

## Quickstart (Docker)

```bash
cp .env.example .env          # then replace the dev secrets (see "Config")
docker compose up --build     # db → migrate (one-shot) → web + worker
```

```bash
# create a tenant (admin-only). The response returns the tenant's api_key ONCE —
# store it; only its hash is kept server-side.
curl -s localhost:8000/v1/tenants \
  -H "Authorization: Bearer $VAULT_ADMIN_TOKEN" \
  -H 'content-type: application/json' -d '{"name":"acme"}'
# => {"id":"<id>","name":"acme","api_key":"cvk_..."}

# Every tenant-scoped call authenticates with that key; the tenant is derived from it,
# never sent in the request (no cross-tenant access is expressible).
TENANT_KEY=cvk_...

# store an API-key credential (no OAuth dance needed for key-based providers)
curl -s localhost:8000/v1/connect/stripe/api-key \
  -H "Authorization: Bearer $TENANT_KEY" -H 'content-type: application/json' \
  -d '{"external_user_id":"user-1","api_key":"sk_test_..."}'

# fetch a guaranteed-valid token (refreshes under a row lock if near expiry)
curl -s "localhost:8000/v1/credentials/stripe?external_user_id=user-1" \
  -H "Authorization: Bearer $TENANT_KEY"
```

## Quickstart (local binary)

```bash
# Run from the workspace root; -p credvault selects the service binary.
cargo run -p credvault -- gen-key          # generate an encryption key (and a state secret)
cargo run -p credvault -- list-providers   # show catalog + which are configured via env
# with VAULT_DATABASE_URL pointing at Postgres:
cargo run -p credvault -- migrate
cargo run -p credvault -- web              # or: worker
```

---

## HTTP API

Authentication is by bearer token. **admin** = `VAULT_ADMIN_TOKEN` (tenant provisioning
only). **tenant** = the per-tenant API key issued at creation; the `tenant_id` is resolved
from it server-side and is never accepted from the request. The OAuth callback is the only
unauthenticated route — it is gated by the signed, single-use `state` token instead.

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET  | `/healthz` | — | Liveness (no DB). |
| GET  | `/readyz` | — | Readiness (`SELECT 1`). |
| GET  | `/v1/providers` | — | Catalog + per-provider `configured` flag. |
| POST | `/v1/tenants` | admin bearer | Create a tenant; returns its API key once. |
| GET  | `/v1/connect/:provider/start` | tenant bearer | Begin OAuth; returns `authorize_url` (or 302 with `?redirect=true`). |
| GET  | `/v1/connect/:provider/callback` | signed state | OAuth redirect target; exchanges code, stores tokens. |
| POST | `/v1/connect/:provider/api-key` | tenant bearer | Store an API-key credential. |
| GET  | `/v1/credentials/:provider` | tenant bearer | **The endpoint.** Returns a valid `access_token`, refreshing if needed. |
| GET  | `/v1/connections` | tenant bearer | List the tenant's connections (no secrets). |
| DELETE | `/v1/connections/:id` | tenant bearer | Revoke/delete a connection (tenant-scoped). |

`:provider` is one of `google`, `github`, `slack`, `notion`, `stripe`.
Connection identity is `(tenant_id, provider, external_user_id, account_key)`;
`account_key` defaults to `"default"` and lets one end-user hold multiple accounts at
the same provider.

> Note on auth scope: the credential and management endpoints are unauthenticated in this
> reference build and are meant to sit behind your platform's own service-to-service auth
> (mTLS / gateway / network policy). Tenant creation is the one admin-gated action. See
> [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for hardening.

---

## Adding a provider

Providers are **plugins**: one JSON manifest per provider, in **one** format. There are no
built-ins compiled into the binary — the shipped defaults in `plugins/default/` and
anything you add are the same shape, the same validation, the same code path. To add a
provider, drop a `<id>.json` manifest into a directory on `VAULT_PLUGIN_DIRS`:

```json
{
  "manifest_version": 1,
  "id": "linear",
  "version": "1.0.0",
  "auth_type": "oauth2",
  "authorize_url": "https://linear.app/oauth/authorize",
  "token_url": "https://api.linear.app/oauth/token",
  "client_id_env": "LINEAR_CLIENT_ID",
  "client_secret_env": "LINEAR_CLIENT_SECRET",
  "default_scopes": ["read", "write"]
}
```

`id` is the provider key used in routes (`/v1/connect/linear/...`) and storage; `version`
is packaging metadata surfaced by discovery. Quirk knobs (all declarative, all defaulted,
all JSON fields): `token_auth_style` (`"post"` body vs `"basic"`), `token_accept_json`,
`token_path` (dotted path into a nested token JSON, e.g. Slack's `authed_user.access_token`),
`extra_authorize_params` (e.g. Google's `[["access_type","offline"],["prompt","consent"]]`),
`refresh_token_rotates` (whether the provider issues a new refresh token on refresh),
and `uses_pkce` (drive the flow with PKCE — see below). For providers whose endpoints
embed a per-customer host/tenant (e.g. Workday), see **Tenant-scoped providers** below.

### OAuth flow: PKCE & revocation

The engine runs the authorization-code flow with **PKCE (RFC 7636, S256)** for any
provider with `uses_pkce: true` — required by providers like X/Twitter, harmless
defense-in-depth elsewhere. Since we're a confidential client, the `code_verifier` is
sent *alongside* the client secret. Each authorization generates a fresh random verifier;
only its S256 challenge travels in the authorize URL, and the verifier itself is stored
**server-side, encrypted** (identity-bound AAD) in the single-use `oauth_flows` row keyed
by the state nonce — then decrypted and consumed once at the callback. The default `x`
provider plugin exercises this end to end.

On disconnect, `DELETE /v1/connections/:id` **revokes the token upstream** (RFC 7009,
best-effort) for providers that declare a `revoke_url`, then removes the local row — so a
deleted credential is killed at the provider, not just forgotten locally.

### Tenant-scoped (instance) providers

Some providers (e.g. Workday) are multi-tenant with a **per-customer** host and tenant in
every URL — the authorize/token endpoints *and* the API base. A plugin marks itself
tenant-scoped with two declarative fields:

```jsonc
{
  "id": "workday",
  "auth_type": "oauth2",
  "authorize_url": "https://{host}/ccx/oauth2/{tenant}/authorize",
  "token_url":     "https://{host}/ccx/oauth2/{tenant}/token",
  "client_id_env": "WORKDAY_CLIENT_ID",
  "client_secret_env": "WORKDAY_CLIENT_SECRET",
  "instance_vars": ["host", "tenant"],            // template variables in the URLs
  "instance_host_suffixes": [".workday.com"]       // allowed hosts (required when instance_vars is set)
}
```

The caller supplies the values per connection via the `instance` query parameter on
`connect/{provider}/start` — a JSON object naming every `instance_var`, e.g.
`?instance={"host":"…","tenant":"…"}`. That instance is stored on the connection (carried
through the single-use flow row), used to rebuild the per-customer endpoints on every code
exchange, refresh, and revoke, and returned on the credentials response so the caller can
build the provider's API base.

Because the host is **caller-supplied**, the resolved URLs are SSRF-checked **and**
matched against `instance_host_suffixes` at *use* time — not just at manifest load — so a
tenant cannot point the vault at an arbitrary origin and exfiltrate the deployment's client
secret. Each suffix must begin with `.` (so `.workday.com` matches `x.workday.com` but not
`evilworkday.com`). At manifest load, the templated URLs are validated structurally: https
scheme, and every `{placeholder}` must be a declared `instance_var`. The OAuth engine is
unchanged — the service resolves a per-connection spec and the same single code path runs.

### Discovery, overrides & validation

`VAULT_PLUGIN_DIRS` is a colon-separated list of directories (like `PATH`). Every `*.json`
file in each is one provider manifest, and **the filename is the provider id** (`github.json`
→ `github`); a manifest whose `id` field disagrees with its filename is rejected. **Later
directories win by `id`**, so an operator's `github.json` cleanly overrides a shipped default
without editing it. An unset/empty variable loads **zero** providers — the core is lean, and
the default directory is what makes it useful. Every manifest is validated at startup (even
one that's later shadowed), so an invalid plugin **fails fast** rather than at first request.

```bash
# Defaults plus your own, your dir overriding by id:
VAULT_PLUGIN_DIRS=plugins/default:/etc/credvault/plugins cargo run -p credvault -- list-providers

# Validate a directory without a database (CI / pre-flight); non-zero on any bad manifest:
VAULT_PLUGIN_DIRS=/etc/credvault/plugins cargo run -p credvault -- validate-plugins
```

A manifest mirrors `ProviderSpec` field-for-field plus `id`/`version`, with the same
defaulted quirk knobs. `auth_type` is `"oauth2"` or `"api_key"`. Secrets never go in a
manifest: `client_id_env` / `client_secret_env` name the env vars the credentials are read
from, so manifests stay non-secret and committable.

---

## Config

All configuration is environment variables (Twelve-Factor). Full list with defaults in
`.env.example`. The essentials:

| Var | Required | Meaning |
|-----|----------|---------|
| `VAULT_DATABASE_URL` | yes | Postgres connection string. |
| `VAULT_KEYS` | yes (prod) | JSON `{"<ver>":"<base64url 32-byte key>"}`. Generate with `gen-key`. |
| `VAULT_ACTIVE_KEY` | yes (prod) | Which key version encrypts new writes. |
| `VAULT_STATE_SECRET` | **yes** | HMAC secret for signed OAuth state. No default; ≥ 32 bytes; or `*_FILE`. |
| `VAULT_ADMIN_TOKEN` | **yes** | Bearer token for tenant creation. No default; ≥ 32 bytes; or `*_FILE`. |
| `VAULT_PUBLIC_BASE_URL` | yes | Public origin for OAuth callbacks. |
| `VAULT_PLUGIN_DIRS` | yes (to have any providers) | Colon-separated provider-plugin dirs; later wins by `id`. Unset = zero providers. Image defaults to `/app/plugins/default`. |
| `VAULT_BIND_HOST` | no | Bind address (default `127.0.0.1`; set `0.0.0.0` to expose). |
| `VAULT_ALLOW_INSECURE_HTTP` | no | `1` permits http provider endpoints + skips DB-TLS check (dev only). |
| `<PROVIDER>_CLIENT_ID` / `_SECRET` | per provider | OAuth client creds for providers you enable. |

Any secret var also accepts a `*_FILE` variant (e.g. `VAULT_STATE_SECRET_FILE`) pointing at
a mounted file — preferred in production so secrets never sit in the process environment.

### Key rotation

Keys are versioned. To rotate: add a new version to `VAULT_KEYS`, set
`VAULT_ACTIVE_KEY` to it (new writes use it; old rows still decrypt by their stored
version), then run `credvault rotate-keys` to re-encrypt existing rows under the active
key. No downtime, no flag-day.

---

## Tests & what's actually verified

```bash
cargo test --workspace                     # unit + integration (Postgres DB test auto-skips)
cargo test -p credvault --features sqlite  # adds a real, in-process DB lifecycle — no Postgres
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --check
cargo build --release --locked
# or simply: make ci
```

Verified locally with no external services: crypto round-trip / AAD / version /
rotation, secret redaction (Debug never leaks plaintext), signed-state issue / verify /
tamper / expiry, default provider-plugin quirks, plugin-directory discovery / override /
filename-id / validation, PKCE (RFC 7636 S256 vector + authorize/exchange wiring), token
revocation, and the OAuth engine (code exchange + refresh classification) via an in-memory
transport double.

`cargo test -p credvault --features sqlite` additionally runs the **full database lifecycle**
(`crates/credvault/tests/service_sqlite.rs`) against an in-process SQLite: tenant creation, OAuth code
exchange, encrypted upsert, the just-in-time refresh inside a transaction, cross-tenant
isolation, the API-key path, list/delete, and a PKCE-connect + revoke-on-disconnect
flow — **34 tests under `--features sqlite` (33 on the default build), all green, with no
external database**. The service shares one set of SQL across both backends; only the row-lock
clause and the "now" expression differ (see `crates/credvault/src/db.rs`).

SQLite serialises writers itself, so it cannot reproduce Postgres's row-level
`SELECT ... FOR UPDATE` concurrency semantics. That specific guarantee is covered by
`crates/credvault/tests/service_pg.rs`, gated on `DATABASE_URL` and run in CI against a real Postgres
service. So: SQLite proves the lifecycle logic locally; Postgres proves the locking in
CI.

---

## Contributing

Contributions are welcome. The CI gates (`cargo fmt --check`, `clippy -D warnings`, the
full test suite, and a real-Postgres integration job) run on every pull request and are
the contract — if they pass, the change is in good shape. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the workflow and [SECURITY.md](SECURITY.md) for
how to report a vulnerability privately.

Please review the [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Security

Report vulnerabilities to [security@chamuka.ai](mailto:security@chamuka.ai). See [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this work by you, as defined in the Apache-2.0 license, shall be licensed as
above, without any additional terms or conditions.

---

Part of [Chamuka Labs](https://chamuka.ai), an applied AI lab.
