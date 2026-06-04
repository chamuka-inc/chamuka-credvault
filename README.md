# credvault

A multi-tenant, multi-provider **credential vault** — the load-bearing layer of an
integration platform. It stores per-end-user OAuth tokens and API keys for many
providers, encrypts them at rest, and keeps them alive across expiry, rotation, and
revocation so that a caller can ask for "a valid access token for user U at provider P"
and always get one back (or a clear, typed reason why not).

This is the hard, security-critical core that products like Pipedream and Composio are
built around. Point it at workflows and it's an automation backend; point it at an agent
runtime and it's tool-auth. The vault doesn't care.

---

## Why Rust (this codebase is maintained by AI agents)

The design constraint that dominates every other is that this code is written and
maintained by AI agents, not a standing human team. An agent's characteristic failure
mode is not laziness — it's **confident, plausible, silently-wrong** code, which for a
credential vault means the worst possible bugs: a leaked token, a cross-tenant read, a
refresh race. So the stack is chosen to **distrust the coder as much as possible** and
push correctness into machine-checkable form:

- **Secrets can't be logged.** Plaintext tokens live in `SecretString` (`src/secret.rs`).
  The type has no `Display`, and its `Debug` prints `REDACTED`. "Don't log the secret"
  is therefore not a code-review rule an agent must remember — it's a compile/September
  behavior the type enforces. Plaintext is exposed in exactly **one** function in the
  whole crate: the credentials response handler.
- **One refresh path.** Just-in-time fetch and the background worker both go through a
  single `SELECT ... FOR UPDATE` row lock (`service::refresh_locked`). There is no second
  code path to keep consistent, so the refresh race can't be reintroduced in one place
  while being fixed in another.
- **Providers are data, not code.** The built-in catalog is a bundled JSON document
  (`src/providers/catalog.json`), parsed and validated like any runtime-supplied
  provider — adding an integration is a data edit, never a new code path. Provider quirks (Google's offline
  consent params, Slack's nested token JSON, Notion's Basic-auth token call, Stripe's
  API-key model) are declarative fields, so they can't hide control-flow bugs. Ships with
  eleven built-ins spanning the variations — Google, GitHub, Slack, Notion, Stripe, X,
  GitLab, Spotify, Microsoft, Zoom, SendGrid (POST vs HTTP Basic client auth, PKCE,
  refresh-token rotation, nested token paths, and API-key-only).
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

### Source map

| File | Responsibility |
|------|----------------|
| `src/secret.rs` | `SecretString` re-exports; the no-leak guarantee. |
| `src/crypto.rs` | Versioned AES-256-GCM keyring; `v{ver}.{b64(nonce\|ct)}`; AAD-bound. |
| `src/state.rs` | Signed, expiring OAuth `state` (CSRF), constant-time verify. |
| `src/models.rs` | `Connection` row, status enum, AAD derivation, `public()` projection. |
| `src/providers/` | `ProviderSpec` + bundled `catalog.json` built-ins + runtime JSON loading. |
| `src/transport.rs` | `TokenTransport` trait + reqwest impl + test double. |
| `src/oauth.rs` | One generic authorize / code-exchange / refresh / revoke engine (PKCE-aware). |
| `src/pkce.rs` | RFC 7636 S256: stateless verifier derived from the state nonce. |
| `src/service.rs` | The core: tenants, connect, the single locked refresh path, worker queries. |
| `src/db.rs` | Backend selection (Postgres prod / SQLite tests) behind one set of SQL. |
| `src/pipedream.rs` | Import Pipedream's app catalog into provider JSON (`import-pipedream` bin). |
| `src/api.rs` | Axum router, edge validation, admin auth, the one secret exposure. |
| `src/worker.rs` | Background refresh loop with graceful shutdown. |
| `src/config.rs` | Twelve-factor config from env. |
| `src/error.rs` | Typed errors → stable HTTP status + code; DB detail never leaks. |

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
cargo run -- gen-key          # generate an encryption key (and a state secret)
cargo run -- list-providers   # show catalog + which are configured via env
# with VAULT_DATABASE_URL pointing at Postgres:
cargo run -- migrate
cargo run -- web              # or: worker
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
> DEPLOYMENT.md for hardening.

---

## Adding a provider

Providers are data in **one** JSON format. The built-in catalog
(`src/providers/catalog.json`, bundled into the binary) and anything you add at runtime
use the same shape and the same validation — there's no separate "code" path. To ship a
new built-in, append an entry to `catalog.json`; to add one without rebuilding, supply
it at runtime (next section). Either way:

```json
{
  "name": "linear",
  "auth_type": "oauth2",
  "authorize_url": "https://linear.app/oauth/authorize",
  "token_url": "https://api.linear.app/oauth/token",
  "client_id_env": "LINEAR_CLIENT_ID",
  "client_secret_env": "LINEAR_CLIENT_SECRET",
  "default_scopes": ["read", "write"]
}
```

Quirk knobs (all declarative, all defaulted, all JSON fields):
`token_auth_style` (`"post"` body vs `"basic"`), `token_accept_json`, `token_path`
(dotted path into a nested token JSON, e.g. Slack's `authed_user.access_token`),
`extra_authorize_params` (e.g. Google's `[["access_type","offline"],["prompt","consent"]]`),
`refresh_token_rotates` (whether the provider issues a new refresh token on refresh),
and `uses_pkce` (drive the flow with PKCE — see below).

### OAuth flow: PKCE & revocation

The engine runs the authorization-code flow with **PKCE (RFC 7636, S256)** for any
provider with `uses_pkce: true` — required by providers like X/Twitter, harmless
defense-in-depth elsewhere. Since we're a confidential client, the `code_verifier` is
sent *alongside* the client secret. PKCE is **stateless**: the verifier is derived from
the signed-state nonce (`HMAC(state_secret, nonce)`), so only the public challenge
travels in the authorize URL and the verifier is recomputed at the callback — no session
store, no extra DB column. The built-in `x` provider exercises this end to end.

On disconnect, `DELETE /v1/connections/:id` **revokes the token upstream** (RFC 7009,
best-effort) for providers that declare a `revoke_url`, then removes the local row — so a
deleted credential is killed at the provider, not just forgotten locally.

### …without recompiling

The same providers can be supplied as JSON at runtime — built-ins are always present,
and a JSON entry whose `name` matches one **overrides** it; new names are **added**.
Point at a file and/or pass inline JSON; both are merged (inline wins on conflict),
and an invalid catalog **fails fast at startup** rather than at first request:

```bash
VAULT_PROVIDERS_FILE=providers.example.json cargo run -- list-providers
# or inline:
VAULT_PROVIDERS_JSON='[{"name":"linear","auth_type":"oauth2",
  "authorize_url":"https://linear.app/oauth/authorize",
  "token_url":"https://api.linear.app/oauth/token",
  "client_id_env":"LINEAR_CLIENT_ID","client_secret_env":"LINEAR_CLIENT_SECRET",
  "default_scopes":["read"]}]' cargo run -- list-providers
```

The JSON shape mirrors `ProviderSpec` field-for-field (see `providers.example.json`),
with the same defaulted quirk knobs. `auth_type` is `"oauth2"` or `"api_key"`.
Secrets never go in JSON: `client_id_env` / `client_secret_env` name the env vars the
credentials are read from, so the catalog stays non-secret and committable.

### …from Pipedream's catalog

`import-pipedream` turns a local clone of [Pipedream's open-source
components](https://github.com/PipedreamHQ/pipedream/tree/master/components) into a
provider file this vault can load. Each app is one `components/<slug>/<slug>.app.mjs`
exporting `{ type:"app", app:"<slug>", methods }`; the importer reads the slug and
infers the auth type from how the methods consume the credential
(`this.$auth.oauth_access_token` → OAuth2, otherwise key-based).

```bash
git clone --depth 1 https://github.com/PipedreamHQ/pipedream
import-pipedream pipedream/components --out providers.pipedream.json
# -> providers.pipedream.json        directly loadable (key-based apps + completed OAuth)
# -> providers.pipedream.todo.json   overlay skeleton: OAuth apps still missing endpoints
```

**Important limitation, by design on Pipedream's side:** Pipedream brokers the OAuth
handshake on its own platform, so the public components contain **no `authorize_url`,
`token_url`, or scopes**. That means:

- **key-based apps import complete** — an API-key provider needs no endpoints;
- **OAuth apps import as skeletons** (identity + `auth_type` + conventional
  `<SLUG>_CLIENT_ID/_SECRET` env names) and are written to the `*.todo.json` overlay
  skeleton until you supply endpoints.

Fill the skeleton from each provider's own OAuth docs (see
`pipedream.overlay.example.json`) and re-run to complete them:

```bash
import-pipedream pipedream/components \
  --overlay pipedream.overlay.example.json --out providers.pipedream.json
VAULT_PROVIDERS_FILE=providers.pipedream.json credvault list-providers
```

The importer validates every emitted entry against the same rules the runtime loader
uses, so an OAuth app never lands in the loadable file without its endpoints. (Pipedream
also exposes an exact `auth_type` per app via its `/v1/connect/apps` API if you prefer an
authoritative classification over the source-scan heuristic.)

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
cargo test                       # unit + integration (Postgres DB test auto-skips)
cargo test --features sqlite     # adds a real, in-process DB lifecycle — no Postgres
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo build --release --locked
```

Verified locally with no external services: crypto round-trip / AAD / version /
rotation, secret redaction (Debug never leaks plaintext), signed-state issue / verify /
tamper / expiry, provider catalog quirks, runtime JSON provider add/override, the
Pipedream importer (slug + auth-type parsing, overlay completion), PKCE (RFC 7636 S256
vector + stateless verifier derivation + authorize/exchange wiring), token revocation,
and the OAuth engine (code exchange + refresh classification) via an in-memory transport
double.

`cargo test --features sqlite` additionally runs the **full database lifecycle**
(`tests/service_sqlite.rs`) against an in-process SQLite: tenant creation, OAuth code
exchange, encrypted upsert, the just-in-time refresh inside a transaction, cross-tenant
isolation, the API-key path, list/delete, and a PKCE-connect + revoke-on-disconnect
flow — **34 tests under `--features sqlite` (33 on the default build), all green, with no
external database**. The service shares one set of SQL across both backends; only the row-lock
clause and the "now" expression differ (see `src/db.rs`).

SQLite serialises writers itself, so it cannot reproduce Postgres's row-level
`SELECT ... FOR UPDATE` concurrency semantics. That specific guarantee is covered by
`tests/service_pg.rs`, gated on `DATABASE_URL` and run in CI against a real Postgres
service. So: SQLite proves the lifecycle logic locally; Postgres proves the locking in
CI.

---

## License

Provided as a reference implementation.
