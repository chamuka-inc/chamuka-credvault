# Architecture

credvault is the load-bearing credential layer of an integration platform: it stores
per-end-user credentials for many providers across many tenants, and keeps them valid
across expiry, rotation, and revocation. This document describes how it is built and why.

The guiding choice is that the **security invariants are enforced by the compiler and the
type system**, not by reviewer discipline. Where a property can be made structural — a
secret that has no `Display`, a tenant id that can only come from an authenticated key, a
single function that performs decryption — it is made structural, so violating it fails to
compile rather than failing in production.

## Workspace

credvault is a Cargo workspace with two crates:

| Crate | Produces | Role |
|-------|----------|------|
| `crates/credvault` | the `credvault` library + binary | The vault itself: HTTP service, OAuth engine, crypto, persistence, worker. Published to crates.io. |
| `crates/credvault-import-pipedream` | the `import-pipedream` binary | An offline tool that turns Pipedream's component catalog into provider manifests. `publish = false`; kept separate so its concerns never enter the library's dependency graph or public API. |

Shared package metadata and dependency versions are declared once in the root
`Cargo.toml` (`[workspace.package]` / `[workspace.dependencies]`); each crate inherits
them with `field.workspace = true`.

## The big picture

```
                    ┌────────────────────────────────────────────┐
   caller  ──────►  │  web (axum)   stateless HTTP, validates,    │
   "token for U@P"  │               exposes secret in ONE place   │
                    └───────────────┬────────────────────────────┘
                                    │  service::*  (the core)
                    ┌───────────────┴────────────────────────────┐
   provider  ◄────► │  oauth engine + transport (reqwest)         │
   token endpoints  │  crypto keyring (AES-256-GCM-SIV, versioned)│
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

State lives in the database, never in process memory (twelve-factor VI). The shared
`AppState` (`src/lib.rs`) is just a cheaply-cloneable bundle of a connection pool, the
keyring, the outbound transport, and the config — all behind `Arc`.

## Module map (`crates/credvault/src`)

- **`crypto/`** — encryption at rest. `crypto/mod.rs` is a versioned AES-256-GCM-SIV
  keyring; ciphertext is `v{version}.{base64url(nonce ‖ ct+tag)}`, and the version prefix
  makes key rotation routine (add a key, mark it active, re-encrypt lazily). The AEAD is
  bound to an **AAD** derived from the row identity, so a blob cannot be moved between rows
  even with database write access. `crypto/secret.rs` holds `SecretString` and the no-leak
  guarantee: plaintext has no `Display`/`Debug` that reveals it and is unwrapped in exactly
  one place (`expose_secret`).
- **`oauth/`** — the single OAuth2 engine (`oauth/mod.rs`): one generic
  authorize / code-exchange / refresh / revoke path; per-provider variation comes entirely
  from the `ProviderSpec`, never from branches. `oauth/pkce.rs` is RFC 7636 S256;
  `oauth/pipedream.rs` is the manifest-extraction logic used by the importer tool.
- **`http/`** — everything that speaks HTTP. `http/api.rs` is the axum router with
  edge validation and the one secret exposure (the credentials response); `http/auth.rs`
  resolves the API key into a `TenantPrincipal`/`AdminPrincipal` extractor; `http/ratelimit.rs`
  is a per-IP limiter; `http/transport.rs` is the outbound `TokenTransport` trait (reqwest
  implementation plus an in-memory test double).
- **`service.rs`** — the core. Tenant creation, the connect flows, and the **single locked
  refresh path** used by both just-in-time reads and the background worker.
- **`models.rs`** — the `Connection` row, its status enum, AAD derivation, and the
  `public()` projection that strips secrets for API responses.
- **`state.rs`** — the signed, expiring OAuth `state` token (CSRF defence), verified in
  constant time.
- **`providers/`** — `ProviderSpec` plus plugin-directory discovery. There are **no
  built-in providers**; the registry is loaded from the directories named by
  `VAULT_PLUGIN_DIRS`. See [../plugins/README.md](../plugins/README.md) for the manifest
  contract.
- **`db.rs`** — backend selection. One set of SQL serves both Postgres (production) and
  SQLite (the `sqlite` feature, for in-process tests); only the row-lock clause and the
  "now" expression differ.
- **`config.rs`** / **`error.rs`** — twelve-factor config from the environment, and typed
  errors that map to stable HTTP status + code without leaking database detail.

## The invariants (and how they're enforced)

These are the properties the architecture exists to protect. Each is structural — a change
that weakens one tends not to compile.

1. **Secrets never get a `Display` and never appear in logs.** Plaintext lives in
   `SecretString` (`crypto/secret.rs`) and is exposed in exactly one function. There is no
   second unwrap to audit.
2. **One refresh path.** Just-in-time refresh (on read) and the worker both go through the
   same `SELECT ... FOR UPDATE` locked path in `service.rs`. Concurrent refreshers
   serialise on the row lock; there is no parallel code path that could double-refresh or
   skip the lock.
3. **Tenant isolation is non-negotiable.** A handler receives a `TenantPrincipal` whose
   `tenant_id` is derived from the presented API key server-side. The id is never read from
   the query string or body, so a handler has no way to *name* another tenant's data — the
   cross-tenant query is unwriteable, not merely unwritten.
4. **Ciphertext is tenant- and row-bound.** Encryption AAD is derived from the connection
   identity, so a stolen blob cannot be decrypted in another row's context.
5. **Providers are plugins, not code.** A new integration is a declarative `<id>.json`
   manifest dropped into a plugin directory — no new control flow.

## Process model

One binary, several roles, selected by the first argument or `VAULT_PROCESS`:

- **`web`** — the stateless axum service. Scale horizontally for read traffic.
- **`worker`** — the background refresh loop; scans for connections due for refresh and
  refreshes each in its own transaction, with graceful SIGTERM shutdown. Scale
  independently for refresh throughput.
- **`migrate`** — a one-shot release step that applies migrations and exits. It is given
  only the database URL, never the runtime app secrets.
- Maintenance / no-DB helpers: `gen-key`, `list-providers`, `validate-plugins`,
  `rotate-keys`, and `healthcheck` (used by the container's `HEALTHCHECK`).

Migrations are owned by the `migrate` step, never applied by the app at boot — schema
changes are a deliberate release action. See [DEPLOYMENT.md](DEPLOYMENT.md) for how the
three processes are wired together and how secrets are delivered.

## Testing strategy

The `sqlite` feature compiles the service against an in-process SQLite so the **entire
database lifecycle** runs in CI with no external services. The Postgres-only concurrency
guarantee (row-level `SELECT ... FOR UPDATE`) — which SQLite cannot reproduce, since it
serialises writers itself — is covered by `tests/service_pg.rs`, gated on `DATABASE_URL`
and run against a real Postgres in CI. SQLite proves the lifecycle logic; Postgres proves
the locking.
