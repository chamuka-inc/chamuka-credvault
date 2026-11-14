# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-06-04

Initial public release.

### Added

- Multi-tenant, multi-provider credential vault with a single core endpoint:
  "give me a valid access token for user U at provider P."
- Encryption of credentials at rest using a **versioned AES-256-GCM keyring** with
  AAD binding and online key rotation (`rotate-keys`).
- `SecretString` plaintext wrapper with no `Display` and a redacting `Debug`, so secrets
  cannot be logged; plaintext is exposed in exactly one function in the crate.
- Generic OAuth2 engine: authorization-code exchange, refresh, and best-effort upstream
  revocation (RFC 7009), with a single `SELECT ... FOR UPDATE` locked refresh path shared
  by the just-in-time and background-worker flows.
- **PKCE (RFC 7636, S256)** support — a fresh per-authorization verifier, stored encrypted
  (identity-bound) in the single-use `oauth_flows` row and consumed once at the callback.
- Signed, expiring OAuth `state` tokens (CSRF protection) with constant-time verification.
- Providers as plugins: the binary embeds none. Every provider is a declarative JSON
  manifest discovered from `VAULT_PLUGIN_DIRS` (later dirs override earlier by `id`),
  validated at startup; adding one is a file, not code. `validate-plugins` checks a dir
  without a database.
- Eleven default provider plugins shipped in `plugins/default/`: Google, GitHub, Slack,
  Notion, Stripe, X, GitLab, Spotify, Microsoft, Zoom, and SendGrid — spanning POST vs
  HTTP Basic client auth, PKCE, refresh-token rotation, nested token paths, and
  API-key-only models.
- Per-tenant API keys (only the hash is stored); `tenant_id` is always derived
  server-side and never accepted from the request.
- HTTP API (Axum) with `/healthz`, `/readyz`, provider listing, tenant provisioning,
  OAuth connect/callback, API-key connect, credential fetch, and connection management.
- Background refresh worker with graceful SIGTERM shutdown, runnable as an independent
  process from the same binary.
- Twelve-Factor configuration from environment variables, with `*_FILE` variants for all
  secrets so they need never sit in the process environment.
- Postgres (production) and SQLite (test/dev) backends behind one set of SQL.
- Per-IP rate limiting and typed errors that map to stable HTTP status codes without
  leaking database detail.
- Comprehensive test suite: full database lifecycle on in-process SQLite (no external
  services) plus Postgres row-locking concurrency tests gated in CI.
- CI gating every change: `cargo fmt --check`, `clippy -D warnings`, the test suite, a
  real-Postgres integration job, a locked release build, and a Docker image smoke test.
- Supply-chain security workflow (`cargo audit` + `cargo deny`) on dependency changes and
  weekly, with a `deny.toml` policy for advisories, licenses, bans, and sources.
- Tag-triggered release pipeline: version-guard, full gate re-run, crates.io publish,
  multi-arch (amd64/arm64) container image to GHCR, and a GitHub Release with notes and
  static (musl) binaries.
- Hardened container supply chain: base images pinned by digest, a Trivy scan gate that
  fails the release on fixable HIGH/CRITICAL vulnerabilities (results uploaded to the
  Security tab), and SBOM + max provenance attestations published with the image.
- Dependabot for cargo, GitHub Actions, and Docker dependencies.
- Multi-stage `Dockerfile` (non-root, stripped binary) and `docker-compose.yml` for local
  topology (db → migrate → web + worker).
- Documentation: `README.md`, `DEPLOYMENT.md` (production hardening), `SECURITY.md`,
  `CONTRIBUTING.md`, and `CODE_OF_CONDUCT.md`.

[Unreleased]: https://github.com/chamuka-labs/credvault/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/chamuka-labs/credvault/releases/tag/v1.0.0
