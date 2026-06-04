# Contributing to credvault

Thanks for your interest in improving credvault. This document describes how to get set
up, what the project expects from a change, and how to get it merged.

credvault is security-critical infrastructure that holds other people's credentials. The
bar for changes is correspondingly high — but the bar is enforced by **types, tests, and
CI**, not by tribal knowledge. If the gates pass, your change is in good shape.

## Code of Conduct

This project adheres to the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating,
you are expected to uphold it.

## Reporting security issues

**Do not file public issues for vulnerabilities.** Follow the private disclosure process
in [SECURITY.md](SECURITY.md).

## Getting started

You need a recent stable Rust toolchain (MSRV is **1.96**; check `Cargo.toml`).

```bash
git clone https://github.com/chamuka-inc/credvault
cd credvault

cargo build                       # default (Postgres) build
cargo test                        # unit + integration (Postgres-only tests auto-skip)
cargo test --features sqlite      # full DB lifecycle on in-process SQLite — no Postgres
```

No external services are required to develop locally: the `sqlite` feature runs the
complete database lifecycle in process. Postgres-specific concurrency tests
(`tests/service_pg.rs`) are gated on `DATABASE_URL` and run in CI against a real Postgres.

## The checks that gate every change

CI runs these on every pull request. Run them locally before pushing — they are exactly
the contract:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo test --features sqlite
cargo build --release --locked
```

Dependency changes additionally run a supply-chain gate (the `security` workflow). To run
it locally, install [`cargo-deny`](https://github.com/EmbarkStudios/cargo-deny) and
[`cargo-audit`](https://github.com/rustsec/rustsec/tree/main/cargo-audit):

```bash
cargo deny check     # advisories, license policy, banned/duplicate crates, sources
cargo audit          # known RUSTSEC advisories
```

A change is mergeable when all of the above are green. Warnings are errors; formatting is
not negotiable (it keeps diffs minimal and review focused on behavior).

## Design principles to preserve

These are the invariants the architecture exists to protect. A change that weakens any of
them needs a very good reason and explicit discussion:

- **Secrets never get a `Display` and never appear in logs.** Plaintext lives in
  `SecretString` and is exposed in exactly one function. Don't add a second.
- **One refresh path.** Just-in-time and worker refresh both go through the single
  `SELECT ... FOR UPDATE` locked path. Don't introduce a parallel one.
- **Tenant isolation is non-negotiable.** The `tenant_id` is always derived from the API
  key server-side, never accepted from the request. No query may cross tenants.
- **Providers are plugins, not code.** Add integrations by dropping a `<id>.json` manifest
  into a plugin directory (`plugins/default/` for a new default), not by adding control
  flow. New behavior that can't be a declarative field deserves scrutiny.
- **Tests and the README are the source of truth.** If you change behavior, change the
  tests and the docs in the same PR.

See the README's "Why Rust" section for the reasoning behind each.

## Submitting a pull request

1. **Open an issue first** for anything non-trivial, so the approach can be agreed before
   you invest in it. Small, obvious fixes can go straight to a PR.
2. **Branch** from `main`.
3. **Keep the PR focused.** One logical change per PR; unrelated cleanups go in their own.
4. **Add or update tests** for any behavior change. New providers need a catalog test; new
   service behavior needs a `tests/service_sqlite.rs` case.
5. **Update documentation** (README, `DEPLOYMENT.md`, `.env.example`, `CHANGELOG.md`) when
   behavior, config, or the API surface changes.
6. **Write a clear PR description**: what changed, why, and how you verified it.
7. **Ensure CI is green.** PRs are not reviewed until the gates pass.

## Commit messages

Write imperative, descriptive commit subjects ("Add Linear provider to catalog", not
"changes"). Explain the *why* in the body when it isn't obvious. We preserve history on
merge — keep the commit log meaningful.

## Adding a provider

Most provider additions are a single JSON manifest — see the "Adding a provider" section of
the [README](README.md#adding-a-provider). Add a `<id>.json` to `plugins/default/` (for a
new default) or any plugin directory, extend the `tests/default_plugins.rs` assertions if
it introduces a quirk, and run `cargo test`. No code changes should be necessary for a
standard OAuth2 or API-key provider.

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License, Version 2.0](LICENSE), consistent with the rest of the project.
