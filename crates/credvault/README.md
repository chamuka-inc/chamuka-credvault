# credvault

Multi-tenant, multi-provider credential vault — the load-bearing layer of an integration
platform. It stores per-end-user credentials for many providers across many tenants and
keeps them valid across expiry, rotation, and revocation.

This crate is both the library and the `credvault` service binary (the `web`, `worker`,
and `migrate` roles, plus maintenance subcommands). It is built in Rust so the security
invariants are enforced by the compiler rather than by discipline:

- secrets have no `Display` and are unwrapped in exactly one place;
- a single `SELECT ... FOR UPDATE` path performs every token refresh;
- a tenant id can only come from an authenticated API key, never from a request;
- credential ciphertext is AAD-bound to its row, and the AES-256-GCM-SIV keyring is
  versioned for zero-downtime key rotation;
- providers are declarative JSON plugins, not code.

## Use it

```bash
cargo run -p credvault -- gen-key          # generate an encryption key
cargo run -p credvault -- list-providers   # show the loaded provider plugins
cargo run -p credvault -- migrate          # apply migrations (needs VAULT_DATABASE_URL)
cargo run -p credvault -- web              # serve the HTTP API (or: worker)
```

The `sqlite` feature compiles the service against an in-process SQLite for tests and local
development with no external database:

```bash
cargo test -p credvault --features sqlite
```

## Documentation

- The HTTP API, quickstarts, and configuration: the [repository README](../../README.md).
- The design and the invariants above, in depth: [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md).
- Running it in production: [docs/DEPLOYMENT.md](../../docs/DEPLOYMENT.md).
- Adding a provider (the manifest contract): [plugins/README.md](../../plugins/README.md).

## License

Apache-2.0. See [LICENSE](../../LICENSE).
