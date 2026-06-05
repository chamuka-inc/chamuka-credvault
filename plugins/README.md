# Provider plugins

Providers are **data, not code**. The generic OAuth2 engine and the service layer are
written once and parameterised entirely by a provider manifest, so adding an integration
is a new JSON file — never a code change. credvault ships **no built-in providers**: even
the ones in [`default/`](default/) are loaded through the same path as any third-party
plugin.

## Discovery

At startup the vault loads every manifest from the colon-separated directories named by
`VAULT_PLUGIN_DIRS` (PATH-style; later directories win by `id`). Unset or empty means zero
providers. The container image ships `default/` and sets `VAULT_PLUGIN_DIRS=/app/plugins/default`.

```bash
# defaults plus your own, your dir overriding by id:
VAULT_PLUGIN_DIRS=/app/plugins/default:/etc/credvault/plugins credvault list-providers

# validate a directory without a database (CI / pre-flight); non-zero on any bad manifest:
VAULT_PLUGIN_DIRS=/etc/credvault/plugins cargo run -p credvault -- validate-plugins
```

A malformed manifest fails the process at startup, not at first request.

## The manifest

One JSON file per provider, conventionally named `<id>.json`. The full contract — every
field, its type, default, and which are required — is in
[`manifest.schema.json`](manifest.schema.json) (JSON Schema 2020-12). The loader uses
`deny_unknown_fields`, so a typo'd or stray key is a hard error rather than a silently
dropped field.

Three rules worth stating outright:

- **Secrets never go in a manifest.** `client_id_env` / `client_secret_env` name the *env
  vars* the credentials are read from (the `*_FILE` convention works too, for mounted
  secrets), so manifests stay non-secret and committable.
- **`auth_type` is `"oauth2"` or `"api_key"`.** OAuth providers must supply
  `authorize_url`, `token_url`, `client_id_env`, and `client_secret_env`. API-key
  providers need none of those.
- **Per-provider quirks are declarative knobs**, not branches: token auth style, accept
  header, extra authorize params, dotted token paths, refresh rotation, PKCE.

### Minimal API-key provider

```json
{
  "manifest_version": 1,
  "id": "sendgrid",
  "version": "1.0.0",
  "auth_type": "api_key"
}
```

### OAuth2 provider (with quirks)

```json
{
  "manifest_version": 1,
  "id": "google",
  "version": "1.0.0",
  "auth_type": "oauth2",
  "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_url": "https://oauth2.googleapis.com/token",
  "revoke_url": "https://oauth2.googleapis.com/revoke",
  "client_id_env": "GOOGLE_CLIENT_ID",
  "client_secret_env": "GOOGLE_CLIENT_SECRET",
  "default_scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
  "extra_authorize_params": [["access_type", "offline"], ["prompt", "consent"]]
}
```

## Adding a default provider

Drop a `<id>.json` into [`default/`](default/), extend the assertions in
`crates/credvault/tests/default_plugins.rs` if it introduces a quirk, and run `cargo test`.
See the ["Adding a provider"](../README.md#adding-a-provider) section of the root README,
and [credvault-import-pipedream](../crates/credvault-import-pipedream/README.md) for
bulk-importing Pipedream's catalog.
