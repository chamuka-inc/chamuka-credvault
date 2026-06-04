//! Providers as plugins. The generic OAuth2 engine and the service layer are written
//! once and parameterised entirely by a [`ProviderSpec`]. There are **no built-in
//! providers**: every provider — including the ones we ship — is a declarative manifest
//! discovered at startup from the directories named by `VAULT_PLUGIN_DIRS`. The defaults
//! are simply the manifests in the bundled `plugins/default` directory, loaded through the
//! exact same path as any third-party plugin.
//!
//! A plugin is one JSON file per provider: the [`ProviderSpec`] fields plus packaging
//! metadata (`id`, `version`, `manifest_version`). Per-provider auth-dialect quirks are
//! declarative knobs (token auth style, accept header, extra authorize params, dotted
//! token path, refresh rotation), not branches — so adding an integration is a new file,
//! never a code change.

use std::sync::OnceLock;

use anyhow::Context;

use crate::secret::{secret, SecretString};

/// Directories searched for provider plugin manifests, colon-separated like `PATH`.
/// Unset/empty means the vault loads zero providers (a lean core); the container image
/// sets this to the bundled default directory to be useful out of the box.
const PLUGIN_DIRS_ENV: &str = "VAULT_PLUGIN_DIRS";

/// Current envelope schema version. A manifest may declare its own `manifest_version`;
/// anything newer than this is refused so an older binary can't silently misread a format
/// it doesn't understand.
const CURRENT_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
pub enum AuthType {
    #[serde(rename = "oauth2", alias = "OAuth2")]
    OAuth2,
    /// User-supplied long-lived key; no redirect flow, no refresh.
    #[serde(rename = "api_key", alias = "apikey", alias = "ApiKey")]
    ApiKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenAuthStyle {
    /// client_id/secret in the form body.
    Post,
    /// client_id/secret as HTTP Basic.
    Basic,
}

#[derive(Debug, Clone, serde::Deserialize)]
// `default` lets a manifest omit any field; `deny_unknown_fields` makes a typo'd or stray
// key a hard parse error rather than a silently-dropped field — important now that manifests
// are authored by plugin authors, not just us.
#[serde(default, deny_unknown_fields)]
pub struct ProviderSpec {
    /// Envelope schema version of the manifest format itself. Defaults to 1; a value
    /// greater than [`CURRENT_MANIFEST_VERSION`] is refused by the loader.
    pub manifest_version: u32,
    /// Canonical provider key — the value used in `/v1/connect/{id}` routes, the DB
    /// `provider` column, and the AAD identity. Stable; unique across loaded plugins.
    pub id: String,
    /// Plugin version (semver recommended). Packaging metadata the engine ignores at
    /// runtime; surfaced by discovery (`list-providers`, `GET /v1/providers`).
    pub version: String,
    pub auth_type: AuthType,
    pub authorize_url: String,
    pub token_url: String,
    pub revoke_url: Option<String>,
    pub client_id_env: String,
    pub client_secret_env: String,
    pub default_scopes: Vec<String>,
    pub scope_separator: String,
    pub token_auth_style: TokenAuthStyle,
    pub token_accept_json: bool,
    pub extra_authorize_params: Vec<(String, String)>,
    pub token_path: String,
    pub refresh_token_path: String,
    pub expires_in_path: String,
    pub refresh_token_rotates: bool,
    /// Drive the authorization-code flow with PKCE (RFC 7636, S256). Required by some
    /// providers (e.g. X/Twitter); harmless defense-in-depth elsewhere.
    pub uses_pkce: bool,
}

impl Default for ProviderSpec {
    fn default() -> Self {
        ProviderSpec {
            manifest_version: CURRENT_MANIFEST_VERSION,
            id: String::new(),
            version: String::new(),
            auth_type: AuthType::OAuth2,
            authorize_url: String::new(),
            token_url: String::new(),
            revoke_url: None,
            client_id_env: String::new(),
            client_secret_env: String::new(),
            default_scopes: Vec::new(),
            scope_separator: " ".to_string(),
            token_auth_style: TokenAuthStyle::Post,
            token_accept_json: false,
            extra_authorize_params: Vec::new(),
            token_path: "access_token".to_string(),
            refresh_token_path: "refresh_token".to_string(),
            expires_in_path: "expires_in".to_string(),
            refresh_token_rotates: false,
            uses_pkce: false,
        }
    }
}

/// Resolve a provider client credential from the env var named by `env_key`, or from the
/// file named by `{env_key}_FILE` — the same `*_FILE` convention the vault uses for every
/// other secret, so OAuth client secrets can be mounted (Docker/K8s secrets) rather than
/// left in the process environment, where `docker inspect` / `/proc/<pid>/environ` expose
/// them. A configured-but-unreadable `_FILE` path is treated as absent (the provider reads
/// as not-configured) and logged, rather than panicking the request.
fn client_cred(env_key: &str) -> Option<String> {
    match crate::config::var_file(env_key) {
        Ok(value) => value,
        Err(e) => {
            tracing::warn!(error = %e, env_key, "could not read provider credential file");
            None
        }
    }
}

impl ProviderSpec {
    pub fn client_id(&self) -> Option<String> {
        client_cred(&self.client_id_env)
    }
    pub fn client_secret(&self) -> Option<SecretString> {
        client_cred(&self.client_secret_env).map(secret)
    }
    pub fn is_configured(&self) -> bool {
        match self.auth_type {
            AuthType::ApiKey => true,
            AuthType::OAuth2 => self.client_id().is_some() && self.client_secret().is_some(),
        }
    }
}

static REGISTRY: OnceLock<Vec<ProviderSpec>> = OnceLock::new();

/// The active provider registry: every plugin discovered from `VAULT_PLUGIN_DIRS`. Lazily
/// loaded on first use; `init_plugins` lets the binary load it eagerly at startup so a bad
/// manifest fails the process rather than the first request. On a load error here (after
/// the eager startup check has already passed) the registry resolves empty rather than
/// panicking a request thread.
pub fn registry() -> &'static [ProviderSpec] {
    REGISTRY
        .get_or_init(|| {
            load_from_dirs().unwrap_or_else(|e| {
                tracing::error!(error = %e, "plugin load failed; no providers available");
                Vec::new()
            })
        })
        .as_slice()
}

pub fn get(id: &str) -> Option<&'static ProviderSpec> {
    registry().iter().find(|s| s.id == id)
}

/// Discover and validate every provider plugin, failing fast on a malformed manifest.
/// Returns each loaded `(id, version)` for the startup log. Safe to call once at startup,
/// before any `registry()`/`get()` access.
pub fn init_plugins() -> anyhow::Result<Vec<(String, String)>> {
    let specs = load_from_dirs()?;
    let loaded = specs
        .iter()
        .map(|s| (s.id.clone(), s.version.clone()))
        .collect();
    // If the registry was already initialised (e.g. by a prior `registry()` call in a
    // test), keep the existing value; startup calls this before any other access.
    let _ = REGISTRY.set(specs);
    Ok(loaded)
}

/// Load all plugin manifests from the directories named by `VAULT_PLUGIN_DIRS`
/// (colon-separated, in order). An unset/empty variable yields an empty registry.
fn load_from_dirs() -> anyhow::Result<Vec<ProviderSpec>> {
    let dirs = std::env::var(PLUGIN_DIRS_ENV).unwrap_or_default();
    let list: Vec<&str> = dirs.split(':').filter(|d| !d.is_empty()).collect();
    load_from(&list)
}

/// Load and fully validate manifests from an explicit, ordered list of plugin directories.
/// Pure: reads no environment and touches no global state.
///
/// Within a directory, every `*.json` file is one provider manifest and the file's stem is
/// its `id` (`github.json` ⇒ `github`) — a manifest whose `id` field disagrees with its
/// filename is rejected, so the override target is never ambiguous and an `id` typo can't
/// silently spawn a second provider. Across directories, a later directory's manifest
/// replaces an earlier one with the same `id` (so an operator's custom dir cleanly overrides
/// a shipped default). **Every** manifest is validated as it is read — including one that is
/// later shadowed — so no malformed file is ever silently ignored. Result is sorted by `id`.
pub fn load_from(dirs: &[&str]) -> anyhow::Result<Vec<ProviderSpec>> {
    use std::collections::BTreeMap;

    let mut by_id: BTreeMap<String, ProviderSpec> = BTreeMap::new();
    for dir in dirs {
        let in_this_dir = load_dir(dir)
            .with_context(|| format!("loading plugin directory {dir} ({PLUGIN_DIRS_ENV})"))?;
        // Later directories override earlier ones by id.
        by_id.extend(in_this_dir);
    }
    Ok(by_id.into_values().collect())
}

/// Read and validate one plugin directory into an `id -> spec` map. Files are processed in
/// filename order for deterministic diagnostics. Because the filename stem *is* the `id` and
/// filenames are unique within a directory, two manifests in one directory can never claim
/// the same `id`.
fn load_dir(dir: &str) -> anyhow::Result<std::collections::BTreeMap<String, ProviderSpec>> {
    use std::collections::BTreeMap;

    ensure_not_world_writable(dir)?;

    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("reading directory {dir}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();

    let mut by_id: BTreeMap<String, ProviderSpec> = BTreeMap::new();
    for file in files {
        let display = file.display();
        let path = file.to_string_lossy();
        ensure_not_world_writable(&path)?;
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let data = std::fs::read_to_string(&file)
            .with_context(|| format!("reading manifest {display}"))?;
        let spec: ProviderSpec =
            serde_json::from_str(&data).with_context(|| format!("parsing manifest {display}"))?;
        anyhow::ensure!(
            spec.manifest_version <= CURRENT_MANIFEST_VERSION,
            "manifest {display} declares manifest_version {} but this build understands at most {CURRENT_MANIFEST_VERSION}",
            spec.manifest_version
        );
        // The filename is the id. This keeps override-by-id unambiguous and turns an id typo
        // into an error instead of a silently-added duplicate provider.
        anyhow::ensure!(
            spec.id == stem,
            "manifest {display} declares id '{}' but its filename implies '{stem}'; rename the file to '{}.json' (or fix the id)",
            spec.id,
            spec.id
        );
        validate_spec(&spec).with_context(|| format!("invalid manifest {display}"))?;
        // `stem` is unique within the directory and equals the id, so this never overwrites.
        by_id.insert(spec.id.clone(), spec);
    }
    Ok(by_id)
}

/// Validate a single provider spec. Public so the Pipedream importer can dogfood the
/// exact same rules the runtime loader enforces.
pub fn validate_spec(s: &ProviderSpec) -> anyhow::Result<()> {
    anyhow::ensure!(!s.id.trim().is_empty(), "a provider has an empty id");
    if s.auth_type == AuthType::OAuth2 {
        anyhow::ensure!(
            !s.authorize_url.is_empty(),
            "provider '{}' (oauth2) is missing authorize_url",
            s.id
        );
        anyhow::ensure!(
            !s.token_url.is_empty(),
            "provider '{}' (oauth2) is missing token_url",
            s.id
        );
        anyhow::ensure!(
            !s.client_id_env.is_empty() && !s.client_secret_env.is_empty(),
            "provider '{}' (oauth2) is missing client_id_env/client_secret_env",
            s.id
        );
        // Every endpoint the service will POST credentials to must be TLS and must not
        // point at an internal/metadata address (SSRF). A misconfigured or hostile
        // provider entry could otherwise exfiltrate the client secret + tokens, or pivot
        // to e.g. 169.254.169.254.
        validate_endpoint(&s.id, "authorize_url", &s.authorize_url)?;
        validate_endpoint(&s.id, "token_url", &s.token_url)?;
        if let Some(revoke) = s.revoke_url.as_deref().filter(|u| !u.is_empty()) {
            validate_endpoint(&s.id, "revoke_url", revoke)?;
        }
    }
    Ok(())
}

/// A provider endpoint must be HTTPS (loopback `http` is tolerated for local dev) and must
/// not resolve to a loopback/private/link-local IP literal.
fn validate_endpoint(provider: &str, field: &str, raw: &str) -> anyhow::Result<()> {
    let url = reqwest::Url::parse(raw)
        .with_context(|| format!("provider '{provider}' {field} is not a valid URL: {raw}"))?;
    let host = url
        .host_str()
        .with_context(|| format!("provider '{provider}' {field} has no host: {raw}"))?;
    // `url` returns IPv6 hosts bracketed (`[fd00::1]`); strip before parsing as an IP.
    let ip_literal = host
        .trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .ok();
    let is_loopback_host = host.eq_ignore_ascii_case("localhost")
        || ip_literal.map(|ip| ip.is_loopback()) == Some(true);
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host => {} // dev convenience only
        other => {
            anyhow::bail!("provider '{provider}' {field} must use https (got {other}://): {raw}")
        }
    }
    if let Some(ip) = ip_literal {
        anyhow::ensure!(
            is_loopback_host || is_global_ip(ip),
            "provider '{provider}' {field} points at a non-routable address ({ip}); \
             internal/metadata endpoints are refused: {raw}"
        );
    }
    Ok(())
}

/// Reject IP literals that must never be the target of an outbound credential POST:
/// loopback, private, link-local (incl. the 169.254.169.254 cloud-metadata address),
/// unspecified, and IPv6 unique-local. Conservative on purpose.
fn is_global_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || (seg & 0xfe00) == 0xfc00  // unique-local fc00::/7
                || (seg & 0xffc0) == 0xfe80) // link-local fe80::/10
        }
    }
}

/// Refuse to read a plugin manifest file (or directory) that is group- or world-writable:
/// a writable plugin path is an injection vector for hostile token/authorize endpoints.
#[cfg(unix)]
fn ensure_not_world_writable(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat {path}"))?
        .permissions()
        .mode();
    anyhow::ensure!(
        mode & 0o022 == 0,
        "plugin path {path} is group/world-writable (mode {:o}); tighten to 0600/0640 (dirs 0700/0750)",
        mode & 0o777
    );
    Ok(())
}

#[cfg(not(unix))]
fn ensure_not_world_writable(_path: &str) -> anyhow::Result<()> {
    Ok(())
}

/// Resolve a dotted path like `authed_user.access_token` against a JSON value.
pub fn dotted_get<'a>(value: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = value;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oauth_spec(authorize: &str, token: &str) -> ProviderSpec {
        ProviderSpec {
            id: "t".into(),
            auth_type: AuthType::OAuth2,
            authorize_url: authorize.into(),
            token_url: token.into(),
            client_id_env: "T_ID".into(),
            client_secret_env: "T_SECRET".into(),
            ..Default::default()
        }
    }

    #[test]
    fn https_endpoints_pass() {
        let s = oauth_spec(
            "https://idp.example.com/auth",
            "https://idp.example.com/token",
        );
        assert!(validate_spec(&s).is_ok());
    }

    #[test]
    fn plaintext_http_is_rejected_except_loopback() {
        let public = oauth_spec(
            "http://idp.example.com/auth",
            "https://idp.example.com/token",
        );
        assert!(
            validate_spec(&public).is_err(),
            "public http must be refused"
        );

        let loopback = oauth_spec("http://localhost:9000/auth", "http://127.0.0.1:9000/token");
        assert!(
            validate_spec(&loopback).is_ok(),
            "loopback http is dev-allowed"
        );
    }

    #[test]
    fn ssrf_internal_targets_are_rejected() {
        for bad in [
            "https://169.254.169.254/latest/meta-data/", // cloud metadata
            "https://10.0.0.5/token",                    // RFC1918
            "https://192.168.1.1/token",
            "https://[fd00::1]/token", // IPv6 ULA
        ] {
            let s = oauth_spec("https://idp.example.com/auth", bad);
            assert!(validate_spec(&s).is_err(), "{bad} must be refused as SSRF");
        }
    }

    #[test]
    fn revoke_url_is_validated_when_present() {
        let mut s = oauth_spec(
            "https://idp.example.com/auth",
            "https://idp.example.com/token",
        );
        s.revoke_url = Some("http://169.254.169.254/kill".into());
        assert!(validate_spec(&s).is_err());
    }

    /// OAuth client secrets must honor the `*_FILE` convention used by every other secret,
    /// so they can be mounted (Docker/K8s secret) instead of sitting in the environment.
    #[test]
    fn client_secret_honors_file_mount_convention() {
        use crate::secret::ExposeSecret;

        // A uniquely-named var so this test can't collide with others sharing the process.
        const KEY: &str = "CREDVAULT_TEST_CLIENT_SECRET";
        let file_key = format!("{KEY}_FILE");
        let expose = |s: Option<SecretString>| s.map(|v| v.expose_secret().to_string());

        let path = std::env::temp_dir().join(format!("credvault_cred_{}.txt", std::process::id()));
        // File holds the secret with surrounding whitespace to prove it is trimmed.
        std::fs::write(&path, "  file-mounted-secret\n").unwrap();

        let mut spec = oauth_spec("https://idp.example.com/a", "https://idp.example.com/t");
        spec.client_secret_env = KEY.into();

        // Baseline: neither the env var nor the *_FILE var is set -> not configured.
        std::env::remove_var(KEY);
        std::env::remove_var(&file_key);
        assert!(spec.client_secret().is_none());
        assert!(!spec.is_configured()); // client_id also unset

        // The *_FILE mount supplies the value, trimmed.
        std::env::set_var(&file_key, &path);
        assert_eq!(
            expose(spec.client_secret()),
            Some("file-mounted-secret".into())
        );

        // When both are present the mounted file wins (env must not override a mounted secret).
        std::env::set_var(KEY, "plain-env-secret");
        assert_eq!(
            expose(spec.client_secret()),
            Some("file-mounted-secret".into())
        );

        // Without the *_FILE var, it falls back to the plain env var (unchanged behavior).
        std::env::remove_var(&file_key);
        assert_eq!(
            expose(spec.client_secret()),
            Some("plain-env-secret".into())
        );

        std::env::remove_var(KEY);
        let _ = std::fs::remove_file(&path);
    }
}
