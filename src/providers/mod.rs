//! Providers as data. The generic OAuth2 engine and the service layer are written
//! once and parameterised entirely by a [`ProviderSpec`]. Adding an integration means
//! appending one spec in `catalog.rs` — no flow logic changes.
//!
//! Per-provider auth-dialect quirks are declarative knobs (token auth style, accept
//! header, extra authorize params, dotted token path, refresh rotation), not branches.

pub mod catalog;

use std::sync::OnceLock;

use anyhow::Context;

use crate::secret::{secret, SecretString};

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
#[serde(default)]
pub struct ProviderSpec {
    pub name: String,
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
            name: String::new(),
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

impl ProviderSpec {
    pub fn client_id(&self) -> Option<String> {
        std::env::var(&self.client_id_env)
            .ok()
            .filter(|v| !v.is_empty())
    }
    pub fn client_secret(&self) -> Option<SecretString> {
        std::env::var(&self.client_secret_env)
            .ok()
            .filter(|v| !v.is_empty())
            .map(secret)
    }
    pub fn is_configured(&self) -> bool {
        match self.auth_type {
            AuthType::ApiKey => true,
            AuthType::OAuth2 => self.client_id().is_some() && self.client_secret().is_some(),
        }
    }
}

static REGISTRY: OnceLock<Vec<ProviderSpec>> = OnceLock::new();

/// The active provider catalog: built-ins overlaid with any runtime JSON. Lazily
/// loaded on first use; `init_from_env` lets the binary load it eagerly at startup.
pub fn registry() -> &'static [ProviderSpec] {
    REGISTRY
        .get_or_init(|| {
            load_from_env().unwrap_or_else(|e| {
                tracing::error!(error = %e, "provider config invalid; using built-ins only");
                catalog::build()
            })
        })
        .as_slice()
}

pub fn get(name: &str) -> Option<&'static ProviderSpec> {
    registry().iter().find(|s| s.name == name)
}

/// Parse and validate the provider catalog from the environment, failing fast on a
/// malformed config. Returns the provider names. Safe to call once at startup.
pub fn init_from_env() -> anyhow::Result<Vec<String>> {
    let specs = load_from_env()?;
    let names = specs.iter().map(|s| s.name.clone()).collect();
    // If the registry was already initialised (e.g. by a prior `registry()` call in a
    // test), keep the existing value; startup calls this before any other access.
    let _ = REGISTRY.set(specs);
    Ok(names)
}

/// Built-ins first, then overlay providers from `VAULT_PROVIDERS_FILE` (a path to a
/// JSON array) and `VAULT_PROVIDERS_JSON` (an inline JSON array). An entry whose name
/// matches a built-in replaces it; new names are added. Result is sorted by name.
fn load_from_env() -> anyhow::Result<Vec<ProviderSpec>> {
    use std::collections::BTreeMap;

    let mut by_name: BTreeMap<String, ProviderSpec> = catalog::build()
        .into_iter()
        .map(|s| (s.name.clone(), s))
        .collect();

    if let Ok(path) = std::env::var("VAULT_PROVIDERS_FILE") {
        if !path.is_empty() {
            ensure_not_world_writable(&path)?;
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("reading VAULT_PROVIDERS_FILE ({path})"))?;
            merge_json(&mut by_name, &data)
                .with_context(|| format!("parsing VAULT_PROVIDERS_FILE ({path})"))?;
        }
    }
    if let Ok(json) = std::env::var("VAULT_PROVIDERS_JSON") {
        if !json.is_empty() {
            merge_json(&mut by_name, &json).context("parsing VAULT_PROVIDERS_JSON")?;
        }
    }

    let specs: Vec<ProviderSpec> = by_name.into_values().collect();
    for s in &specs {
        validate_spec(s)?;
    }
    Ok(specs)
}

fn merge_json(
    by_name: &mut std::collections::BTreeMap<String, ProviderSpec>,
    data: &str,
) -> anyhow::Result<()> {
    let incoming: Vec<ProviderSpec> = serde_json::from_str(data)?;
    for spec in incoming {
        by_name.insert(spec.name.clone(), spec);
    }
    Ok(())
}

/// Validate a single provider spec. Public so the Pipedream importer can dogfood the
/// exact same rules the runtime loader enforces.
pub fn validate_spec(s: &ProviderSpec) -> anyhow::Result<()> {
    anyhow::ensure!(!s.name.trim().is_empty(), "a provider has an empty name");
    if s.auth_type == AuthType::OAuth2 {
        anyhow::ensure!(
            !s.authorize_url.is_empty(),
            "provider '{}' (oauth2) is missing authorize_url",
            s.name
        );
        anyhow::ensure!(
            !s.token_url.is_empty(),
            "provider '{}' (oauth2) is missing token_url",
            s.name
        );
        anyhow::ensure!(
            !s.client_id_env.is_empty() && !s.client_secret_env.is_empty(),
            "provider '{}' (oauth2) is missing client_id_env/client_secret_env",
            s.name
        );
        // Every endpoint the service will POST credentials to must be TLS and must not
        // point at an internal/metadata address (SSRF). A misconfigured or hostile
        // provider entry could otherwise exfiltrate the client secret + tokens, or pivot
        // to e.g. 169.254.169.254.
        validate_endpoint(&s.name, "authorize_url", &s.authorize_url)?;
        validate_endpoint(&s.name, "token_url", &s.token_url)?;
        if let Some(revoke) = s.revoke_url.as_deref().filter(|u| !u.is_empty()) {
            validate_endpoint(&s.name, "revoke_url", revoke)?;
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

/// Refuse to read a provider catalog file that is group- or world-writable: a writable
/// catalog is an injection vector for hostile token/authorize endpoints.
#[cfg(unix)]
fn ensure_not_world_writable(path: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .with_context(|| format!("stat {path}"))?
        .permissions()
        .mode();
    anyhow::ensure!(
        mode & 0o022 == 0,
        "provider file {path} is group/world-writable (mode {:o}); tighten to 0600/0640",
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
            name: "t".into(),
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
}
