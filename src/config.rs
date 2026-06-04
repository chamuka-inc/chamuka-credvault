//! Configuration — read once from the environment at startup (Twelve-Factor III).
//!
//! Per-provider client credentials are intentionally absent: they are read by name
//! from each `ProviderSpec` at use time, so adding a provider needs no change here.
//!
//! Secrets fail **closed**: the state secret and admin token have no built-in default,
//! must be at least [`MIN_SECRET_LEN`] bytes, and may be supplied out-of-band via the
//! `{NAME}_FILE` convention (a path to a file, e.g. a mounted Docker/K8s secret) so they
//! need never appear in the process environment at all. An empty value is treated as
//! absent, never as a default — a blanked-out secret can't silently weaken the service.

use crate::secret::{secret, SecretString};
use anyhow::{bail, Context};

/// Minimum length for the state secret and admin token. 32 bytes ≈ 256 bits of entropy
/// when randomly generated (`openssl rand -base64 32`).
pub const MIN_SECRET_LEN: usize = 32;

/// Rate limit for the request middleware: requests per IP per minute. 0 disables it.
pub const DEFAULT_RATE_LIMIT_PER_MINUTE: u32 = 120;

#[derive(Debug)]
pub struct Config {
    pub database_url: String,
    pub keys_json: String,
    pub active_key: String,
    pub state_secret: SecretString,
    pub state_ttl_seconds: i64,
    pub public_base_url: String,
    pub refresh_skew_seconds: i64,
    pub refresh_horizon_seconds: i64,
    pub worker_interval_seconds: u64,
    pub refresh_max_attempts: i32,
    pub admin_token: SecretString,
    pub bind_addr: String,
    pub http_timeout_seconds: u64,
    /// Reject plaintext `http://` provider endpoints (and require TLS on outbound calls).
    /// True in production; an operator may set `VAULT_ALLOW_INSECURE_HTTP=1` for local dev.
    pub require_https: bool,
    /// Per-IP request budget per minute on the API surface; 0 disables rate limiting.
    pub rate_limit_per_minute: u32,
    /// Max request body size in bytes (DoS guard on JSON handlers).
    pub max_body_bytes: usize,
}

fn var(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// A configuration value, optionally sourced from a file via the `{key}_FILE` convention
/// (the file's trimmed contents). The file form wins so secrets can be mounted rather than
/// exported into the environment, where `docker inspect` / `/proc/<pid>/environ` expose them.
///
/// `pub(crate)` so the single implementation of the `*_FILE` convention is shared by
/// every secret in the vault — including per-provider OAuth client credentials
/// (`src/providers`), not just the service-level secrets resolved here.
pub(crate) fn var_file(key: &str) -> anyhow::Result<Option<String>> {
    if let Some(path) = var(&format!("{key}_FILE")) {
        let body = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {key}_FILE ({path})"))?;
        let trimmed = body.trim();
        return Ok((!trimmed.is_empty()).then(|| trimmed.to_string()));
    }
    Ok(var(key))
}

fn var_or(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|| default.to_string())
}

fn parse_or<T: std::str::FromStr>(key: &str, default: T) -> T {
    var(key).and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn bool_or(key: &str, default: bool) -> bool {
    match var(key).as_deref() {
        Some("1" | "true" | "yes" | "on") => true,
        Some("0" | "false" | "no" | "off") => false,
        _ => default,
    }
}

/// A required secret: present (env or `{key}_FILE`), non-empty, and at least
/// [`MIN_SECRET_LEN`] bytes. There is deliberately no default — a missing or trivially
/// short secret is a hard startup failure, not a silent fallback to a known dev value.
fn require_secret(key: &str) -> anyhow::Result<SecretString> {
    let value =
        var_file(key)?.with_context(|| format!("{key} is required (set {key} or {key}_FILE)"))?;
    if value.len() < MIN_SECRET_LEN {
        bail!(
            "{key} must be at least {MIN_SECRET_LEN} bytes ({} given); generate one with \
             `openssl rand -base64 32`",
            value.len()
        );
    }
    Ok(secret(value))
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let port = var_or("PORT", "8000");
        let bind_host = var_or("VAULT_BIND_HOST", "127.0.0.1");
        let database_url = var("VAULT_DATABASE_URL").context("VAULT_DATABASE_URL is required")?;
        let require_https = !bool_or("VAULT_ALLOW_INSECURE_HTTP", false);
        validate_database_url(&database_url, require_https)?;
        Ok(Config {
            database_url,
            // The encryption keyset is a secret: support the file convention too.
            keys_json: var_file("VAULT_KEYS")?.unwrap_or_else(|| "{}".into()),
            active_key: var_or("VAULT_ACTIVE_KEY", "1"),
            state_secret: require_secret("VAULT_STATE_SECRET")?,
            state_ttl_seconds: parse_or("VAULT_STATE_TTL_SECONDS", 600),
            public_base_url: var_or("VAULT_PUBLIC_BASE_URL", "http://localhost:8000"),
            refresh_skew_seconds: parse_or("VAULT_REFRESH_SKEW_SECONDS", 120),
            refresh_horizon_seconds: parse_or("VAULT_REFRESH_HORIZON_SECONDS", 600),
            worker_interval_seconds: parse_or("VAULT_WORKER_INTERVAL_SECONDS", 60),
            refresh_max_attempts: parse_or("VAULT_REFRESH_MAX_ATTEMPTS", 5),
            admin_token: require_secret("VAULT_ADMIN_TOKEN")?,
            // Bind to loopback by default; containers set VAULT_BIND_HOST=0.0.0.0 explicitly.
            bind_addr: format!("{bind_host}:{port}"),
            http_timeout_seconds: parse_or("VAULT_HTTP_TIMEOUT_SECONDS", 15),
            require_https,
            rate_limit_per_minute: parse_or(
                "VAULT_RATE_LIMIT_PER_MINUTE",
                DEFAULT_RATE_LIMIT_PER_MINUTE,
            ),
            max_body_bytes: parse_or("VAULT_MAX_BODY_BYTES", 64 * 1024),
        })
    }

    pub fn redirect_uri(&self, provider: &str) -> String {
        format!("{}/v1/connect/{}/callback", self.public_base_url, provider)
    }

    /// Read and validate just the database URL — for the `migrate` release step, which
    /// needs the database but none of the runtime application secrets.
    pub fn database_url_from_env() -> anyhow::Result<String> {
        let url = var("VAULT_DATABASE_URL").context("VAULT_DATABASE_URL is required")?;
        validate_database_url(&url, !bool_or("VAULT_ALLOW_INSECURE_HTTP", false))?;
        Ok(url)
    }
}

/// Fail closed if a remote Postgres URL does not enable TLS. Localhost is exempt (a
/// loopback socket to a sidecar DB is not exposed), and the check is skipped entirely when
/// `VAULT_ALLOW_INSECURE_HTTP` has put the service in dev mode.
fn validate_database_url(url: &str, require_tls: bool) -> anyhow::Result<()> {
    if !require_tls {
        return Ok(());
    }
    let is_postgres = url.starts_with("postgres://") || url.starts_with("postgresql://");
    if !is_postgres {
        return Ok(()); // sqlite / other backends: nothing to enforce here.
    }
    let host = host_of(url).unwrap_or_default();
    let has_tls = url.contains("sslmode=")
        && !url.contains("sslmode=disable")
        && !url.contains("sslmode=allow");
    // Only require TLS for clearly *public* endpoints. Loopback, single-label internal
    // service names (e.g. `db`, `postgres` on a container network), and private/link-local
    // IP literals are exempt — they are not exposed on the open network.
    let is_internal = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback() || is_private_ip(ip),
        Err(_) => host.is_empty() || !host.contains('.'),
    };
    if !is_internal && !has_tls {
        bail!(
            "VAULT_DATABASE_URL points at a public host ({host}) without TLS; append \
             `?sslmode=verify-full` (or set VAULT_ALLOW_INSECURE_HTTP=1 for local dev)"
        );
    }
    Ok(())
}

/// Non-routable IP literal: loopback, private (RFC 1918 / ULA), link-local, or unspecified.
fn is_private_ip(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (seg & 0xfe00) == 0xfc00
                || (seg & 0xffc0) == 0xfe80
        }
    }
}

/// Best-effort host extraction from a `scheme://[user[:pass]@]host[:port]/...` URL,
/// without pulling in a URL parser for this one check.
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    let authority = after_scheme.split(['/', '?']).next()?;
    let host_port = authority.rsplit('@').next()?;
    let host = host_port
        .rsplit_once(':')
        .map(|(h, _)| h)
        .unwrap_or(host_port);
    Some(host.trim_matches(['[', ']']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction_handles_creds_port_and_ipv6() {
        assert_eq!(host_of("postgres://db:5432/vault").as_deref(), Some("db"));
        assert_eq!(
            host_of("postgres://u:p@host.example.com:5432/x").as_deref(),
            Some("host.example.com")
        );
        assert_eq!(host_of("postgres://[::1]:5432/x").as_deref(), Some("::1"));
    }

    #[test]
    fn db_tls_required_only_for_public_hosts() {
        // Disabled in dev mode regardless.
        assert!(validate_database_url("postgres://db.example.com/x", false).is_ok());
        // Internal/loopback/private are exempt.
        assert!(validate_database_url("postgres://db:5432/vault", true).is_ok());
        assert!(validate_database_url("postgres://localhost/x", true).is_ok());
        assert!(validate_database_url("postgres://127.0.0.1/x", true).is_ok());
        assert!(validate_database_url("postgres://10.1.2.3:5432/x", true).is_ok());
        // sqlite / non-postgres untouched.
        assert!(validate_database_url("sqlite::memory:", true).is_ok());
        // A public FQDN without sslmode must fail closed...
        assert!(validate_database_url("postgres://db.example.com:5432/x", true).is_err());
        // ...and pass once TLS is requested.
        assert!(
            validate_database_url("postgres://db.example.com/x?sslmode=verify-full", true).is_ok()
        );
        // sslmode=disable does not count as TLS.
        assert!(
            validate_database_url("postgres://db.example.com/x?sslmode=disable", true).is_err()
        );
    }
}
