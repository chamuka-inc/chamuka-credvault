//! The single OAuth2 implementation. Every provider flows through here; the
//! `ProviderSpec` supplies all variation. No per-provider branches.
//!
//! `pkce` carries the PKCE verifier/challenge helpers; `pipedream` carries the
//! offline importer's manifest-extraction logic (used by the `import-pipedream` tool).

pub mod pipedream;
pub mod pkce;

use std::collections::BTreeMap;

use crate::crypto::secret::{secret, ExposeSecret, SecretString};
use crate::http::transport::TokenTransport;
use crate::providers::{dotted_get, ProviderSpec, TokenAuthStyle};

pub struct TokenResult {
    pub access_token: SecretString,
    pub refresh_token: Option<SecretString>,
    pub expires_in: Option<i64>,
    pub scope: Option<String>,
}

#[derive(Debug)]
pub struct OAuthFailure {
    pub retryable: bool,
    pub needs_reauth: bool,
    pub message: String,
}

impl OAuthFailure {
    fn retryable(msg: impl Into<String>) -> Self {
        Self {
            retryable: true,
            needs_reauth: false,
            message: msg.into(),
        }
    }
    fn fatal(msg: impl Into<String>) -> Self {
        Self {
            retryable: false,
            needs_reauth: false,
            message: msg.into(),
        }
    }
    fn reauth(msg: impl Into<String>) -> Self {
        Self {
            retryable: false,
            needs_reauth: true,
            message: msg.into(),
        }
    }
}

pub fn build_authorize_url(
    spec: &ProviderSpec,
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    scopes: &[String],
    pkce_challenge: Option<&str>,
) -> String {
    let scope_list = if scopes.is_empty() {
        &spec.default_scopes
    } else {
        scopes
    };
    let scope = scope_list.join(&spec.scope_separator);
    // BTreeMap keeps the query deterministic (nice for tests and caching).
    let mut params: BTreeMap<&str, String> = BTreeMap::new();
    params.insert("response_type", "code".to_string());
    params.insert("client_id", client_id.to_string());
    params.insert("redirect_uri", redirect_uri.to_string());
    params.insert("state", state.to_string());
    params.insert("scope", scope);
    if let Some(challenge) = pkce_challenge {
        params.insert("code_challenge", challenge.to_string());
        params.insert("code_challenge_method", "S256".to_string());
    }
    for (k, v) in &spec.extra_authorize_params {
        params.insert(k.as_str(), v.clone());
    }
    let query: Vec<String> = params
        .iter()
        .map(|(k, v)| format!("{}={}", k, urlencode(v)))
        .collect();
    format!("{}?{}", spec.authorize_url, query.join("&"))
}

pub async fn exchange_code(
    transport: &dyn TokenTransport,
    spec: &ProviderSpec,
    client_id: &str,
    client_secret: &SecretString,
    code: &str,
    redirect_uri: &str,
    pkce_verifier: Option<&str>,
) -> Result<TokenResult, OAuthFailure> {
    let mut form = vec![
        ("grant_type".to_string(), "authorization_code".to_string()),
        ("code".to_string(), code.to_string()),
        ("redirect_uri".to_string(), redirect_uri.to_string()),
    ];
    if let Some(verifier) = pkce_verifier {
        form.push(("code_verifier".to_string(), verifier.to_string()));
    }
    token_request(transport, spec, client_id, client_secret, form).await
}

/// Best-effort token revocation (RFC 7009). No-op when the provider declares no
/// `revoke_url`. Used on disconnect so a deleted connection's token is also killed
/// upstream, not just forgotten locally.
pub async fn revoke(
    transport: &dyn TokenTransport,
    spec: &ProviderSpec,
    client_id: &str,
    client_secret: &SecretString,
    token: &SecretString,
) -> Result<(), OAuthFailure> {
    let Some(url) = spec.revoke_url.as_deref().filter(|u| !u.is_empty()) else {
        return Ok(());
    };
    let mut form = vec![("token".to_string(), token.expose_secret().to_string())];
    let basic = client_auth(spec, client_id, client_secret, &mut form);
    let (status, _) = transport
        .post_form(url, &form, spec.token_accept_json, basic)
        .await
        .map_err(|e| OAuthFailure::retryable(format!("network: {}", e.0)))?;
    // RFC 7009: the endpoint returns 200 even for an already-invalid token. Treat any
    // 2xx as success; 5xx as retryable; anything else as a non-fatal revoke failure.
    if status < 300 {
        Ok(())
    } else if status >= 500 {
        Err(OAuthFailure::retryable(format!(
            "{} revoke returned {}",
            spec.id, status
        )))
    } else {
        Err(OAuthFailure::fatal(format!(
            "{} revoke returned {}",
            spec.id, status
        )))
    }
}

pub async fn refresh(
    transport: &dyn TokenTransport,
    spec: &ProviderSpec,
    client_id: &str,
    client_secret: &SecretString,
    refresh_token: &SecretString,
) -> Result<TokenResult, OAuthFailure> {
    let form = vec![
        ("grant_type".to_string(), "refresh_token".to_string()),
        (
            "refresh_token".to_string(),
            refresh_token.expose_secret().to_string(),
        ),
    ];
    token_request(transport, spec, client_id, client_secret, form).await
}

async fn token_request(
    transport: &dyn TokenTransport,
    spec: &ProviderSpec,
    client_id: &str,
    client_secret: &SecretString,
    mut form: Vec<(String, String)>,
) -> Result<TokenResult, OAuthFailure> {
    let basic = client_auth(spec, client_id, client_secret, &mut form);

    let (status, body) = transport
        .post_form(&spec.token_url, &form, spec.token_accept_json, basic)
        .await
        .map_err(|e| OAuthFailure::retryable(format!("network: {}", e.0)))?;

    if status >= 500 {
        return Err(OAuthFailure::retryable(format!(
            "{} returned {}",
            spec.id, status
        )));
    }

    // OAuth error semantics. invalid_grant / revoked => user must reconnect.
    if let Some(code) = body.get("error").and_then(|v| v.as_str()) {
        return Err(classify(spec, code));
    }
    // Slack signals failure via ok:false rather than an HTTP status or an `error` field;
    // any `error` string was already handled above, so the code here is unknown.
    if body.get("ok").and_then(|v| v.as_bool()) == Some(false) {
        return Err(classify(spec, "unknown"));
    }
    if status >= 400 {
        return Err(OAuthFailure::fatal(format!(
            "{} returned {}",
            spec.id, status
        )));
    }

    let access = dotted_get(&body, &spec.token_path)
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            OAuthFailure::fatal(format!("{}: no token at {}", spec.id, spec.token_path))
        })?;

    let refresh_token = dotted_get(&body, &spec.refresh_token_path)
        .and_then(|v| v.as_str())
        .map(secret);

    let expires_in = dotted_get(&body, &spec.expires_in_path).and_then(|v| match v {
        serde_json::Value::Number(n) => n.as_i64(),
        serde_json::Value::String(s) => s.parse().ok(),
        _ => None,
    });

    let scope = body.get("scope").and_then(|v| v.as_str()).map(String::from);

    Ok(TokenResult {
        access_token: secret(access),
        refresh_token,
        expires_in,
        scope,
    })
}

/// Apply the provider's client-authentication style to an outbound token-endpoint request:
/// either hand back HTTP Basic credentials for the caller to set, or push client_id/
/// client_secret into the form body. One copy, shared by every token-endpoint call
/// (exchange, refresh, revoke) so the two dialects can never drift apart.
fn client_auth(
    spec: &ProviderSpec,
    client_id: &str,
    client_secret: &SecretString,
    form: &mut Vec<(String, String)>,
) -> Option<(String, SecretString)> {
    match spec.token_auth_style {
        TokenAuthStyle::Basic => Some((client_id.to_string(), client_secret.clone())),
        TokenAuthStyle::Post => {
            form.push(("client_id".to_string(), client_id.to_string()));
            form.push((
                "client_secret".to_string(),
                client_secret.expose_secret().to_string(),
            ));
            None
        }
    }
}

fn classify(spec: &ProviderSpec, code: &str) -> OAuthFailure {
    match code {
        "invalid_grant" | "invalid_token" | "token_revoked" => {
            OAuthFailure::reauth(format!("{}: {}", spec.id, code))
        }
        other => OAuthFailure::fatal(format!("{}: {}", spec.id, other)),
    }
}

/// Minimal RFC 3986 percent-encoding for query values (no external dep).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}
