//! Outbound provider HTTP behind a trait, so the OAuth engine is testable offline.
//!
//! `post_form` returns the HTTP status + parsed JSON body for any completed response
//! (including 4xx/5xx with a JSON error). A `TransportError` means the request did not
//! complete (network/TLS) — the OAuth layer treats that as retryable.

use async_trait::async_trait;
use std::time::Duration;

use crate::crypto::secret::{ExposeSecret, SecretString};

#[derive(Debug)]
pub struct TransportError(pub String);

#[async_trait]
pub trait TokenTransport: Send + Sync {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        accept_json: bool,
        basic: Option<(String, SecretString)>,
    ) -> Result<(u16, serde_json::Value), TransportError>;
}

pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// `https_only` rejects any plaintext `http://` outbound request at the client layer —
    /// a backstop beneath provider-spec validation so a token/refresh/revoke call can never
    /// leave the process in cleartext in production.
    pub fn new(timeout_seconds: u64, https_only: bool) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_seconds))
            .https_only(https_only)
            .user_agent("credvault/1.0")
            .build()
            .expect("reqwest client builds");
        Self { client }
    }
}

#[async_trait]
impl TokenTransport for ReqwestTransport {
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        accept_json: bool,
        basic: Option<(String, SecretString)>,
    ) -> Result<(u16, serde_json::Value), TransportError> {
        let mut req = self.client.post(url).form(form);
        if accept_json {
            req = req.header(reqwest::header::ACCEPT, "application/json");
        }
        if let Some((user, pass)) = basic {
            req = req.basic_auth(user, Some(pass.expose_secret()));
        }
        let resp = req
            .send()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        let status = resp.status().as_u16();
        // Parse JSON if possible; otherwise hand back Null so the caller can decide.
        let body = resp
            .text()
            .await
            .map_err(|e| TransportError(e.to_string()))?;
        let value = serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
        Ok((status, value))
    }
}

/// A closure-backed transport for tests. The closure is synchronous and pure.
pub struct FnTransport<F>(pub F);

#[async_trait]
impl<F> TokenTransport for FnTransport<F>
where
    F: Fn(&str, &[(String, String)]) -> Result<(u16, serde_json::Value), TransportError>
        + Send
        + Sync,
{
    async fn post_form(
        &self,
        url: &str,
        form: &[(String, String)],
        _accept_json: bool,
        _basic: Option<(String, SecretString)>,
    ) -> Result<(u16, serde_json::Value), TransportError> {
        (self.0)(url, form)
    }
}
