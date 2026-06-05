//! The generic OAuth engine, exercised offline via a closure transport.
mod common;

use credvault::crypto::secret::{secret, ExposeSecret};
use credvault::http::transport::{FnTransport, TransportError};
use credvault::oauth;
use credvault::providers;

type R = Result<(u16, serde_json::Value), TransportError>;

// Avoid requiring Debug on the secret-bearing success type.
fn expect_err<T>(r: Result<T, oauth::OAuthFailure>) -> oauth::OAuthFailure {
    match r {
        Ok(_) => panic!("expected an OAuth failure"),
        Err(e) => e,
    }
}

#[tokio::test]
async fn exchange_code_success() {
    common::default_plugins();
    let spec = providers::get("github").unwrap();
    let t = FnTransport(|_url: &str, _form: &[(String, String)]| -> R {
        Ok((
            200,
            serde_json::json!({"access_token": "gho_abc", "scope": "repo"}),
        ))
    });
    let r = oauth::exchange_code(&t, spec, "cid", &secret("sec"), "code", "https://cb", None)
        .await
        .unwrap();
    assert_eq!(r.access_token.expose_secret(), "gho_abc");
    assert_eq!(r.scope.as_deref(), Some("repo"));
}

#[tokio::test]
async fn invalid_grant_flags_reauth() {
    common::default_plugins();
    let spec = providers::get("google").unwrap();
    let t = FnTransport(|_url: &str, _form: &[(String, String)]| -> R {
        Ok((400, serde_json::json!({"error": "invalid_grant"})))
    });
    let err = expect_err(oauth::refresh(&t, spec, "cid", &secret("sec"), &secret("rt")).await);
    assert!(err.needs_reauth);
    assert!(!err.retryable);
}

#[tokio::test]
async fn server_error_is_retryable() {
    common::default_plugins();
    let spec = providers::get("google").unwrap();
    let t = FnTransport(|_url: &str, _form: &[(String, String)]| -> R {
        Ok((503, serde_json::Value::Null))
    });
    let err = expect_err(oauth::refresh(&t, spec, "cid", &secret("sec"), &secret("rt")).await);
    assert!(err.retryable);
}

#[tokio::test]
async fn slack_ok_false_is_failure() {
    common::default_plugins();
    let spec = providers::get("slack").unwrap();
    let t = FnTransport(|_url: &str, _form: &[(String, String)]| -> R {
        Ok((
            200,
            serde_json::json!({"ok": false, "error": "invalid_code"}),
        ))
    });
    let err = expect_err(
        oauth::exchange_code(&t, spec, "cid", &secret("sec"), "code", "https://cb", None).await,
    );
    assert!(!err.retryable);
}

#[tokio::test]
async fn network_failure_is_retryable() {
    common::default_plugins();
    let spec = providers::get("google").unwrap();
    let t = FnTransport(|_url: &str, _form: &[(String, String)]| -> R {
        Err(TransportError("connection refused".into()))
    });
    let err = expect_err(oauth::refresh(&t, spec, "cid", &secret("sec"), &secret("rt")).await);
    assert!(err.retryable);
}
