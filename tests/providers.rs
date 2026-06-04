//! The provider registry (loaded from the default plugin dir) + the generic authorize-URL
//! builder honor declarative quirks.

mod common;

use credvault::oauth;
use credvault::providers::{self, dotted_get};

#[test]
fn registry_lookup() {
    common::default_plugins();
    for id in ["google", "github", "slack", "notion", "stripe"] {
        assert!(providers::get(id).is_some(), "{id} missing");
    }
    assert!(providers::get("does-not-exist").is_none());
}

#[test]
fn google_authorize_url_has_offline_params() {
    common::default_plugins();
    let spec = providers::get("google").unwrap();
    let url = oauth::build_authorize_url(spec, "client-123", "https://cb/x", "STATE", &[], None);
    assert!(url.contains("access_type=offline"));
    assert!(url.contains("prompt=consent"));
    assert!(url.contains("state=STATE"));
    assert!(url.contains("client_id=client-123"));
    assert!(url.contains("response_type=code"));
}

#[test]
fn slack_nested_token_path() {
    common::default_plugins();
    let v = serde_json::json!({"ok": true, "authed_user": {"access_token": "xoxp-1"}});
    let spec = providers::get("slack").unwrap();
    assert_eq!(
        dotted_get(&v, &spec.token_path).and_then(|x| x.as_str()),
        Some("xoxp-1")
    );
}

#[test]
fn unconfigured_without_env() {
    common::default_plugins();
    // No GOOGLE_CLIENT_ID set in this process => not configured.
    let spec = providers::get("google").unwrap();
    assert!(!spec.is_configured());
    // ApiKey providers are always "configured" (no client creds needed).
    assert!(providers::get("stripe").unwrap().is_configured());
}
