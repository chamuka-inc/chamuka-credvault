//! Providers can be added and overridden at runtime via JSON, no recompile. This test
//! owns its process, so it sets the env var before the catalog is first touched.

use credvault::providers;

#[test]
fn json_env_adds_and_overrides_providers() {
    std::env::set_var(
        "VAULT_PROVIDERS_JSON",
        r#"[
          {
            "name": "linear",
            "auth_type": "oauth2",
            "authorize_url": "https://linear.app/oauth/authorize",
            "token_url": "https://api.linear.app/oauth/token",
            "client_id_env": "LINEAR_CLIENT_ID",
            "client_secret_env": "LINEAR_CLIENT_SECRET",
            "default_scopes": ["read", "write"]
          },
          {
            "name": "github",
            "auth_type": "oauth2",
            "authorize_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "client_id_env": "GITHUB_CLIENT_ID",
            "client_secret_env": "GITHUB_CLIENT_SECRET",
            "default_scopes": ["repo"],
            "token_accept_json": true
          }
        ]"#,
    );

    // New provider appears.
    let linear = providers::get("linear").expect("linear added from JSON");
    assert_eq!(linear.token_url, "https://api.linear.app/oauth/token");
    assert_eq!(linear.default_scopes, vec!["read", "write"]);

    // Existing provider is overridden (built-in github had two scopes).
    let github = providers::get("github").expect("github present");
    assert_eq!(github.default_scopes, vec!["repo"]);

    // Untouched built-ins remain.
    assert!(providers::get("google").is_some());
    assert!(providers::get("stripe").is_some());
}
