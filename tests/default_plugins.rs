//! The default providers ship as plugin manifests in `plugins/default`, discovered through
//! the same path as any third-party plugin — there are no built-ins. Prove they all parse,
//! pass the runtime validation the loader applies, carry their packaging metadata, and keep
//! every dialect quirk, so a malformed or lossy edit fails here rather than in production.

mod common;

use credvault::providers::{self, AuthType, TokenAuthStyle};

#[test]
fn default_plugins_parse_validate_and_keep_quirks() {
    common::default_plugins(); // loads plugins/default into the registry (validating each)
    let specs = providers::registry();

    let ids: Vec<&str> = specs.iter().map(|s| s.id.as_str()).collect();
    for expected in [
        "google",
        "github",
        "slack",
        "notion",
        "stripe",
        "x",
        "gitlab",
        "spotify",
        "microsoft",
        "zoom",
        "sendgrid",
    ] {
        assert!(
            ids.contains(&expected),
            "default plugins missing '{expected}'"
        );
    }

    // Every shipped plugin carries packaging metadata.
    assert!(
        specs.iter().all(|s| !s.version.is_empty()),
        "a default plugin is missing its version"
    );

    let by = |n: &str| specs.iter().find(|s| s.id == n).unwrap();

    // Quirks must survive the manifest round-trip, not just the ids.
    assert!(
        !by("google").extra_authorize_params.is_empty(),
        "google extra_authorize_params lost"
    );
    assert_eq!(by("slack").token_path, "authed_user.access_token");
    assert_eq!(by("notion").token_auth_style, TokenAuthStyle::Basic);
    assert!(by("github").token_accept_json);
    assert_eq!(by("stripe").auth_type, AuthType::ApiKey);
    assert_eq!(by("sendgrid").auth_type, AuthType::ApiKey);

    let x = by("x");
    assert!(x.uses_pkce && x.refresh_token_rotates);
    assert_eq!(x.token_auth_style, TokenAuthStyle::Basic);
    assert_eq!(
        x.revoke_url.as_deref(),
        Some("https://api.twitter.com/2/oauth2/revoke")
    );

    assert!(by("gitlab").uses_pkce && by("gitlab").refresh_token_rotates);
    assert!(by("microsoft").uses_pkce);
    assert_eq!(by("zoom").token_auth_style, TokenAuthStyle::Basic);
    assert!(by("zoom").refresh_token_rotates);
}
