//! The built-in catalog is bundled JSON. Prove it parses, passes the same validation
//! the runtime loader applies, and that every dialect quirk survives the round-trip —
//! so a malformed or lossy edit to `catalog.json` fails here rather than in production.

use credvault::providers::{catalog, validate_spec, AuthType, TokenAuthStyle};

#[test]
fn bundled_catalog_parses_validates_and_keeps_quirks() {
    let specs = catalog::build(); // parses catalog.json; panics if malformed

    for s in &specs {
        validate_spec(s).unwrap_or_else(|e| panic!("invalid built-in '{}': {e}", s.name));
    }

    let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
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
        assert!(names.contains(&expected), "catalog missing '{expected}'");
    }

    let by = |n: &str| specs.iter().find(|s| s.name == n).unwrap();

    // Quirks must survive JSON deserialization, not just the names.
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
