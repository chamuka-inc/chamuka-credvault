//! Importer parsing/classification, using synthetic sources that mirror the real
//! `app.mjs` shapes (key `app: "<slug>"`, `this.$auth.<field>` usage).

use credvault::oauth::pipedream::{classify_auth, extract_slug, import_source, AuthKind};
use serde_json::{json, Map};

const OAUTH_APP: &str = r#"
import { axios } from "@pipedream/platform";
export default {
  type: "app",
  app: "airtable_oauth",
  methods: {
    _headers() {
      return { Authorization: `Bearer ${this.$auth.oauth_access_token}` };
    },
    _baseUrl() { return "https://api.airtable.com/v0"; },
  },
};
"#;

const KEY_APP: &str = r#"
import { axios } from "@pipedream/platform";
export default {
  type: "app",
  app: "stripe",
  methods: {
    _auth() { return { username: this.$auth.api_key }; },
  },
};
"#;

const NO_AUTH_APP: &str = r#"
export default {
  type: "app",
  app: "formatting",
  methods: {},
};
"#;

#[test]
fn extracts_slug_from_app_key_not_type_value() {
    assert_eq!(extract_slug(OAUTH_APP).as_deref(), Some("airtable_oauth"));
    assert_eq!(extract_slug(KEY_APP).as_deref(), Some("stripe"));
    assert_eq!(extract_slug("no app here").as_deref(), None);
}

#[test]
fn classifies_auth_kind() {
    assert_eq!(classify_auth(OAUTH_APP), AuthKind::OAuth2);
    assert_eq!(classify_auth(KEY_APP), AuthKind::ApiKey);
    assert_eq!(classify_auth(NO_AUTH_APP), AuthKind::None);
}

#[test]
fn key_app_imports_complete_and_valid() {
    let overlay = Map::new();
    let (slug, kind, outcome) = import_source("stripe", KEY_APP, &overlay);
    assert_eq!(slug, "stripe");
    assert_eq!(kind, AuthKind::ApiKey);
    let value = outcome.expect("key app should validate without endpoints");
    assert_eq!(value["auth_type"], "api_key");
}

#[test]
fn oauth_app_needs_endpoints_without_overlay() {
    let overlay = Map::new();
    let (_, kind, outcome) = import_source("airtable_oauth", OAUTH_APP, &overlay);
    assert_eq!(kind, AuthKind::OAuth2);
    // No authorize/token URL yet -> fails the same validation the runtime applies.
    assert!(outcome.is_err());
}

#[test]
fn oauth_app_completes_with_overlay() {
    let mut overlay = Map::new();
    overlay.insert(
        "airtable_oauth".to_string(),
        json!({
            "authorize_url": "https://airtable.com/oauth2/v1/authorize",
            "token_url": "https://airtable.com/oauth2/v1/token",
            "default_scopes": ["data.records:read"]
        }),
    );
    let (_, _, outcome) = import_source("airtable_oauth", OAUTH_APP, &overlay);
    let value = outcome.expect("overlay should complete the oauth spec");
    assert_eq!(value["auth_type"], "oauth2");
    assert_eq!(value["client_id_env"], "AIRTABLE_OAUTH_CLIENT_ID");
    assert_eq!(value["token_url"], "https://airtable.com/oauth2/v1/token");
}
