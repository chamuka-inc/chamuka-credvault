//! The built-in integrations, expressed as data (JSON), not hand-written Rust.
//!
//! `catalog.json` is bundled into the binary at compile time, so the service works
//! zero-config out of the box. It is parsed with the *same* `ProviderSpec`
//! deserialization and validated by the *same* rules as providers supplied at runtime
//! via `VAULT_PROVIDERS_FILE` / `VAULT_PROVIDERS_JSON` — there is one provider format,
//! and the built-ins are simply its default document. Adding or changing a built-in is
//! a JSON edit; quirks (Google's offline params, Slack's nested token path, Notion's
//! Basic auth, the API-key providers) are declarative fields.

use super::ProviderSpec;

/// The bundled catalog source. A test parses and validates it, so a malformed edit
/// fails CI rather than at runtime.
pub const CATALOG_JSON: &str = include_str!("catalog.json");

pub fn build() -> Vec<ProviderSpec> {
    serde_json::from_str(CATALOG_JSON).expect("bundled provider catalog.json is valid")
}
