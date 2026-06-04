//! Import Pipedream's open-source app catalog into our provider JSON.
//!
//! Pipedream defines one app per `components/<slug>/<slug>.app.mjs`, each exporting
//! `{ type: "app", app: "<slug>", methods }`. The methods reference the credential as
//! `this.$auth.<field>`: `oauth_access_token` for OAuth apps, `api_key` (or a
//! service-specific name) for key-based apps. That is enough to recover an app's
//! identity and auth *type* by scanning the source — no JS execution, no dependencies.
//!
//! What the repo does NOT contain: OAuth `authorize_url` / `token_url` / scopes.
//! Pipedream brokers the OAuth handshake on its own platform ("OAuth flow and token
//! refresh fully handled by Pipedream"), so the components only consume an
//! already-minted token. Consequently:
//!
//! * **key-based apps import complete** — an api-key `ProviderSpec` needs no endpoints;
//! * **OAuth apps import as skeletons** — identity + `auth_type` + conventional env-var
//!   names — and must be completed with endpoints from an *overlay* (a small JSON map
//!   you maintain for the apps you actually use, or each provider's own docs).
//!
//! The importer emits a directory of provider plugin manifests — one `<id>.json` per app
//! that passes the runtime's own validation — plus a pre-keyed overlay skeleton listing
//! every OAuth app still missing endpoints, so completing them is fill-in-the-blanks.
//! Imported manifests are ordinary plugins: point `VAULT_PLUGIN_DIRS` at the output
//! directory and they load exactly like the shipped defaults, with no special handling.

use std::path::Path;

use serde_json::{json, Map, Value};

use crate::providers::{validate_spec, ProviderSpec};

/// Auth classification recovered from an `app.mjs` source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    OAuth2,
    ApiKey,
    /// No credential referenced (e.g. apps that take only user-supplied config).
    None,
}

/// Extract the `app: "<slug>"` identifier from an `app.mjs` source. Matches the *key*
/// `app:` (not the `type: "app"` value) and returns the first such quoted token.
pub fn extract_slug(src: &str) -> Option<String> {
    let bytes = src.as_bytes();
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'$';
    let mut from = 0;
    while let Some(rel) = src[from..].find("app") {
        let start = from + rel;
        let end = start + 3;
        from = end;
        // "app" must stand alone as a key, not be part of a longer identifier.
        if start > 0 && is_ident(bytes[start - 1]) {
            continue;
        }
        if end < bytes.len() && is_ident(bytes[end]) {
            continue;
        }
        // Expect optional whitespace then ':'.
        let mut j = end;
        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
            j += 1;
        }
        if j >= bytes.len() || bytes[j] != b':' {
            continue;
        }
        // After ':', optional whitespace then a quote opening the slug.
        let mut k = j + 1;
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k >= bytes.len() || (bytes[k] != b'"' && bytes[k] != b'\'') {
            continue;
        }
        let quote = bytes[k];
        let val_start = k + 1;
        let mut m = val_start;
        while m < bytes.len() && bytes[m] != quote {
            m += 1;
        }
        if m < bytes.len() && m > val_start {
            return Some(src[val_start..m].to_string());
        }
    }
    None
}

/// Classify auth by the credential field the source consumes. `oauth_access_token` is
/// the OAuth signal; any other `$auth` reference is treated as key-based.
pub fn classify_auth(src: &str) -> AuthKind {
    if src.contains("oauth_access_token") {
        AuthKind::OAuth2
    } else if src.contains("$auth") {
        AuthKind::ApiKey
    } else {
        AuthKind::None
    }
}

/// Conventional env-var names for an OAuth app's client credentials. Slugs are already
/// snake_case (e.g. `airtable_oauth`), so we just upper-case them.
pub fn client_env_names(slug: &str) -> (String, String) {
    let p = slug.to_ascii_uppercase();
    (format!("{p}_CLIENT_ID"), format!("{p}_CLIENT_SECRET"))
}

/// Version stamped on every imported manifest. Imported providers are skeletons completed
/// from an overlay, so they start at a 0.x version an operator bumps as they verify them.
const IMPORT_VERSION: &str = "0.1.0";

/// The minimal provider manifest for a parsed app, before any overlay is applied.
fn base_value(slug: &str, kind: AuthKind) -> Option<Value> {
    match kind {
        AuthKind::ApiKey => Some(json!({
            "manifest_version": 1,
            "id": slug,
            "version": IMPORT_VERSION,
            "auth_type": "api_key",
        })),
        AuthKind::OAuth2 => {
            let (id_env, secret_env) = client_env_names(slug);
            Some(json!({
                "manifest_version": 1,
                "id": slug,
                "version": IMPORT_VERSION,
                "auth_type": "oauth2",
                "client_id_env": id_env,
                "client_secret_env": secret_env,
            }))
        }
        AuthKind::None => None,
    }
}

/// Shallow-merge `overlay` fields onto `base` (overlay wins).
fn apply_overlay(base: &mut Value, overlay: Option<&Value>) {
    if let (Value::Object(b), Some(Value::Object(o))) = (base, overlay) {
        for (k, v) in o {
            b.insert(k.clone(), v.clone());
        }
    }
}

/// One importable app: the parsed slug, its classification, and the provider JSON value.
pub struct Imported {
    pub slug: String,
    pub kind: AuthKind,
    pub value: Value,
}

/// Outcome of importing a components tree.
#[derive(Default)]
pub struct ImportReport {
    /// Specs that pass the runtime's validation — write these straight to a provider file.
    pub loadable: Vec<Imported>,
    /// OAuth apps still missing endpoints; keys for the overlay skeleton you must fill.
    pub needs_endpoints: Vec<String>,
    /// Apps that reference no credential and were skipped.
    pub skipped_no_auth: Vec<String>,
    /// Apps that failed for an unexpected reason (slug, message).
    pub errors: Vec<(String, String)>,
}

impl ImportReport {
    /// A pre-keyed overlay skeleton for every OAuth app missing endpoints: fill the
    /// blanks and pass it back via `--overlay` to complete those providers.
    pub fn overlay_skeleton(&self) -> Value {
        let mut m = Map::new();
        for slug in &self.needs_endpoints {
            m.insert(
                slug.clone(),
                json!({
                    "authorize_url": "",
                    "token_url": "",
                    "default_scopes": []
                }),
            );
        }
        Value::Object(m)
    }
}

/// Process a single app source. `overlay` is the per-slug override object (if any).
/// Returns the classification and either a validated value or the reason it's incomplete.
pub fn import_source(
    dir_name: &str,
    src: &str,
    overlay: &Map<String, Value>,
) -> (String, AuthKind, Result<Value, String>) {
    let slug = extract_slug(src).unwrap_or_else(|| dir_name.to_string());
    let kind = classify_auth(src);
    let Some(mut value) = base_value(&slug, kind) else {
        return (
            slug,
            kind,
            Err("no $auth credential referenced".to_string()),
        );
    };
    apply_overlay(&mut value, overlay.get(&slug));

    match serde_json::from_value::<ProviderSpec>(value.clone()) {
        Ok(spec) => match validate_spec(&spec) {
            Ok(()) => (slug, kind, Ok(value)),
            Err(e) => (slug, kind, Err(e.to_string())),
        },
        Err(e) => (slug, kind, Err(format!("deserialize: {e}"))),
    }
}

/// Walk a Pipedream `components/` directory and import every app. `overlay` supplies
/// OAuth endpoints (and any quirk overrides) per slug.
pub fn import_components(
    components_dir: &Path,
    overlay: &Map<String, Value>,
) -> std::io::Result<ImportReport> {
    let mut report = ImportReport::default();

    let mut dirs: Vec<_> = std::fs::read_dir(components_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    dirs.sort_by_key(|e| e.file_name());

    for entry in dirs {
        let dir = entry.path();
        let dir_name = entry.file_name().to_string_lossy().to_string();
        let Some(app_file) = find_app_file(&dir, &dir_name) else {
            continue; // not an app component (e.g. shared dir)
        };
        let src = match std::fs::read_to_string(&app_file) {
            Ok(s) => s,
            Err(e) => {
                report.errors.push((dir_name, e.to_string()));
                continue;
            }
        };

        let (slug, kind, outcome) = import_source(&dir_name, &src, overlay);
        match outcome {
            Ok(value) => report.loadable.push(Imported { slug, kind, value }),
            Err(_) if kind == AuthKind::OAuth2 => report.needs_endpoints.push(slug),
            Err(_) if kind == AuthKind::None => report.skipped_no_auth.push(slug),
            Err(msg) => report.errors.push((slug, msg)),
        }
    }
    Ok(report)
}

/// Find `<slug>.app.mjs`, falling back to any single `*.app.mjs` in the directory.
fn find_app_file(dir: &Path, dir_name: &str) -> Option<std::path::PathBuf> {
    let primary = dir.join(format!("{dir_name}.app.mjs"));
    if primary.is_file() {
        return Some(primary);
    }
    std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .find_map(|e| {
            let p = e.path();
            let name = p.file_name()?.to_string_lossy().to_string();
            (p.is_file() && name.ends_with(".app.mjs")).then_some(p)
        })
}
