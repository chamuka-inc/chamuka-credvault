//! `import-pipedream` — turn a local clone of Pipedream's `components/` directory into
//! a provider catalog this vault can load.
//!
//! Usage:
//!   import-pipedream <components-dir> [--overlay <file.json>] [--out <file.json>]
//!
//! Outputs:
//!   <out>            valid, directly-loadable providers (set VAULT_PROVIDERS_FILE to it)
//!   <out>.todo.json  overlay skeleton: OAuth apps still missing endpoints, pre-keyed
//!
//! Example:
//!   git clone --depth 1 https://github.com/PipedreamHQ/pipedream
//!   import-pipedream pipedream/components --overlay my-oauth-endpoints.json \
//!     --out providers.pipedream.json
//!   VAULT_PROVIDERS_FILE=providers.pipedream.json credvault list-providers

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde_json::{Map, Value};

use credvault::pipedream::{import_components, AuthKind};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut components_dir: Option<String> = None;
    let mut overlay_path: Option<String> = None;
    let mut out_path = "providers.pipedream.json".to_string();

    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--overlay" => match it.next() {
                Some(v) => overlay_path = Some(v.clone()),
                None => return fail("--overlay needs a path"),
            },
            "--out" => match it.next() {
                Some(v) => out_path = v.clone(),
                None => return fail("--out needs a path"),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: import-pipedream <components-dir> [--overlay f.json] [--out f.json]"
                );
                return ExitCode::SUCCESS;
            }
            other if components_dir.is_none() => components_dir = Some(other.to_string()),
            other => return fail(&format!("unexpected argument: {other}")),
        }
    }

    let Some(components_dir) = components_dir else {
        return fail("missing <components-dir> (path to a Pipedream components/ clone)");
    };

    let overlay = match overlay_path.as_deref() {
        Some(p) => match load_overlay(Path::new(p)) {
            Ok(o) => o,
            Err(e) => return fail(&format!("reading overlay {p}: {e}")),
        },
        None => Map::new(),
    };

    let report = match import_components(Path::new(&components_dir), &overlay) {
        Ok(r) => r,
        Err(e) => return fail(&format!("scanning {components_dir}: {e}")),
    };

    // Write the loadable catalog.
    let out = PathBuf::from(&out_path);
    if let Err(e) = write_json(&out, &report.loadable_json()) {
        return fail(&format!("writing {out_path}: {e}"));
    }

    // Write the overlay skeleton for OAuth apps still missing endpoints.
    let todo_written = if report.needs_endpoints.is_empty() {
        None
    } else {
        let todo = out.with_extension("todo.json");
        if let Err(e) = write_json(&todo, &report.overlay_skeleton()) {
            return fail(&format!("writing {}: {e}", todo.display()));
        }
        Some(todo)
    };

    // Summary.
    let oauth_loaded = report
        .loadable
        .iter()
        .filter(|i| i.kind == AuthKind::OAuth2)
        .count();
    let key_loaded = report
        .loadable
        .iter()
        .filter(|i| i.kind == AuthKind::ApiKey)
        .count();

    eprintln!("Imported from {components_dir}:");
    eprintln!(
        "  loadable now : {} ({key_loaded} api-key, {oauth_loaded} oauth completed) -> {out_path}",
        report.loadable.len()
    );
    eprintln!(
        "  need endpoints: {} oauth apps{}",
        report.needs_endpoints.len(),
        match &todo_written {
            Some(p) => format!(" -> fill {} and re-run with --overlay", p.display()),
            None => String::new(),
        }
    );
    eprintln!("  skipped (no auth): {}", report.skipped_no_auth.len());
    if !report.errors.is_empty() {
        eprintln!("  errors: {}", report.errors.len());
        for (slug, msg) in report.errors.iter().take(10) {
            eprintln!("    {slug}: {msg}");
        }
    }

    ExitCode::SUCCESS
}

fn load_overlay(path: &Path) -> std::io::Result<Map<String, Value>> {
    let data = std::fs::read_to_string(path)?;
    let value: Value = serde_json::from_str(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    match value {
        Value::Object(m) => Ok(m),
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "overlay must be a JSON object mapping slug -> { fields }",
        )),
    }
}

fn write_json(path: &Path, value: &Value) -> std::io::Result<()> {
    let mut s = serde_json::to_string_pretty(value).expect("serialize json");
    s.push('\n');
    std::fs::write(path, s)?;
    restrict_perms(path)
}

/// Provider catalogs may carry client-id env names and endpoint config; write them
/// owner-only (0600) so a generated file isn't left group/world-readable.
#[cfg(unix)]
fn restrict_perms(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_perms(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("import-pipedream: {msg}");
    ExitCode::FAILURE
}
