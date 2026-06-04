//! Plugin discovery semantics: directory scanning, later-dir-wins-by-id override, intra-dir
//! id collision, an empty input, and refusal of a too-new manifest schema. Drives the pure
//! `providers::load_from` loader directly with temp directories, so each case is independent
//! of the process-global registry.

use credvault::providers::load_from;
use std::fs;
use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cv_plugins_{}_{tag}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn write(dir: &Path, name: &str, body: &str) {
    fs::write(dir.join(name), body).unwrap();
}

#[test]
fn discovers_every_json_in_a_dir() {
    let d = scratch("discover");
    write(
        &d,
        "alpha.json",
        r#"{"id":"alpha","version":"1.0.0","auth_type":"api_key"}"#,
    );
    write(
        &d,
        "beta.json",
        r#"{"id":"beta","version":"1.0.0","auth_type":"api_key"}"#,
    );
    // A non-json file is ignored.
    write(&d, "README.md", "not a manifest");

    let specs = load_from(&[d.to_str().unwrap()]).unwrap();
    let ids: Vec<&str> = specs.iter().map(|s| s.id.as_str()).collect();
    assert_eq!(ids, vec!["alpha", "beta"]); // sorted by id
    fs::remove_dir_all(&d).ok();
}

#[test]
fn later_dir_overrides_earlier_by_id() {
    let a = scratch("override_a");
    let b = scratch("override_b");
    write(
        &a,
        "shared.json",
        r#"{"id":"shared","version":"1.0.0","auth_type":"api_key"}"#,
    );
    write(
        &a,
        "only_a.json",
        r#"{"id":"only_a","version":"1.0.0","auth_type":"api_key"}"#,
    );
    write(
        &b,
        "shared.json",
        r#"{"id":"shared","version":"2.0.0","auth_type":"api_key"}"#,
    );

    let specs = load_from(&[a.to_str().unwrap(), b.to_str().unwrap()]).unwrap();
    let shared = specs.iter().find(|s| s.id == "shared").unwrap();
    assert_eq!(shared.version, "2.0.0", "later dir must win by id");
    assert!(
        specs.iter().any(|s| s.id == "only_a"),
        "earlier-only providers survive the override"
    );
    fs::remove_dir_all(&a).ok();
    fs::remove_dir_all(&b).ok();
}

#[test]
fn filename_must_match_id() {
    let d = scratch("mismatch");
    // File named github.json but the manifest declares a different id (e.g. a typo): the
    // filename is the id, so this is rejected rather than silently adding a stray provider.
    write(
        &d,
        "github.json",
        r#"{"id":"gitub","version":"1.0.0","auth_type":"api_key"}"#,
    );

    let err = load_from(&[d.to_str().unwrap()]).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("filename implies") && msg.contains("gitub"),
        "expected a filename/id mismatch error, got: {msg}"
    );
    fs::remove_dir_all(&d).ok();
}

#[test]
fn no_dirs_yields_no_providers() {
    assert!(load_from(&[]).unwrap().is_empty());
}

#[test]
fn unknown_field_in_manifest_is_refused() {
    let d = scratch("typo");
    // `tokenpath` is a typo for `token_path` — must fail loudly, not be silently dropped.
    write(
        &d,
        "typo.json",
        r#"{"id":"typo","version":"1.0.0","auth_type":"api_key","tokenpath":"x"}"#,
    );
    let err = load_from(&[d.to_str().unwrap()]).unwrap_err();
    assert!(
        format!("{err:#}").contains("unknown field"),
        "expected an unknown-field error, got: {err:#}"
    );
    fs::remove_dir_all(&d).ok();
}

#[test]
fn manifest_version_newer_than_build_is_refused() {
    let d = scratch("future");
    write(
        &d,
        "future.json",
        r#"{"manifest_version":999,"id":"future","version":"1.0.0","auth_type":"api_key"}"#,
    );
    let err = load_from(&[d.to_str().unwrap()]).unwrap_err();
    assert!(
        format!("{err:#}").contains("manifest_version"),
        "expected a manifest_version error, got: {err:#}"
    );
    fs::remove_dir_all(&d).ok();
}
