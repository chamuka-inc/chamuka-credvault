//! Encryption: roundtrip, AAD binding, versioning, rotation.
use credvault::crypto::{self, Keyring};
use credvault::secret::{secret, ExposeSecret};

fn ring(active: &str) -> Keyring {
    let (k1, k2) = (crypto::generate_key(), crypto::generate_key());
    let json = format!(r#"{{"1":"{k1}","2":"{k2}"}}"#);
    Keyring::from_config(&json, active).unwrap()
}

#[test]
fn roundtrip() {
    let r = ring("1");
    let aad = b"tenant:google:user:default";
    let ct = r.encrypt(&secret("token-xyz"), aad).unwrap();
    assert!(ct.starts_with("v1."));
    assert_eq!(r.decrypt(&ct, aad).unwrap().expose_secret(), "token-xyz");
}

#[test]
fn aad_binding_prevents_relocation() {
    let r = ring("1");
    let ct = r.encrypt(&secret("x"), b"aad-a").unwrap();
    // A blob encrypted for one identity must not decrypt under another.
    assert!(r.decrypt(&ct, b"aad-b").is_err());
}

#[test]
fn version_tracks_active_key() {
    let r = ring("2");
    let ct = r.encrypt(&secret("x"), b"a").unwrap();
    assert_eq!(crypto::key_version_of(&ct).as_deref(), Some("2"));
}

#[test]
fn old_blobs_decrypt_after_rotation() {
    let (k1, k2) = (crypto::generate_key(), crypto::generate_key());
    let json = format!(r#"{{"1":"{k1}","2":"{k2}"}}"#);
    let r1 = Keyring::from_config(&json, "1").unwrap();
    let ct = r1.encrypt(&secret("legacy"), b"a").unwrap();
    // Rotate active to v2; the v1 blob still decrypts.
    let r2 = Keyring::from_config(&json, "2").unwrap();
    assert_eq!(r2.decrypt(&ct, b"a").unwrap().expose_secret(), "legacy");
}

#[test]
fn tampered_ciphertext_fails() {
    let r = ring("1");
    let mut ct = r.encrypt(&secret("x"), b"a").unwrap();
    ct.pop();
    ct.push(if ct.ends_with('A') { 'B' } else { 'A' });
    assert!(r.decrypt(&ct, b"a").is_err());
}
