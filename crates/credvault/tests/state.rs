//! Signed OAuth state: integrity + expiry.
use credvault::crypto::secret::secret;
use credvault::state::{self, StateClaims};

const NOW: i64 = 1_000_000;

fn claims(exp: i64) -> StateClaims {
    StateClaims {
        p: "google".into(),
        n: "nonce".into(),
        exp,
    }
}

#[test]
fn issue_then_verify() {
    let k = secret("state-key");
    let tok = state::issue(&k, &claims(NOW + 100));
    let got = state::verify(&k, &tok, NOW).unwrap();
    assert_eq!(got.p, "google");
    assert_eq!(got.n, "nonce");
}

#[test]
fn rejects_expired() {
    let k = secret("state-key");
    let tok = state::issue(&k, &claims(NOW - 1));
    assert!(state::verify(&k, &tok, NOW).is_err());
}

#[test]
fn rejects_wrong_secret() {
    let tok = state::issue(&secret("key-a"), &claims(NOW + 100));
    assert!(state::verify(&secret("key-b"), &tok, NOW).is_err());
}

#[test]
fn rejects_tampered_payload() {
    let k = secret("state-key");
    let tok = state::issue(&k, &claims(NOW + 100));
    let (payload, sig) = tok.split_once('.').unwrap();
    let mut p = payload.to_string();
    p.pop();
    p.push('A');
    let forged = format!("{p}.{sig}");
    assert!(state::verify(&k, &forged, NOW).is_err());
}
