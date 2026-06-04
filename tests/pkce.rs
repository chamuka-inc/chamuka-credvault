//! PKCE (RFC 7636) correctness and end-to-end wiring through the OAuth engine.

use std::sync::{Arc, Mutex};

use credvault::oauth;
use credvault::pkce;
use credvault::providers::ProviderSpec;
use credvault::secret::{secret, ExposeSecret};
use credvault::transport::{FnTransport, TransportError};

#[test]
fn s256_matches_rfc7636_appendix_b_vector() {
    // RFC 7636, Appendix B.
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    assert_eq!(pkce::challenge_s256(verifier), expected);
}

#[test]
fn generated_verifier_is_random_high_entropy_and_well_formed() {
    let v1 = pkce::generate_verifier();
    let v2 = pkce::generate_verifier();
    // Independent CSPRNG draws: two verifiers must (with overwhelming probability) differ.
    assert_ne!(
        v1.expose_secret(),
        v2.expose_secret(),
        "verifiers must be random, not derived"
    );
    // RFC 7636 length bound: 43..=128 chars, drawn from the unreserved base64url set.
    let v = v1.expose_secret();
    assert!((43..=128).contains(&v.len()));
    assert!(v
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
}

#[test]
fn challenge_is_s256_of_the_generated_verifier() {
    let v = pkce::generate_verifier();
    let expected = pkce::challenge_s256(v.expose_secret());
    // Recomputing the challenge from the same verifier is stable.
    assert_eq!(pkce::challenge_s256(v.expose_secret()), expected);
}

#[test]
fn authorize_url_includes_challenge_only_when_requested() {
    let spec = ProviderSpec {
        id: "x".into(),
        authorize_url: "https://twitter.com/i/oauth2/authorize".into(),
        uses_pkce: true,
        ..Default::default()
    };
    let with = oauth::build_authorize_url(&spec, "cid", "https://cb", "STATE", &[], Some("CHAL"));
    assert!(with.contains("code_challenge=CHAL"));
    assert!(with.contains("code_challenge_method=S256"));

    let without = oauth::build_authorize_url(&spec, "cid", "https://cb", "STATE", &[], None);
    assert!(!without.contains("code_challenge"));
}

#[tokio::test]
async fn exchange_code_sends_verifier_to_token_endpoint() {
    // Capture the form the engine posts so we can assert code_verifier is present.
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(vec![]));
    let seen2 = seen.clone();
    let transport = FnTransport(move |_url: &str, form: &[(String, String)]| {
        *seen2.lock().unwrap() = form.to_vec();
        Ok::<_, TransportError>((200, serde_json::json!({"access_token": "tok"})))
    });

    let spec = ProviderSpec {
        id: "x".into(),
        token_url: "https://api.twitter.com/2/oauth2/token".into(),
        uses_pkce: true,
        ..Default::default()
    };
    let verifier = "the-secret-verifier-value-1234567890-abcdEFG";
    oauth::exchange_code(
        &transport,
        &spec,
        "cid",
        &secret("sec"),
        "auth-code",
        "https://cb",
        Some(verifier),
    )
    .await
    .expect("exchange ok");

    let form = seen.lock().unwrap();
    let cv = form.iter().find(|(k, _)| k == "code_verifier");
    assert_eq!(cv.map(|(_, v)| v.as_str()), Some(verifier));
}

#[tokio::test]
async fn revoke_posts_token_and_is_noop_without_url() {
    let seen: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let seen2 = seen.clone();
    let transport = FnTransport(move |url: &str, _form: &[(String, String)]| {
        *seen2.lock().unwrap() = Some(url.to_string());
        Ok::<_, TransportError>((200, serde_json::Value::Null))
    });

    // No revoke_url -> no request made.
    let no_url = ProviderSpec {
        id: "github".into(),
        ..Default::default()
    };
    oauth::revoke(&transport, &no_url, "cid", &secret("sec"), &secret("tok"))
        .await
        .unwrap();
    assert!(seen.lock().unwrap().is_none(), "no url => no request");

    // With revoke_url -> request hits it.
    let with_url = ProviderSpec {
        id: "x".into(),
        revoke_url: Some("https://api.twitter.com/2/oauth2/revoke".into()),
        ..Default::default()
    };
    oauth::revoke(&transport, &with_url, "cid", &secret("sec"), &secret("tok"))
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap().as_deref(),
        Some("https://api.twitter.com/2/oauth2/revoke")
    );
}
