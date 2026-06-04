//! Signed OAuth `state` — a tamper-proof CSRF token carrying only the provider, a random
//! nonce, and an expiry. The nonce is the handle into the server-side `oauth_flows` row,
//! which holds the authoritative identity (tenant/user/account) and PKCE verifier — so no
//! tenant/user identity ever travels in the front channel.
//!
//! Token = `base64url(claims_json).base64url(hmac_sha256(secret, claims_b64))`.
//! Verified with a constant-time MAC comparison and an expiry check.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::Error;
use crate::secret::{ExposeSecret, SecretString};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Serialize, Deserialize)]
pub struct StateClaims {
    pub p: String, // provider
    pub n: String, // nonce — the oauth_flows row key
    pub exp: i64,  // unix seconds
}

fn sign(secret: &SecretString, payload_b64: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.expose_secret().as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(payload_b64.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

pub fn issue(secret: &SecretString, claims: &StateClaims) -> String {
    let payload = serde_json::to_vec(claims).expect("claims serialize");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let sig = sign(secret, &payload_b64);
    format!("{payload_b64}.{sig}")
}

pub fn verify(secret: &SecretString, token: &str, now_unix: i64) -> Result<StateClaims, Error> {
    let (payload_b64, sig) = token.split_once('.').ok_or(Error::BadState)?;
    let expected = sign(secret, payload_b64);
    if !constant_time_eq::constant_time_eq(expected.as_bytes(), sig.as_bytes()) {
        return Err(Error::BadState);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| Error::BadState)?;
    let claims: StateClaims = serde_json::from_slice(&payload).map_err(|_| Error::BadState)?;
    if now_unix > claims.exp {
        return Err(Error::BadState);
    }
    Ok(claims)
}
