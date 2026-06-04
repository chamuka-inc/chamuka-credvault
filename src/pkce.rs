//! PKCE (RFC 7636) for the authorization-code flow.
//!
//! The per-flow code verifier is a fresh, independent CSPRNG secret — never derived from
//! anything that travels in the front channel. It is generated at authorize time, stored
//! server-side (encrypted, single-use) against the flow's state nonce, and looked up at
//! the callback. Only the S256 *challenge* is public; it travels in the authorize URL.
//!
//! Why independence matters: PKCE defends against authorization-code interception. If the
//! verifier could be recomputed from the state (which rides the front channel alongside
//! the code), an attacker who captures the redirect would hold both halves and PKCE would
//! add nothing. A random verifier known only to the server preserves the guarantee. We are
//! a confidential client (we also hold the client secret), so PKCE is defense-in-depth — a
//! provider opts in with `ProviderSpec.uses_pkce`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::secret::{secret, SecretString};

/// Number of random bytes behind a verifier. 32 bytes → 43 base64url chars, the low end
/// of RFC 7636's 43–128 range, at a full 256 bits of entropy.
const VERIFIER_BYTES: usize = 32;

/// Generate a fresh, single-use PKCE code verifier from the OS CSPRNG. The value is high
/// entropy and unpredictable, so it provides real interception protection rather than
/// relying on the secrecy of any other key.
pub fn generate_verifier() -> SecretString {
    let mut bytes = [0u8; VERIFIER_BYTES];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let v = URL_SAFE_NO_PAD.encode(bytes);
    bytes.iter_mut().for_each(|b| *b = 0);
    secret(v)
}

/// The S256 code challenge for a verifier: `base64url(SHA256(verifier))`.
pub fn challenge_s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
