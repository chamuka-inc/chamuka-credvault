//! Encryption at rest — versioned keyring, AES-256-GCM-SIV, AAD-bound.
//!
//! Ciphertext format: `v{version}.{base64url(nonce ‖ ciphertext+tag)}`.
//! The version prefix makes key rotation routine: add a key, mark it active, and
//! re-encrypt lazily; old blobs keep decrypting under their original key. The AAD is
//! the connection identity, so a blob cannot be moved between rows even with DB write
//! access. The module is small and self-contained so it can be swapped for a KMS.
//!
//! The AEAD is AES-256-GCM-**SIV** (RFC 8452), nonce-misuse-resistant: with a single
//! long-lived key encrypting many blobs, a random 96-bit nonce repeating (birthday bound)
//! is not catastrophic the way it is for plain GCM — a collision at worst leaks whether
//! two (plaintext, AAD) pairs were identical, never the key or the plaintext. Key bytes
//! and transient decode buffers are held in `Zeroizing` so they are wiped on drop.

use std::collections::HashMap;

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine as _;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::{secret, ExposeSecret, SecretString};

const NONCE_LEN: usize = 12;

pub struct Keyring {
    keys: HashMap<String, Zeroizing<[u8; 32]>>,
    active: String,
}

impl Keyring {
    /// Build from `VAULT_KEYS` (JSON `{version: base64url-32-bytes}`) + active version.
    pub fn from_config(keys_json: &str, active: &str) -> anyhow::Result<Self> {
        let raw: HashMap<String, String> = serde_json::from_str(keys_json)?;
        let mut keys = HashMap::new();
        for (ver, b64) in raw {
            // Decoded key bytes pass through a zeroizing buffer so the raw key never
            // lingers in a freed allocation after being copied into the fixed array.
            let bytes = Zeroizing::new(URL_SAFE.decode(b64.as_bytes())?);
            let mut arr = Zeroizing::new([0u8; 32]);
            anyhow::ensure!(bytes.len() == 32, "key {ver} is not 32 bytes");
            arr.copy_from_slice(&bytes);
            keys.insert(ver, arr);
        }
        anyhow::ensure!(
            keys.contains_key(active),
            "active key version {active} not present in VAULT_KEYS"
        );
        Ok(Self {
            keys,
            active: active.to_string(),
        })
    }

    pub fn active_version(&self) -> &str {
        &self.active
    }

    pub fn encrypt(&self, plaintext: &SecretString, aad: &[u8]) -> Result<String, Error> {
        let key = self.keys.get(&self.active).ok_or(Error::Internal)?;
        let cipher = Aes256GcmSiv::new_from_slice(key.as_slice()).map_err(|_| Error::Internal)?;
        let nonce_bytes: [u8; NONCE_LEN] = rand::random();
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.expose_secret().as_bytes(),
                    aad,
                },
            )
            .map_err(|_| Error::Internal)?;
        let mut blob = Vec::with_capacity(NONCE_LEN + ct.len());
        blob.extend_from_slice(&nonce_bytes);
        blob.extend_from_slice(&ct);
        Ok(format!("v{}.{}", self.active, URL_SAFE.encode(blob)))
    }

    pub fn decrypt(&self, token: &str, aad: &[u8]) -> Result<SecretString, Error> {
        let (ver_tag, b64) = token.split_once('.').ok_or(Error::Internal)?;
        let ver = ver_tag.strip_prefix('v').ok_or(Error::Internal)?;
        let key = self.keys.get(ver).ok_or(Error::Internal)?;
        let raw = URL_SAFE
            .decode(b64.as_bytes())
            .map_err(|_| Error::Internal)?;
        if raw.len() < NONCE_LEN {
            return Err(Error::Internal);
        }
        let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
        let cipher = Aes256GcmSiv::new_from_slice(key.as_slice()).map_err(|_| Error::Internal)?;
        // Recovered plaintext lands in a zeroizing buffer before re-entering SecretString,
        // so no transient copy of the cleartext outlives this call.
        let pt = Zeroizing::new(
            cipher
                .decrypt(Nonce::from_slice(nonce_bytes), Payload { msg: ct, aad })
                .map_err(|_| Error::Internal)?, // wrong key / tampered / rebound AAD
        );
        let s = std::str::from_utf8(&pt).map_err(|_| Error::Internal)?;
        Ok(secret(s))
    }
}

pub fn key_version_of(token: &str) -> Option<String> {
    token
        .split_once('.')
        .and_then(|(v, _)| v.strip_prefix('v'))
        .map(String::from)
}

/// Generate a fresh base64url 256-bit key (for the CLI / bootstrap).
pub fn generate_key() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE.encode(bytes)
}
