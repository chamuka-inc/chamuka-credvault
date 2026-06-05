//! Secret handling — the reason Rust was chosen for this core.
//!
//! Plaintext credentials are carried as [`SecretString`], which:
//!   * has no `Display` and a redacting `Debug` (`Secret([REDACTED])`), so a token
//!     can never reach a log line, an error message, or a panic message by accident;
//!   * zeroizes its memory on drop;
//!   * forces every read through `.expose_secret()`, turning "remember not to log the
//!     secret" (a discipline problem) into "you must write an explicit, greppable
//!     call to see it" (a reviewable, enforceable one).
//!
//! Encryption *output* (ciphertext) is an ordinary `String` — it is safe to store and
//! log. Decryption *returns* a `SecretString`, so recovered plaintext re-enters the
//! protected type immediately.

pub use secrecy::{ExposeSecret, SecretString};

/// Wrap a plaintext value as a secret.
pub fn secret(value: impl Into<String>) -> SecretString {
    SecretString::new(value.into())
}
