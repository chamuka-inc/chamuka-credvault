//! Authentication & tenant authorization for the HTTP surface.
//!
//! Two principals, resolved from the `Authorization: Bearer …` header by typed extractors
//! so a handler that needs one cannot compile without it:
//!
//!   * [`AdminPrincipal`] — the operator, holding `VAULT_ADMIN_TOKEN`. Constant-time
//!     compared. Used only to provision tenants.
//!   * [`TenantPrincipal`] — a tenant, holding its API key. Resolved to a `tenant_id` by
//!     hash lookup. **The `tenant_id` always comes from here, never from the request**, so
//!     a caller can only ever act within its own tenant — closing the cross-tenant IDOR.
//!
//! The OAuth callback is deliberately *not* covered here: it is reached by the end user's
//! browser and authenticates via the signed, single-use `state` token instead.

use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;

use crate::crypto::secret::{secret, ExposeSecret, SecretString};
use crate::error::Error;
use crate::{service, AppState};

/// Prefix on every issued tenant API key — identifies the credential type and lets secret
/// scanners flag it if it ever leaks.
const API_KEY_PREFIX: &str = "cvk_";

/// Mint a fresh tenant API key: prefix + 256 bits of CSPRNG entropy, URL-safe.
pub fn generate_api_key() -> SecretString {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    let key = format!("{API_KEY_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes));
    bytes.iter_mut().for_each(|b| *b = 0);
    secret(key)
}

/// SHA-256 (base64url) of a presented credential. Only the hash is stored or indexed, so
/// the key store reveals nothing usable if exfiltrated; lookups match on the full 256-bit
/// digest of a high-entropy secret, which is not susceptible to a practical timing oracle.
pub fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

/// Pull the bearer token out of the `Authorization` header.
fn bearer(parts: &Parts) -> Result<&str, Error> {
    parts
        .headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or(Error::Unauthorized)
}

/// The operator principal (holds `VAULT_ADMIN_TOKEN`).
pub struct AdminPrincipal;

#[axum::async_trait]
impl FromRequestParts<AppState> for AdminPrincipal {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Error> {
        let token = bearer(parts)?;
        if constant_time_eq::constant_time_eq(
            token.as_bytes(),
            st.cfg.admin_token.expose_secret().as_bytes(),
        ) {
            Ok(AdminPrincipal)
        } else {
            Err(Error::Unauthorized)
        }
    }
}

/// An authenticated tenant. `tenant_id` is the authority for every tenant-scoped operation.
pub struct TenantPrincipal {
    pub tenant_id: String,
}

#[axum::async_trait]
impl FromRequestParts<AppState> for TenantPrincipal {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, Error> {
        let token = bearer(parts)?;
        match service::authenticate_tenant(&st.pool, token).await? {
            Some(tenant_id) => Ok(TenantPrincipal { tenant_id }),
            None => Err(Error::Unauthorized),
        }
    }
}
