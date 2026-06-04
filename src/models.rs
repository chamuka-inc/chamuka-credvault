//! Domain model. A `Connection` is the live link the product is built around:
//! (tenant, provider, end-user, account) → encrypted tokens + lifecycle state.

use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnStatus {
    Active,
    NeedsReauth,
    Error,
}

impl ConnStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnStatus::Active => "active",
            ConnStatus::NeedsReauth => "needs_reauth",
            ConnStatus::Error => "error",
        }
    }
    pub fn from_db(s: &str) -> Self {
        match s {
            "needs_reauth" => ConnStatus::NeedsReauth,
            "error" => ConnStatus::Error,
            _ => ConnStatus::Active,
        }
    }
}

#[derive(Clone, sqlx::FromRow)]
pub struct Connection {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub external_user_id: String,
    pub account_key: String,
    pub enc_access_token: String,
    pub enc_refresh_token: Option<String>,
    pub token_type: String,
    pub scopes: String,
    pub expires_at: Option<OffsetDateTime>,
    pub status: String,
    pub refresh_attempts: i32,
    pub last_refresh_at: Option<OffsetDateTime>,
    pub last_error: Option<String>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

impl Connection {
    /// Identity bytes bound into every ciphertext as AAD.
    pub fn aad(&self) -> Vec<u8> {
        aad_for(
            &self.tenant_id,
            &self.provider,
            &self.external_user_id,
            &self.account_key,
        )
    }

    pub fn status_enum(&self) -> ConnStatus {
        ConnStatus::from_db(&self.status)
    }

    pub fn scopes_vec(&self) -> Vec<String> {
        self.scopes.split_whitespace().map(String::from).collect()
    }

    /// Safe to serialize over the API — contains no secrets.
    pub fn public(&self) -> PublicConnection {
        PublicConnection {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            provider: self.provider.clone(),
            external_user_id: self.external_user_id.clone(),
            account_key: self.account_key.clone(),
            status: self.status.clone(),
            scopes: self.scopes_vec(),
            expires_at: self.expires_at.and_then(|d| d.format(&Rfc3339).ok()),
            last_refresh_at: self.last_refresh_at.and_then(|d| d.format(&Rfc3339).ok()),
        }
    }
}

/// Identity bytes bound into every ciphertext as AAD.
///
/// Encoding is injective: a version byte followed by each field as a 4-byte big-endian
/// length prefix and its raw bytes. Unlike a delimiter-joined string (`a:b:c`), no choice
/// of field values can produce the same byte sequence as a different tuple, so a blob can
/// never be relocated to a row whose identity merely collides under a separator boundary
/// (e.g. `("a:b","c")` vs `("a","b:c")`).
pub fn aad_for(tenant: &str, provider: &str, user: &str, account: &str) -> Vec<u8> {
    const AAD_V1: u8 = 1;
    let fields = [tenant, provider, user, account];
    let mut out = Vec::with_capacity(1 + fields.iter().map(|f| 4 + f.len()).sum::<usize>());
    out.push(AAD_V1);
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f.as_bytes());
    }
    out
}

// Manual, redacting Debug: the encrypted-token columns and the identity tuple are kept
// out of any formatted output (logs, panics) by construction, not by discipline.
impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("status", &self.status)
            .field("expires_at", &self.expires_at)
            .field("enc_access_token", &"[REDACTED]")
            .field(
                "enc_refresh_token",
                &self.enc_refresh_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Serialize)]
pub struct PublicConnection {
    pub id: String,
    pub tenant_id: String,
    pub provider: String,
    pub external_user_id: String,
    pub account_key: String,
    pub status: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<String>,
    pub last_refresh_at: Option<String>,
}
