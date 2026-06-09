//! The credential service — the load-bearing logic.
//!
//! * ONE refresh function (`refresh_locked`), used by both the fetch path (just-in-time)
//!   and the worker (proactive). No second copy to drift.
//! * Row-level locking: refresh happens inside a transaction that took `SELECT … FOR
//!   UPDATE` on the row, so concurrent fetchers serialise instead of stampeding the
//!   provider.

use sqlx::Transaction;

use crate::db::{Db, Pool, LOCK_FOR_UPDATE, NOW};
use time::{Duration, OffsetDateTime};

use crate::config::Config;
use crate::crypto::secret::{ExposeSecret, SecretString};
use crate::crypto::Keyring;
use crate::error::Error;
use crate::http::transport::TokenTransport;
use crate::models::{aad_for, ConnStatus, Connection};
use crate::oauth::{self, OAuthFailure, TokenResult};
use crate::providers::{AuthType, ProviderSpec};
use crate::state::{self, StateClaims};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore;

const COLS: &str = "id, tenant_id, provider, external_user_id, account_key, \
    enc_access_token, enc_refresh_token, token_type, scopes, expires_at, status, \
    refresh_attempts, last_refresh_at, last_error, instance, created_at, updated_at";

pub struct AccessToken {
    pub access_token: SecretString,
    pub token_type: String,
    pub expires_at: Option<OffsetDateTime>,
    pub scopes: Vec<String>,
    /// Per-connection instance JSON for tenant-scoped providers (e.g. the Workday host/
    /// tenant), so the caller can build the API base. `None` for ordinary providers.
    pub instance: Option<String>,
}

/// The natural key of a connection, passed as one value to keep call sites tidy.
#[derive(Clone, Copy)]
pub struct Ident<'a> {
    pub tenant_id: &'a str,
    pub external_user_id: &'a str,
    pub account_key: &'a str,
}

fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// A 256-bit random, URL-safe state nonce — the unguessable handle that ties a signed
/// `state` to its single-use server-side flow row.
fn nonce() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn connect_failure(f: OAuthFailure) -> Error {
    tracing::warn!(message = %f.message, "oauth exchange failed");
    Error::Upstream
}

// --------------------------------------------------------------------------- //
// Tenants
// --------------------------------------------------------------------------- //
/// A newly created tenant. `api_key` is the one and only time the plaintext key is
/// available — only its hash is persisted — so the caller must return it to the operator now.
pub struct NewTenant {
    pub id: String,
    pub name: String,
    pub api_key: SecretString,
}

pub async fn create_tenant(pool: &Pool, name: &str) -> Result<NewTenant, Error> {
    let id = new_id();
    let api_key = crate::http::auth::generate_api_key();
    let api_key_hash = crate::http::auth::token_hash(api_key.expose_secret());
    sqlx::query("INSERT INTO tenants (id, name, api_key_hash) VALUES ($1, $2, $3)")
        .bind(&id)
        .bind(name)
        .bind(&api_key_hash)
        .execute(pool)
        .await?;
    Ok(NewTenant {
        id,
        name: name.to_string(),
        api_key,
    })
}

/// Resolve a presented API key to its tenant id, or `None` if no tenant owns it. The key
/// is matched by hash via a unique index — the raw secret is never compared or stored.
pub async fn authenticate_tenant(pool: &Pool, presented: &str) -> Result<Option<String>, Error> {
    let hash = crate::http::auth::token_hash(presented);
    let row: Option<(String,)> = sqlx::query_as("SELECT id FROM tenants WHERE api_key_hash = $1")
        .bind(&hash)
        .fetch_optional(pool)
        .await?;
    Ok(row.map(|r| r.0))
}

async fn tenant_exists(pool: &Pool, id: &str) -> Result<bool, Error> {
    let row: Option<(String,)> = sqlx::query_as("SELECT id FROM tenants WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?;
    Ok(row.is_some())
}

// --------------------------------------------------------------------------- //
// Authorization
// --------------------------------------------------------------------------- //
/// A started authorization flow. `authorize_url` is handed to the end user; `state` is
/// the signed CSRF token embedded in it (returned separately so a caller could also bind
/// it to a browser cookie for stricter checking).
pub struct Authorization {
    pub authorize_url: String,
    pub state: String,
}

/// The flow row claimed (single-use) at the callback. Identity is read back from storage
/// — the authoritative copy written at authorize time — rather than trusted from the wire.
#[derive(sqlx::FromRow)]
struct ClaimedFlow {
    tenant_id: String,
    external_user_id: String,
    account_key: String,
    pkce_verifier: Option<String>,
    instance: Option<String>,
}

/// Begin an OAuth2 authorization. The identity is supplied by the **authenticated tenant**,
/// never the wire. A single-use flow row is written carrying a fresh, encrypted PKCE
/// verifier (when the provider uses PKCE), keyed by the signed-state nonce.
pub async fn start_authorization(
    pool: &Pool,
    keyring: &Keyring,
    cfg: &Config,
    spec: &ProviderSpec,
    id: Ident<'_>,
    scopes: &[String],
    instance_json: Option<&str>,
) -> Result<Authorization, Error> {
    if spec.auth_type != AuthType::OAuth2 {
        return Err(Error::BadProvider);
    }
    let client_id = spec.client_id().ok_or(Error::NotConfigured)?;
    if spec.client_secret().is_none() {
        return Err(Error::NotConfigured);
    }
    if !tenant_exists(pool, id.tenant_id).await? {
        return Err(Error::UnknownTenant);
    }

    // For tenant-scoped providers, validate the caller's instance and resolve the templated
    // authorize URL now; the normalized instance JSON is stored on the flow so the callback
    // (and later refreshes) reconstruct the same per-customer endpoints.
    let (spec_cow, instance_store) = crate::providers::resolve_instance(spec, instance_json)?;
    let spec = spec_cow.as_ref();

    let now = OffsetDateTime::now_utc();
    let nonce = nonce();
    let claims = StateClaims {
        p: spec.id.clone(),
        n: nonce.clone(),
        exp: now.unix_timestamp() + cfg.state_ttl_seconds,
    };
    let st = state::issue(&cfg.state_secret, &claims);

    // Fresh, independent PKCE verifier — stored encrypted, never derived from the state.
    let (pkce_challenge, enc_verifier) = if spec.uses_pkce {
        let verifier = crate::oauth::pkce::generate_verifier();
        let challenge = crate::oauth::pkce::challenge_s256(verifier.expose_secret());
        let aad = aad_for(id.tenant_id, &spec.id, id.external_user_id, id.account_key);
        (Some(challenge), Some(keyring.encrypt(&verifier, &aad)?))
    } else {
        (None, None)
    };

    let expires_at = now + Duration::seconds(cfg.state_ttl_seconds);
    sqlx::query(
        "INSERT INTO oauth_flows \
         (nonce, provider, tenant_id, external_user_id, account_key, pkce_verifier, expires_at, instance) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(&nonce)
    .bind(&spec.id)
    .bind(id.tenant_id)
    .bind(id.external_user_id)
    .bind(id.account_key)
    .bind(enc_verifier)
    .bind(expires_at)
    .bind(&instance_store)
    .execute(pool)
    .await?;

    let authorize_url = oauth::build_authorize_url(
        spec,
        &client_id,
        &cfg.redirect_uri(&spec.id),
        &st,
        scopes,
        pkce_challenge.as_deref(),
    );
    Ok(Authorization {
        authorize_url,
        state: st,
    })
}

pub async fn complete_authorization(
    pool: &Pool,
    transport: &dyn TokenTransport,
    keyring: &Keyring,
    cfg: &Config,
    spec: &ProviderSpec,
    code: &str,
    state_token: &str,
) -> Result<Connection, Error> {
    let now = OffsetDateTime::now_utc();
    let claims = state::verify(&cfg.state_secret, state_token, now.unix_timestamp())?;
    if claims.p != spec.id {
        return Err(Error::BadState);
    }

    // Claim the flow exactly once. The atomic guarded UPDATE is what makes an intercepted
    // (code, state) pair non-replayable: the second attempt finds consumed_at already set
    // (or the row expired) and gets nothing back.
    let flow = claim_flow(pool, &claims.n, now)
        .await?
        .ok_or(Error::BadState)?;

    let client_id = spec.client_id().ok_or(Error::NotConfigured)?;
    let client_secret = spec.client_secret().ok_or(Error::NotConfigured)?;

    // Reconstruct the per-customer endpoints from the instance stored at authorize time
    // (re-validated, since it determines where the secret + code are POSTed).
    let (spec_cow, _) = crate::providers::resolve_instance(spec, flow.instance.as_deref())?;
    let spec = spec_cow.as_ref();

    // Recover the per-flow PKCE verifier from storage (identity-bound AAD).
    let pkce_verifier = match &flow.pkce_verifier {
        Some(enc) => {
            let aad = aad_for(
                &flow.tenant_id,
                &spec.id,
                &flow.external_user_id,
                &flow.account_key,
            );
            Some(keyring.decrypt(enc, &aad)?)
        }
        None => None,
    };

    let result = oauth::exchange_code(
        transport,
        spec,
        &client_id,
        &client_secret,
        code,
        &cfg.redirect_uri(&spec.id),
        pkce_verifier.as_ref().map(|v| v.expose_secret().as_str()),
    )
    .await
    .map_err(connect_failure)?;

    upsert_from_token(
        pool,
        keyring,
        spec,
        &flow.tenant_id,
        &flow.external_user_id,
        &flow.account_key,
        result,
        flow.instance,
    )
    .await
}

/// Atomically consume a pending flow: mark it consumed only if it is still unconsumed and
/// unexpired, returning its stored identity + verifier. Returns `None` on replay/expiry/
/// unknown nonce — the caller maps that to `BadState`.
async fn claim_flow(
    pool: &Pool,
    nonce: &str,
    now: OffsetDateTime,
) -> Result<Option<ClaimedFlow>, Error> {
    let row = sqlx::query_as::<_, ClaimedFlow>(&format!(
        "UPDATE oauth_flows SET consumed_at = {NOW} \
         WHERE nonce = $1 AND consumed_at IS NULL AND expires_at > $2 \
         RETURNING tenant_id, external_user_id, account_key, pkce_verifier, instance"
    ))
    .bind(nonce)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Delete flows past their expiry (consumed or abandoned). Run periodically by the worker.
pub async fn purge_expired_flows(pool: &Pool) -> Result<u64, Error> {
    let now = OffsetDateTime::now_utc();
    let res = sqlx::query("DELETE FROM oauth_flows WHERE expires_at < $1")
        .bind(now)
        .execute(pool)
        .await?;
    Ok(res.rows_affected())
}

pub async fn store_api_key(
    pool: &Pool,
    keyring: &Keyring,
    spec: &ProviderSpec,
    tenant_id: &str,
    external_user_id: &str,
    api_key: &SecretString,
    account_key: &str,
) -> Result<Connection, Error> {
    if spec.auth_type != AuthType::ApiKey {
        return Err(Error::BadProvider);
    }
    if !tenant_exists(pool, tenant_id).await? {
        return Err(Error::UnknownTenant);
    }
    let aad = aad_for(tenant_id, &spec.id, external_user_id, account_key);
    let enc = keyring.encrypt(api_key, &aad)?;
    let id = new_id();
    let row = sqlx::query_as::<_, Connection>(&format!(
        "INSERT INTO connections \
         (id, tenant_id, provider, external_user_id, account_key, enc_access_token, \
          enc_refresh_token, token_type, scopes, expires_at, status, refresh_attempts, instance) \
         VALUES ($1,$2,$3,$4,$5,$6,NULL,'ApiKey','',NULL,'active',0,NULL) \
         ON CONFLICT (tenant_id, provider, external_user_id, account_key) DO UPDATE SET \
           enc_access_token = EXCLUDED.enc_access_token, enc_refresh_token = NULL, \
           token_type = 'ApiKey', expires_at = NULL, status = 'active', \
           refresh_attempts = 0, last_error = NULL, updated_at = {NOW} \
         RETURNING {COLS}"
    ))
    .bind(id)
    .bind(tenant_id)
    .bind(&spec.id)
    .bind(external_user_id)
    .bind(account_key)
    .bind(enc)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

#[allow(clippy::too_many_arguments)]
async fn upsert_from_token(
    pool: &Pool,
    keyring: &Keyring,
    spec: &ProviderSpec,
    tenant_id: &str,
    external_user_id: &str,
    account_key: &str,
    result: TokenResult,
    instance: Option<String>,
) -> Result<Connection, Error> {
    let aad = aad_for(tenant_id, &spec.id, external_user_id, account_key);
    let enc_access = keyring.encrypt(&result.access_token, &aad)?;
    let enc_refresh = result
        .refresh_token
        .as_ref()
        .map(|rt| keyring.encrypt(rt, &aad))
        .transpose()?;
    let expires_at = result
        .expires_in
        .map(|s| OffsetDateTime::now_utc() + Duration::seconds(s));
    let scopes = result
        .scope
        .map(|s| s.replace(',', " "))
        .unwrap_or_else(|| spec.default_scopes.join(&spec.scope_separator));
    let id = new_id();

    let row = sqlx::query_as::<_, Connection>(&format!(
        "INSERT INTO connections \
         (id, tenant_id, provider, external_user_id, account_key, enc_access_token, \
          enc_refresh_token, token_type, scopes, expires_at, status, refresh_attempts, instance) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,'Bearer',$8,$9,'active',0,$10) \
         ON CONFLICT (tenant_id, provider, external_user_id, account_key) DO UPDATE SET \
           enc_access_token = EXCLUDED.enc_access_token, \
           enc_refresh_token = COALESCE(EXCLUDED.enc_refresh_token, connections.enc_refresh_token), \
           token_type = EXCLUDED.token_type, scopes = EXCLUDED.scopes, \
           expires_at = EXCLUDED.expires_at, status = 'active', refresh_attempts = 0, \
           last_error = NULL, instance = EXCLUDED.instance, updated_at = {NOW} \
         RETURNING {COLS}"
    ))
    .bind(id)
    .bind(tenant_id)
    .bind(&spec.id)
    .bind(external_user_id)
    .bind(account_key)
    .bind(enc_access)
    .bind(enc_refresh)
    .bind(scopes)
    .bind(expires_at)
    .bind(instance)
    .fetch_one(pool)
    .await?;
    Ok(row)
}

// --------------------------------------------------------------------------- //
// The money path: return a valid access token, refreshing if needed.
// --------------------------------------------------------------------------- //
pub async fn get_access_token(
    pool: &Pool,
    transport: &dyn TokenTransport,
    keyring: &Keyring,
    cfg: &Config,
    spec: &ProviderSpec,
    id: Ident<'_>,
) -> Result<AccessToken, Error> {
    let mut tx = pool.begin().await?;
    let mut conn = lock_connection(
        &mut tx,
        id.tenant_id,
        &spec.id,
        id.external_user_id,
        id.account_key,
    )
    .await?
    .ok_or(Error::NotConnected)?;

    let now = OffsetDateTime::now_utc();
    if spec.auth_type == AuthType::OAuth2 && needs_refresh(&conn, cfg, now) {
        refresh_locked(&mut tx, transport, keyring, cfg, spec, &mut conn).await?;
    }
    tx.commit().await?;

    match conn.status_enum() {
        ConnStatus::NeedsReauth => return Err(Error::NeedsReauth),
        ConnStatus::Error => return Err(Error::RefreshUnavailable),
        ConnStatus::Active => {}
    }

    let aad = conn.aad();
    let access = keyring.decrypt(&conn.enc_access_token, &aad)?;
    Ok(AccessToken {
        access_token: access,
        token_type: conn.token_type.clone(),
        expires_at: conn.expires_at,
        scopes: conn.scopes_vec(),
        instance: conn.instance.clone(),
    })
}

// --------------------------------------------------------------------------- //
// Refresh — single source of truth (fetch + worker).
// --------------------------------------------------------------------------- //
fn needs_refresh(conn: &Connection, cfg: &Config, now: OffsetDateTime) -> bool {
    if conn.status_enum() == ConnStatus::NeedsReauth {
        return false;
    }
    match conn.expires_at {
        None => false,
        Some(exp) => now >= exp - Duration::seconds(cfg.refresh_skew_seconds),
    }
}

async fn refresh_locked(
    tx: &mut Transaction<'_, Db>,
    transport: &dyn TokenTransport,
    keyring: &Keyring,
    cfg: &Config,
    spec: &ProviderSpec,
    conn: &mut Connection,
) -> Result<(), Error> {
    let Some(enc_rt) = conn.enc_refresh_token.clone() else {
        conn.status = ConnStatus::NeedsReauth.as_str().to_string();
        conn.last_error = Some("no refresh token on file".to_string());
        return persist_refresh(tx, conn).await;
    };
    // Reconstruct the per-customer token endpoint for tenant-scoped providers from the
    // instance stored on the connection (no-op for ordinary providers).
    let (spec_cow, _) = crate::providers::resolve_instance(spec, conn.instance.as_deref())?;
    let spec = spec_cow.as_ref();
    let aad = conn.aad();
    let refresh_token = keyring.decrypt(&enc_rt, &aad)?;
    let client_id = spec.client_id().ok_or(Error::NotConfigured)?;
    let client_secret = spec.client_secret().ok_or(Error::NotConfigured)?;

    match oauth::refresh(transport, spec, &client_id, &client_secret, &refresh_token).await {
        Ok(result) => apply_token(keyring, spec, conn, result)?,
        Err(f) if f.needs_reauth => {
            conn.status = ConnStatus::NeedsReauth.as_str().to_string();
            conn.last_error = Some(f.message);
            tracing::info!(id = %conn.id, "connection needs reauth");
        }
        Err(f) => {
            conn.refresh_attempts += 1;
            conn.last_error = Some(f.message);
            if !(f.retryable && conn.refresh_attempts < cfg.refresh_max_attempts) {
                conn.status = ConnStatus::Error.as_str().to_string();
                tracing::error!(id = %conn.id, "refresh permanently failed");
            } else {
                tracing::warn!(id = %conn.id, attempt = conn.refresh_attempts, "transient refresh failure");
            }
        }
    }
    persist_refresh(tx, conn).await
}

fn apply_token(
    keyring: &Keyring,
    spec: &ProviderSpec,
    conn: &mut Connection,
    result: TokenResult,
) -> Result<(), Error> {
    let aad = conn.aad();
    conn.enc_access_token = keyring.encrypt(&result.access_token, &aad)?;
    // Only overwrite the refresh token if the provider rotated it (and gave one).
    if let Some(rt) = &result.refresh_token {
        if spec.refresh_token_rotates || conn.enc_refresh_token.is_none() {
            conn.enc_refresh_token = Some(keyring.encrypt(rt, &aad)?);
        }
    }
    if let Some(s) = result.expires_in {
        conn.expires_at = Some(OffsetDateTime::now_utc() + Duration::seconds(s));
    }
    if let Some(scope) = result.scope {
        conn.scopes = scope.replace(',', " ");
    }
    conn.status = ConnStatus::Active.as_str().to_string();
    conn.refresh_attempts = 0;
    conn.last_error = None;
    conn.last_refresh_at = Some(OffsetDateTime::now_utc());
    Ok(())
}

async fn persist_refresh(tx: &mut Transaction<'_, Db>, conn: &Connection) -> Result<(), Error> {
    sqlx::query(&format!(
        "UPDATE connections SET enc_access_token=$1, enc_refresh_token=$2, expires_at=$3, \
         scopes=$4, status=$5, refresh_attempts=$6, last_refresh_at=$7, last_error=$8, \
         updated_at={NOW} WHERE id=$9",
    ))
    .bind(&conn.enc_access_token)
    .bind(&conn.enc_refresh_token)
    .bind(conn.expires_at)
    .bind(&conn.scopes)
    .bind(&conn.status)
    .bind(conn.refresh_attempts)
    .bind(conn.last_refresh_at)
    .bind(&conn.last_error)
    .bind(&conn.id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn lock_connection(
    tx: &mut Transaction<'_, Db>,
    tenant_id: &str,
    provider: &str,
    external_user_id: &str,
    account_key: &str,
) -> Result<Option<Connection>, Error> {
    let row = sqlx::query_as::<_, Connection>(&format!(
        "SELECT {COLS} FROM connections WHERE tenant_id=$1 AND provider=$2 \
         AND external_user_id=$3 AND account_key=$4{LOCK_FOR_UPDATE}"
    ))
    .bind(tenant_id)
    .bind(provider)
    .bind(external_user_id)
    .bind(account_key)
    .fetch_optional(&mut **tx)
    .await?;
    Ok(row)
}

// --------------------------------------------------------------------------- //
// Worker support + management
// --------------------------------------------------------------------------- //
pub async fn due_for_refresh(pool: &Pool, cfg: &Config, limit: i64) -> Result<Vec<String>, Error> {
    let horizon = OffsetDateTime::now_utc() + Duration::seconds(cfg.refresh_horizon_seconds);
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT id FROM connections WHERE status='active' AND expires_at IS NOT NULL \
         AND expires_at <= $1 AND enc_refresh_token IS NOT NULL LIMIT $2",
    )
    .bind(horizon)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

pub async fn refresh_one(
    pool: &Pool,
    transport: &dyn TokenTransport,
    keyring: &Keyring,
    cfg: &Config,
    id: &str,
) -> Result<Option<String>, Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query_as::<_, Connection>(&format!(
        "SELECT {COLS} FROM connections WHERE id=$1{LOCK_FOR_UPDATE}"
    ))
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(mut conn) = row else {
        return Ok(None);
    };
    let now = OffsetDateTime::now_utc();
    if needs_refresh(&conn, cfg, now) {
        let spec = crate::providers::get(&conn.provider).ok_or(Error::UnknownProvider)?;
        refresh_locked(&mut tx, transport, keyring, cfg, spec, &mut conn).await?;
    }
    tx.commit().await?;
    Ok(Some(conn.status))
}

pub async fn list_connections(pool: &Pool, tenant_id: &str) -> Result<Vec<Connection>, Error> {
    let rows = sqlx::query_as::<_, Connection>(&format!(
        "SELECT {COLS} FROM connections WHERE tenant_id=$1 ORDER BY provider, account_key"
    ))
    .bind(tenant_id)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Re-encrypt every connection whose blobs predate the active key version.
/// Safe to run repeatedly; only rewrites rows that need it.
pub async fn rotate_keys(pool: &Pool, keyring: &Keyring) -> Result<u64, Error> {
    let rows = sqlx::query_as::<_, Connection>(&format!("SELECT {COLS} FROM connections"))
        .fetch_all(pool)
        .await?;
    let active = keyring.active_version();
    let mut rotated = 0u64;
    for c in rows {
        let access_stale =
            crate::crypto::key_version_of(&c.enc_access_token).as_deref() != Some(active);
        let refresh_stale = c
            .enc_refresh_token
            .as_ref()
            .is_some_and(|r| crate::crypto::key_version_of(r).as_deref() != Some(active));
        if !access_stale && !refresh_stale {
            continue;
        }
        let aad = c.aad();
        let access = keyring.decrypt(&c.enc_access_token, &aad)?;
        let enc_access = keyring.encrypt(&access, &aad)?;
        let enc_refresh = match &c.enc_refresh_token {
            Some(r) => {
                let rt = keyring.decrypt(r, &aad)?;
                Some(keyring.encrypt(&rt, &aad)?)
            }
            None => None,
        };
        sqlx::query(&format!("UPDATE connections SET enc_access_token=$1, enc_refresh_token=$2, updated_at={NOW} WHERE id=$3"))
            .bind(enc_access)
            .bind(enc_refresh)
            .bind(&c.id)
            .execute(pool)
            .await?;
        rotated += 1;
    }
    Ok(rotated)
}

pub async fn delete_connection(pool: &Pool, tenant_id: &str, id: &str) -> Result<bool, Error> {
    let res = sqlx::query("DELETE FROM connections WHERE id=$1 AND tenant_id=$2")
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
    Ok(res.rows_affected() > 0)
}

/// Fetch a connection by id **scoped to its owning tenant** — the single chokepoint for
/// id-addressed reads, so a connection id leaked or guessed by one tenant never resolves
/// another tenant's row.
async fn fetch_by_id(pool: &Pool, tenant_id: &str, id: &str) -> Result<Option<Connection>, Error> {
    let row = sqlx::query_as::<_, Connection>(&format!(
        "SELECT {COLS} FROM connections WHERE id=$1 AND tenant_id=$2"
    ))
    .bind(id)
    .bind(tenant_id)
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Disconnect: revoke the token upstream (best effort, for OAuth providers that expose
/// a revoke endpoint) and then delete the local connection. Revocation failure does not
/// block deletion — the local credential is always removed. Tenant-scoped throughout.
pub async fn disconnect(
    pool: &Pool,
    transport: &dyn TokenTransport,
    keyring: &Keyring,
    tenant_id: &str,
    id: &str,
) -> Result<bool, Error> {
    let Some(conn) = fetch_by_id(pool, tenant_id, id).await? else {
        return Ok(false);
    };
    if let Some(spec) = crate::providers::get(&conn.provider) {
        // Resolve the per-customer revoke endpoint for tenant-scoped providers; if the
        // stored instance is missing/invalid, skip the upstream revoke and still delete.
        if let Ok((spec_cow, _)) =
            crate::providers::resolve_instance(spec, conn.instance.as_deref())
        {
            let spec = spec_cow.as_ref();
            if spec.auth_type == AuthType::OAuth2 {
                if let (Some(client_id), Some(client_secret)) =
                    (spec.client_id(), spec.client_secret())
                {
                    let aad = conn.aad();
                    if let Ok(access) = keyring.decrypt(&conn.enc_access_token, &aad) {
                        if let Err(f) =
                            oauth::revoke(transport, spec, &client_id, &client_secret, &access)
                                .await
                        {
                            tracing::warn!(id = %conn.id, message = %f.message, "upstream revoke failed; deleting locally anyway");
                        }
                    }
                }
            }
        }
    }
    delete_connection(pool, tenant_id, id).await
}
