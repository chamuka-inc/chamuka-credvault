//! Full lifecycle against an in-process SQLite. Runs only under `--features sqlite`,
//! with no external database, so the complete service path — OAuth code exchange,
//! encrypted upsert, the just-in-time refresh, cross-tenant isolation, the API-key
//! path, and management — is exercised locally on every `cargo test --features sqlite`.
//!
//! SQLite serialises writers itself, so it cannot reproduce Postgres's row-level
//! `FOR UPDATE` concurrency semantics; that specific guarantee is covered by the
//! Postgres integration job in CI. Everything else is identical.
#![cfg(feature = "sqlite")]

mod common;

use credvault::config::Config;
use credvault::crypto::{self, Keyring};
use credvault::providers;
use credvault::secret::{secret, ExposeSecret};
use credvault::service::{self, Ident};
use credvault::transport::{FnTransport, TransportError};

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

type R = Result<(u16, serde_json::Value), TransportError>;

// SQLite-dialect schema: TEXT ids, RFC3339/UTC timestamps that round-trip into
// OffsetDateTime, the same unique identity index and partial "due" index as Postgres.
const SCHEMA: &str = r#"
CREATE TABLE tenants (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    api_key_hash  TEXT NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE UNIQUE INDEX uq_tenant_api_key ON tenants (api_key_hash);
CREATE TABLE oauth_flows (
    nonce             TEXT PRIMARY KEY,
    provider          TEXT NOT NULL,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_user_id  TEXT NOT NULL,
    account_key       TEXT NOT NULL DEFAULT 'default',
    pkce_verifier     TEXT,
    expires_at        TEXT NOT NULL,
    consumed_at       TEXT,
    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE INDEX ix_oauth_flows_expiry ON oauth_flows (expires_at);
CREATE TABLE connections (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    external_user_id    TEXT NOT NULL,
    account_key         TEXT NOT NULL DEFAULT 'default',
    enc_access_token    TEXT NOT NULL,
    enc_refresh_token   TEXT,
    token_type          TEXT NOT NULL DEFAULT 'Bearer',
    scopes              TEXT NOT NULL DEFAULT '',
    expires_at          TEXT,
    status              TEXT NOT NULL DEFAULT 'active',
    refresh_attempts    INTEGER NOT NULL DEFAULT 0,
    last_refresh_at     TEXT,
    last_error          TEXT,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
CREATE UNIQUE INDEX uq_connection_identity
    ON connections (tenant_id, provider, external_user_id, account_key);
CREATE INDEX ix_connections_due
    ON connections (status, expires_at) WHERE enc_refresh_token IS NOT NULL;
CREATE INDEX ix_connections_tenant ON connections (tenant_id);
"#;

fn test_config(keys: &str) -> Config {
    Config {
        database_url: "sqlite::memory:".to_string(),
        keys_json: keys.to_string(),
        active_key: "1".to_string(),
        state_secret: secret("state-secret"),
        state_ttl_seconds: 600,
        public_base_url: "http://localhost:8000".to_string(),
        refresh_skew_seconds: 120,
        refresh_horizon_seconds: 600,
        worker_interval_seconds: 60,
        refresh_max_attempts: 5,
        admin_token: secret("admin-token"),
        bind_addr: "0.0.0.0:8000".to_string(),
        http_timeout_seconds: 15,
        require_https: false,
        rate_limit_per_minute: 0,
        max_body_bytes: 64 * 1024,
    }
}

async fn memory_pool() -> sqlx::SqlitePool {
    // One shared in-memory connection (max 1) keeps the schema visible across calls;
    // the test is sequential so a single connection is sufficient.
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("open sqlite");
    for stmt in SCHEMA.split(';').filter(|s| !s.trim().is_empty()) {
        sqlx::query(stmt).execute(&pool).await.expect("schema");
    }
    pool
}

#[tokio::test]
async fn full_lifecycle_sqlite() {
    common::default_plugins();
    std::env::set_var("GOOGLE_CLIENT_ID", "test-client");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "test-secret");

    let keys = format!(r#"{{"1":"{}"}}"#, crypto::generate_key());
    let cfg = test_config(&keys);
    let keyring = Keyring::from_config(&cfg.keys_json, &cfg.active_key).unwrap();
    let pool = memory_pool().await;

    // authorization_code -> short-lived token w/ refresh; refresh_token -> fresh token.
    let transport = FnTransport(|_url: &str, form: &[(String, String)]| -> R {
        let is_refresh = form
            .iter()
            .any(|(k, v)| k == "grant_type" && v == "refresh_token");
        if is_refresh {
            Ok((
                200,
                serde_json::json!({"access_token": "refreshed-token", "expires_in": 3600}),
            ))
        } else {
            Ok((
                200,
                serde_json::json!({
                    "access_token": "initial-token",
                    "refresh_token": "rt-1",
                    "expires_in": 0
                }),
            ))
        }
    });

    let tenant_id = service::create_tenant(&pool, "Acme").await.unwrap().id;
    let google = providers::get("google").unwrap();

    // Drive the real entry point: start mints the single-use flow + state, the callback
    // consumes it.
    let auth = service::start_authorization(
        &pool,
        &keyring,
        &cfg,
        google,
        Ident {
            tenant_id: &tenant_id,
            external_user_id: "user-1",
            account_key: "default",
        },
        &[],
    )
    .await
    .expect("start");
    let conn = service::complete_authorization(
        &pool,
        &transport,
        &keyring,
        &cfg,
        google,
        "auth-code",
        &auth.state,
    )
    .await
    .expect("connect");
    assert_eq!(conn.status, "active");

    // Single-use: replaying the same state must now fail.
    assert!(
        service::complete_authorization(
            &pool,
            &transport,
            &keyring,
            &cfg,
            google,
            "auth-code",
            &auth.state
        )
        .await
        .is_err(),
        "state replay must be rejected"
    );

    // expires_in 0 => due immediately => fetch must refresh before returning.
    let id = Ident {
        tenant_id: &tenant_id,
        external_user_id: "user-1",
        account_key: "default",
    };
    let tok = service::get_access_token(&pool, &transport, &keyring, &cfg, google, id)
        .await
        .expect("fetch");
    assert_eq!(tok.access_token.expose_secret(), "refreshed-token");

    // Cross-tenant isolation: same user/account under another tenant must not resolve.
    let other = Ident {
        tenant_id: "ghost-tenant",
        external_user_id: "user-1",
        account_key: "default",
    };
    assert!(
        service::get_access_token(&pool, &transport, &keyring, &cfg, google, other)
            .await
            .is_err()
    );

    // API-key provider: stored and returned verbatim, no refresh.
    let stripe = providers::get("stripe").unwrap();
    service::store_api_key(
        &pool,
        &keyring,
        stripe,
        &tenant_id,
        "user-1",
        &secret("sk_live_x"),
        "default",
    )
    .await
    .unwrap();
    let sid = Ident {
        tenant_id: &tenant_id,
        external_user_id: "user-1",
        account_key: "default",
    };
    let skey = service::get_access_token(&pool, &transport, &keyring, &cfg, stripe, sid)
        .await
        .unwrap();
    assert_eq!(skey.access_token.expose_secret(), "sk_live_x");

    // Management: list reflects both connections; delete removes one.
    let list = service::list_connections(&pool, &tenant_id).await.unwrap();
    assert_eq!(list.len(), 2);
    assert!(service::delete_connection(&pool, &tenant_id, &conn.id)
        .await
        .unwrap());
    assert_eq!(
        service::list_connections(&pool, &tenant_id)
            .await
            .unwrap()
            .len(),
        1
    );

    // Cross-tenant delete must not touch another tenant's row.
    let other = service::create_tenant(&pool, "Other").await.unwrap().id;
    assert!(
        !service::delete_connection(&pool, &other, &sid_conn_id(&pool, &tenant_id).await)
            .await
            .unwrap(),
        "deleting another tenant's connection must be a no-op"
    );
}

// Helper: the id of the surviving (stripe) connection for `tenant_id`.
async fn sid_conn_id(pool: &sqlx::SqlitePool, tenant_id: &str) -> String {
    service::list_connections(pool, tenant_id).await.unwrap()[0]
        .id
        .clone()
}

#[tokio::test]
async fn pkce_connect_then_disconnect_revokes_upstream() {
    // X/Twitter is a default OAuth2 provider plugin that requires PKCE and exposes a revoke
    // endpoint — exercises the PKCE code path on connect and revoke-on-disconnect.
    common::default_plugins();
    std::env::set_var("X_CLIENT_ID", "x-client");
    std::env::set_var("X_CLIENT_SECRET", "x-secret");

    let keys = format!(r#"{{"1":"{}"}}"#, crypto::generate_key());
    let cfg = test_config(&keys);
    let keyring = Keyring::from_config(&cfg.keys_json, &cfg.active_key).unwrap();
    let pool = memory_pool().await;

    let revoked = Arc::new(Mutex::new(false));
    let saw_verifier = Arc::new(Mutex::new(false));
    let (rv, sv) = (revoked.clone(), saw_verifier.clone());
    let transport = FnTransport(move |url: &str, form: &[(String, String)]| -> R {
        if url.contains("revoke") {
            *rv.lock().unwrap() = true;
            return Ok((200, serde_json::Value::Null));
        }
        // Code-exchange: PKCE means the engine must include a code_verifier.
        if form.iter().any(|(k, _)| k == "code_verifier") {
            *sv.lock().unwrap() = true;
        }
        Ok((
            200,
            serde_json::json!({"access_token":"at","refresh_token":"rt","expires_in":3600}),
        ))
    });

    let tenant_id = service::create_tenant(&pool, "Acme").await.unwrap().id;
    let x = providers::get("x").unwrap();
    assert!(x.uses_pkce, "x must require PKCE");

    let auth = service::start_authorization(
        &pool,
        &keyring,
        &cfg,
        x,
        Ident {
            tenant_id: &tenant_id,
            external_user_id: "user-1",
            account_key: "default",
        },
        &[],
    )
    .await
    .expect("start");
    let conn =
        service::complete_authorization(&pool, &transport, &keyring, &cfg, x, "code", &auth.state)
            .await
            .expect("connect");

    assert!(
        *saw_verifier.lock().unwrap(),
        "exchange must send PKCE code_verifier"
    );

    // Disconnect must revoke upstream, then remove the local row.
    assert!(
        service::disconnect(&pool, &transport, &keyring, &tenant_id, &conn.id)
            .await
            .unwrap()
    );
    assert!(
        *revoked.lock().unwrap(),
        "disconnect must call the revoke endpoint"
    );
    assert!(service::list_connections(&pool, &tenant_id)
        .await
        .unwrap()
        .is_empty());
}
