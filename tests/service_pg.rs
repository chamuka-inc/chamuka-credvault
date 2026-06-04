//! Full lifecycle against a real Postgres. Gated on DATABASE_URL so the rest of the
//! suite runs anywhere; CI sets it. Exercises the locked just-in-time refresh path
//! and the API-key path end to end.
#![cfg(not(feature = "sqlite"))]

use credvault::config::Config;
use credvault::crypto::{self, Keyring};
use credvault::providers;
use credvault::secret::{secret, ExposeSecret};
use credvault::service::{self, Ident};
use credvault::transport::{FnTransport, TransportError};

type R = Result<(u16, serde_json::Value), TransportError>;

fn test_config(url: &str, keys: &str) -> Config {
    Config {
        database_url: url.to_string(),
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

#[tokio::test]
async fn full_lifecycle() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        eprintln!("SKIP full_lifecycle: DATABASE_URL not set");
        return;
    };

    // OAuth client creds the engine reads from env.
    std::env::set_var("GOOGLE_CLIENT_ID", "test-client");
    std::env::set_var("GOOGLE_CLIENT_SECRET", "test-secret");

    let keys = format!(r#"{{"1":"{}"}}"#, crypto::generate_key());
    let cfg = test_config(&url, &keys);
    let keyring = Keyring::from_config(&cfg.keys_json, &cfg.active_key).unwrap();

    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrate");
    sqlx::query("TRUNCATE connections, tenants CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    // Transport: authorization_code -> short-lived token w/ refresh; refresh -> new token.
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

    // Drive the real entry point: start mints the single-use flow + state; the callback
    // verifies and consumes it.
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

    // Single-use: replaying the same state must fail.
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

    // The token is due immediately (expires_in 0) -> fetch must refresh under the lock.
    let id = Ident {
        tenant_id: &tenant_id,
        external_user_id: "user-1",
        account_key: "default",
    };
    let tok = service::get_access_token(&pool, &transport, &keyring, &cfg, google, id)
        .await
        .expect("fetch");
    assert_eq!(tok.access_token.expose_secret(), "refreshed-token");

    // Cross-tenant isolation: same user key under a different tenant must not resolve.
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

    // API-key provider: store + retrieve verbatim, no refresh.
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

    // Management.
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
}
