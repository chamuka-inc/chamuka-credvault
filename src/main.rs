//! Binary entrypoint. One image, several processes selected by argument or
//! VAULT_PROCESS: `web`, `worker`, `migrate`, plus `gen-key` / `list-providers` /
//! `validate-plugins` (no DB) and `rotate-keys` (maintenance).

use std::sync::Arc;

use anyhow::Context;

use credvault::config::Config;
use credvault::crypto::{self, Keyring};
use credvault::transport::{ReqwestTransport, TokenTransport};
use credvault::{api, db, providers, service, worker, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();

    // Discover provider plugins from VAULT_PLUGIN_DIRS and validate now, so a malformed
    // manifest fails fast at startup rather than at first request. There are no built-in
    // providers: an unset/empty VAULT_PLUGIN_DIRS simply loads none.
    let plugins = providers::init_plugins().context("loading provider plugins")?;
    tracing::info!(
        plugins = plugins.len(),
        dirs = %std::env::var("VAULT_PLUGIN_DIRS").unwrap_or_default(),
        "provider plugins loaded"
    );

    let mode = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("VAULT_PROCESS").ok())
        .unwrap_or_else(|| "web".to_string());

    // Modes that need neither config nor a database.
    match mode.as_str() {
        "gen-key" => {
            println!("{}", crypto::generate_key());
            return Ok(());
        }
        "list-providers" => {
            for s in providers::registry() {
                let state = if s.is_configured() {
                    "configured"
                } else {
                    "unconfigured"
                };
                println!(
                    "{:14} {:8} {:12} {}",
                    s.id,
                    s.version,
                    state,
                    s.default_scopes.join(",")
                );
            }
            return Ok(());
        }
        "validate-plugins" => {
            // The eager init_plugins() above already validated every manifest (and would
            // have aborted with a precise error otherwise). Reaching here means all loaded
            // plugins are well-formed; report what was found.
            let specs = providers::registry();
            for s in specs {
                let auth = match s.auth_type {
                    providers::AuthType::OAuth2 => "oauth2",
                    providers::AuthType::ApiKey => "api_key",
                };
                println!("ok  {:14} v{:8} {auth}", s.id, s.version);
            }
            println!("{} provider plugin(s) valid", specs.len());
            return Ok(());
        }
        "healthcheck" => {
            // Used by the container HEALTHCHECK; no curl/wget needed in the image.
            let port = std::env::var("PORT").unwrap_or_else(|_| "8000".to_string());
            let url = format!("http://127.0.0.1:{port}/healthz");
            let ok = reqwest::Client::new()
                .get(&url)
                .timeout(std::time::Duration::from_secs(2))
                .send()
                .await
                .map(|r| r.status().is_success())
                .unwrap_or(false);
            if ok {
                return Ok(());
            }
            std::process::exit(1);
        }
        _ => {}
    }

    // Every remaining mode needs config + a database. Reject anything unknown here so
    // an invalid command fails with a usage message instead of a missing-DB error.
    if !matches!(mode.as_str(), "migrate" | "rotate-keys" | "worker" | "web") {
        anyhow::bail!(
            "unknown process '{mode}' (use web|worker|migrate|gen-key|list-providers|validate-plugins|rotate-keys)"
        );
    }

    // `migrate` is a release step that should run with the narrowest possible inputs — the
    // database URL alone — so it never demands the runtime app secrets. The other modes
    // build the full, fail-closed Config.
    if mode == "migrate" {
        let database_url = Config::database_url_from_env().context("loading config")?;
        let pool = db::connect(&database_url, 10)
            .await
            .context("connecting to database")?;
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("running migrations")?;
        tracing::info!("migrations applied");
        return Ok(());
    }

    let cfg = Config::from_env().context("loading config")?;
    let pool = db::connect(&cfg.database_url, 10)
        .await
        .context("connecting to database")?;

    match mode.as_str() {
        "rotate-keys" => {
            let keyring = Keyring::from_config(&cfg.keys_json, &cfg.active_key)?;
            let n = service::rotate_keys(&pool, &keyring).await?;
            tracing::info!(rotated = n, "key rotation complete");
        }
        "worker" => {
            let state = build_state(cfg, pool)?;
            worker::run(state).await;
        }
        "web" => {
            let state = build_state(cfg, pool)?;
            let addr = state.cfg.bind_addr.clone();
            let app = api::router(state);
            let listener = tokio::net::TcpListener::bind(&addr)
                .await
                .with_context(|| format!("binding {addr}"))?;
            tracing::info!(%addr, "web listening");
            // connect-info gives the rate limiter the peer IP.
            let service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
            axum::serve(listener, service)
                .with_graceful_shutdown(worker::shutdown_signal())
                .await
                .context("serving http")?;
        }
        _ => unreachable!("mode validated above"),
    }
    Ok(())
}

fn build_state(cfg: Config, pool: db::Pool) -> anyhow::Result<AppState> {
    let keyring = Arc::new(Keyring::from_config(&cfg.keys_json, &cfg.active_key)?);
    let transport: Arc<dyn TokenTransport> = Arc::new(ReqwestTransport::new(
        cfg.http_timeout_seconds,
        cfg.require_https,
    ));
    Ok(AppState {
        pool,
        keyring,
        transport,
        cfg: Arc::new(cfg),
    })
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(false)
        .init();
}
