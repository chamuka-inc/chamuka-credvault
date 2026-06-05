//! The refresh daemon (Factor VIII, IX, XII). A separate process from the web tier,
//! sharing only the database. It proactively refreshes tokens nearing expiry so the
//! fetch path rarely has to. Failures are isolated per connection; shutdown is graceful.

use std::time::Duration;

use crate::{service, AppState};

const BATCH: i64 = 100;

pub async fn run(state: AppState) {
    let period = Duration::from_secs(state.cfg.worker_interval_seconds.max(1));
    let mut ticker = tokio::time::interval(period);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    tracing::info!(
        interval_secs = state.cfg.worker_interval_seconds,
        "refresh worker started"
    );

    loop {
        tokio::select! {
            _ = ticker.tick() => tick(&state).await,
            _ = shutdown_signal() => {
                tracing::info!("refresh worker shutting down");
                break;
            }
        }
    }
}

async fn tick(state: &AppState) {
    // Sweep abandoned/expired OAuth flow rows so the table does not grow unbounded.
    match service::purge_expired_flows(&state.pool).await {
        Ok(n) if n > 0 => tracing::debug!(purged = n, "expired oauth flows removed"),
        _ => {}
    }

    let due = match service::due_for_refresh(&state.pool, &state.cfg, BATCH).await {
        Ok(ids) => ids,
        Err(_) => {
            // already logged at the source
            return;
        }
    };
    if due.is_empty() {
        return;
    }
    tracing::info!(count = due.len(), "refreshing due connections");
    for id in due {
        // Each connection is its own transaction; one failure can't sink the batch.
        match service::refresh_one(
            &state.pool,
            state.transport.as_ref(),
            &state.keyring,
            &state.cfg,
            &id,
        )
        .await
        {
            Ok(Some(status)) => tracing::debug!(id = %id, status = %status, "refreshed"),
            Ok(None) => {}
            Err(_) => tracing::warn!(id = %id, "refresh attempt errored"),
        }
    }
}

pub async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
