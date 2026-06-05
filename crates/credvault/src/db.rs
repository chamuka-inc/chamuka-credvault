//! Database backend selection.
//!
//! Production uses Postgres (default build). Tests can compile with `--features sqlite`
//! to run the full service against an in-process SQLite, with no external database.
//!
//! The two backends share one set of SQL. Only three things differ between dialects,
//! and they are isolated here as values, not as branching query code:
//!
//! * the row-lock clause — Postgres takes an explicit `SELECT … FOR UPDATE`; SQLite
//!   serialises writers at the database level, so the clause is empty and the same
//!   mutual-exclusion guarantee holds without it;
//! * the "current timestamp" expression;
//! * the connection pool type.
//!
//! Placeholders (`$1`, `$2`, …) and `INSERT … ON CONFLICT … DO UPDATE` are accepted by
//! both dialects verbatim, so the query strings themselves are identical.

#[cfg(not(feature = "sqlite"))]
mod backend {
    /// The compile-time database driver.
    pub use sqlx::Postgres as Db;
    /// The connection pool type carried in `AppState`.
    pub type Pool = sqlx::PgPool;

    /// Row-lock clause appended to the refresh `SELECT`. Postgres locks the row so
    /// concurrent refreshers serialise instead of stampeding the provider.
    pub const LOCK_FOR_UPDATE: &str = " FOR UPDATE";
    /// SQL expression for "now", written into `updated_at` on writes.
    pub const NOW: &str = "now()";

    /// Open a pool. `max` bounds concurrent connections.
    pub async fn connect(url: &str, max: u32) -> Result<Pool, sqlx::Error> {
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(max)
            .connect(url)
            .await
    }
}

#[cfg(feature = "sqlite")]
mod backend {
    pub use sqlx::Sqlite as Db;
    pub type Pool = sqlx::SqlitePool;

    /// SQLite has no row-lock syntax; its single-writer model already serialises the
    /// refresh transaction, so no clause is needed.
    pub const LOCK_FOR_UPDATE: &str = "";
    /// RFC3339/UTC so the value round-trips back into `OffsetDateTime` on read.
    pub const NOW: &str = "strftime('%Y-%m-%dT%H:%M:%SZ','now')";

    pub async fn connect(url: &str, max: u32) -> Result<Pool, sqlx::Error> {
        sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max)
            .connect(url)
            .await
    }
}

pub use backend::{connect, Db, Pool, LOCK_FOR_UPDATE, NOW};

/// A transaction over the selected backend.
pub type DbTransaction<'a> = sqlx::Transaction<'a, Db>;
