//! One typed error for the whole crate, mapped to HTTP at the edge.
//!
//! Two rules encoded here:
//!   * Client-facing messages never contain secrets or internal details. `sqlx` and
//!     `reqwest` failures are logged server-side and collapsed to generic 5xx codes.
//!   * Every variant has an explicit status + stable machine code, so callers can
//!     branch on `code` (e.g. `needs_reauth`) without string-matching prose.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no connection for this tenant/provider/user")]
    NotConnected,
    #[error("connection needs re-authorization")]
    NeedsReauth,
    #[error("connection temporarily unavailable")]
    RefreshUnavailable,
    #[error("unknown provider")]
    UnknownProvider,
    #[error("provider does not support this operation")]
    BadProvider,
    #[error("provider client credentials are not configured")]
    NotConfigured,
    #[error("invalid or expired state")]
    BadState,
    #[error("unknown tenant")]
    UnknownTenant,
    #[error("unauthorized")]
    Unauthorized,
    #[error("{0}")]
    Validation(String),
    #[error("upstream provider error")]
    Upstream,
    #[error("internal error")]
    Internal,
}

impl Error {
    fn parts(&self) -> (StatusCode, &'static str) {
        use Error::*;
        match self {
            NotConnected => (StatusCode::NOT_FOUND, "not_connected"),
            NeedsReauth => (StatusCode::CONFLICT, "needs_reauth"),
            RefreshUnavailable => (StatusCode::SERVICE_UNAVAILABLE, "refresh_failed"),
            UnknownProvider => (StatusCode::NOT_FOUND, "unknown_provider"),
            BadProvider => (StatusCode::BAD_REQUEST, "bad_provider"),
            NotConfigured => (StatusCode::SERVICE_UNAVAILABLE, "not_configured"),
            BadState => (StatusCode::BAD_REQUEST, "bad_state"),
            UnknownTenant => (StatusCode::NOT_FOUND, "unknown_tenant"),
            Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Validation(_) => (StatusCode::BAD_REQUEST, "validation"),
            Upstream => (StatusCode::BAD_GATEWAY, "upstream_error"),
            Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();
        let message = self.to_string();
        (status, Json(json!({ "code": code, "message": message }))).into_response()
    }
}

// Internal failures: log the detail, expose nothing.
impl From<sqlx::Error> for Error {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error");
        Error::Internal
    }
}
