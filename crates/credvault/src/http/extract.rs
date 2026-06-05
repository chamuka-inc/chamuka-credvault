//! Request extractors that fail in the crate's own error envelope.
//!
//! axum's built-in `Query`/`Path`/`Json` extractors reject a malformed request *before*
//! any handler runs, with a plain-text body — and, for a well-formed JSON body of the
//! wrong shape, a `422`. That bypasses the `{code, message}` JSON contract every other
//! error on this surface honors, and surfaces a status the OpenAPI spec never documents.
//!
//! These thin wrappers delegate to the axum extractors on the happy path and translate any
//! rejection into [`Error::Validation`] — so a malformed request is a `400` carrying the
//! same envelope as a field-level validation failure. The rejection's own description
//! (e.g. "missing field `state`") is structural, never secret, so it is passed through as
//! the message. Handlers use these in place of the axum extractors; nothing else changes.

use axum::extract::{FromRequest, FromRequestParts, Request};
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use crate::error::Error;
use crate::AppState;

/// `Json<T>`: request extraction that fails as a `400` envelope, and a response body
/// identical to `axum::Json`. One type serves both directions so handlers read uniformly.
pub struct Json<T>(pub T);

#[axum::async_trait]
impl<T> FromRequest<AppState> for Json<T>
where
    T: serde::de::DeserializeOwned,
{
    type Rejection = Error;

    async fn from_request(req: Request, state: &AppState) -> Result<Self, Error> {
        axum::Json::<T>::from_request(req, state)
            .await
            .map(|axum::Json(v)| Json(v))
            .map_err(|r| Error::Validation(r.to_string()))
    }
}

impl<T: serde::Serialize> IntoResponse for Json<T> {
    fn into_response(self) -> Response {
        axum::Json(self.0).into_response()
    }
}

/// `Query<T>` with the same envelope-on-failure behavior as [`Json`].
pub struct Query<T>(pub T);

#[axum::async_trait]
impl<T> FromRequestParts<AppState> for Query<T>
where
    T: serde::de::DeserializeOwned,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Error> {
        axum::extract::Query::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Query(v)| Query(v))
            .map_err(|r| Error::Validation(r.to_string()))
    }
}

/// `Path<T>` with the same envelope-on-failure behavior as [`Json`].
pub struct Path<T>(pub T);

#[axum::async_trait]
impl<T> FromRequestParts<AppState> for Path<T>
where
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Error> {
        axum::extract::Path::<T>::from_request_parts(parts, state)
            .await
            .map(|axum::extract::Path(v)| Path(v))
            .map_err(|r| Error::Validation(r.to_string()))
    }
}
