//! HTTP surface (Factor VII). Stateless handlers; every request opens and drops a
//! short-lived DB interaction. Validation happens at the edge; secrets are exposed in
//! exactly one place — the credentials response — and nowhere else.
//!
//! Authorization is structural: every tenant-scoped handler takes a [`TenantPrincipal`]
//! (resolved from the API key by an extractor), and the `tenant_id` it operates on comes
//! from that principal — never from the query string or body. A handler physically cannot
//! read another tenant's data because it has no way to name another tenant. Tenant
//! provisioning takes an [`AdminPrincipal`]. The OAuth callback is the one unauthenticated
//! route; it is gated by the signed, single-use `state` token instead.

use std::time::Duration;

use axum::extract::{DefaultBodyLimit, State};
use axum::response::{Html, IntoResponse, Redirect};
use axum::routing::{delete, get, post};
use axum::Router;
use serde::Deserialize;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::crypto::secret::{secret, ExposeSecret};
use crate::error::Error;
use crate::http::auth::{AdminPrincipal, TenantPrincipal};
use crate::http::extract::{Json, Path, Query};
use crate::http::ratelimit;
use crate::{providers, service, AppState};

pub fn router(state: AppState) -> Router {
    let limiter = ratelimit::RateLimiter::new(state.cfg.rate_limit_per_minute);
    let max_body = state.cfg.max_body_bytes;
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/providers", get(list_providers))
        .route("/v1/tenants", post(create_tenant))
        .route("/v1/connect/:provider/start", get(connect_start))
        .route("/v1/connect/:provider/callback", get(connect_callback))
        .route("/v1/connect/:provider/api-key", post(connect_api_key))
        .route("/v1/credentials/:provider", get(get_credentials))
        .route("/v1/connections", get(list_connections))
        .route("/v1/connections/:id", delete(delete_connection))
        // Coarse per-IP rate limit and a hard body cap, applied to the whole surface.
        .layer(axum::middleware::from_fn_with_state(
            limiter,
            ratelimit::enforce,
        ))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(30),
        ))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

// ----------------------------- validation ----------------------------------- //
/// The account key used when a caller doesn't name one — the common single-account case.
const DEFAULT_ACCOUNT_KEY: &str = "default";

fn validate_id(field: &str, v: &str) -> Result<(), Error> {
    if v.is_empty() || v.len() > 255 {
        return Err(Error::Validation(format!("{field} must be 1..=255 chars")));
    }
    Ok(())
}

fn spec_or_404(provider: &str) -> Result<&'static providers::ProviderSpec, Error> {
    providers::get(provider).ok_or(Error::UnknownProvider)
}

// ----------------------------- health --------------------------------------- //
async fn healthz() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn readyz(State(st): State<AppState>) -> Result<Json<Value>, Error> {
    sqlx::query("SELECT 1").execute(&st.pool).await?;
    Ok(Json(json!({ "ready": true })))
}

// ----------------------------- discovery ------------------------------------ //
async fn list_providers() -> Json<Value> {
    let items: Vec<Value> = providers::registry()
        .iter()
        .map(|s| {
            json!({
                "id": s.id,
                "version": s.version,
                "auth_type": s.auth_type.as_str(),
                "configured": s.is_configured(),
                "scopes": s.default_scopes,
            })
        })
        .collect();
    Json(json!({ "providers": items }))
}

// ----------------------------- tenants -------------------------------------- //
#[derive(Deserialize)]
struct TenantIn {
    name: String,
}

async fn create_tenant(
    _admin: AdminPrincipal,
    State(st): State<AppState>,
    Json(body): Json<TenantIn>,
) -> Result<Json<Value>, Error> {
    if body.name.trim().is_empty() || body.name.len() > 255 {
        return Err(Error::Validation("name must be 1..=255 chars".into()));
    }
    let t = service::create_tenant(&st.pool, &body.name).await?;
    // The API key is returned exactly once, here. Only its hash is stored.
    Ok(Json(json!({
        "id": t.id,
        "name": t.name,
        "api_key": t.api_key.expose_secret(),
    })))
}

// ----------------------------- connect: oauth ------------------------------- //
#[derive(Deserialize)]
struct StartQuery {
    external_user_id: String,
    #[serde(default)]
    account_key: Option<String>,
    #[serde(default)]
    redirect: Option<bool>,
    /// Tenant-scoped providers only: a JSON object naming the provider's declared
    /// `instance_vars`, e.g. `{"host":"wd2-impl-services1.workday.com","tenant":"acme"}`.
    /// Ignored by ordinary providers; required by instance providers.
    #[serde(default)]
    instance: Option<String>,
}

async fn connect_start(
    tenant: TenantPrincipal,
    State(st): State<AppState>,
    Path(provider): Path<String>,
    Query(q): Query<StartQuery>,
) -> Result<axum::response::Response, Error> {
    let spec = spec_or_404(&provider)?;
    validate_id("external_user_id", &q.external_user_id)?;
    let account_key = q.account_key.unwrap_or_else(|| DEFAULT_ACCOUNT_KEY.into());
    let auth = service::start_authorization(
        &st.pool,
        &st.keyring,
        &st.cfg,
        spec,
        service::Ident {
            tenant_id: &tenant.tenant_id,
            external_user_id: &q.external_user_id,
            account_key: &account_key,
        },
        &[],
        q.instance.as_deref(),
    )
    .await?;
    if q.redirect.unwrap_or(false) {
        Ok(Redirect::to(&auth.authorize_url).into_response())
    } else {
        Ok(Json(json!({ "authorize_url": auth.authorize_url })).into_response())
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn connect_callback(
    State(st): State<AppState>,
    Path(provider): Path<String>,
    Query(q): Query<CallbackQuery>,
) -> Result<Html<String>, Error> {
    let spec = spec_or_404(&provider)?;
    let conn = service::complete_authorization(
        &st.pool,
        st.transport.as_ref(),
        &st.keyring,
        &st.cfg,
        spec,
        &q.code,
        &q.state,
    )
    .await?;
    Ok(Html(format!(
        "<h2>Connected {} ✓</h2><p>You can close this window.</p>",
        conn.provider
    )))
}

#[derive(Deserialize)]
struct ApiKeyIn {
    external_user_id: String,
    api_key: String,
    #[serde(default)]
    account_key: Option<String>,
}

async fn connect_api_key(
    tenant: TenantPrincipal,
    State(st): State<AppState>,
    Path(provider): Path<String>,
    Json(body): Json<ApiKeyIn>,
) -> Result<Json<Value>, Error> {
    let spec = spec_or_404(&provider)?;
    validate_id("external_user_id", &body.external_user_id)?;
    if body.api_key.is_empty() {
        return Err(Error::Validation("api_key must not be empty".into()));
    }
    let account_key = body
        .account_key
        .unwrap_or_else(|| DEFAULT_ACCOUNT_KEY.into());
    let conn = service::store_api_key(
        &st.pool,
        &st.keyring,
        spec,
        &tenant.tenant_id,
        &body.external_user_id,
        &secret(body.api_key),
        &account_key,
    )
    .await?;
    Ok(Json(serde_json::to_value(conn.public()).unwrap()))
}

// ----------------------------- credentials: THE endpoint -------------------- //
#[derive(Deserialize)]
struct CredQuery {
    external_user_id: String,
    #[serde(default)]
    account_key: Option<String>,
}

async fn get_credentials(
    tenant: TenantPrincipal,
    State(st): State<AppState>,
    Path(provider): Path<String>,
    Query(q): Query<CredQuery>,
) -> Result<Json<Value>, Error> {
    let spec = spec_or_404(&provider)?;
    validate_id("external_user_id", &q.external_user_id)?;
    let account_key = q.account_key.unwrap_or_else(|| DEFAULT_ACCOUNT_KEY.into());
    let resp = service::get_access_token(
        &st.pool,
        st.transport.as_ref(),
        &st.keyring,
        &st.cfg,
        spec,
        service::Ident {
            tenant_id: &tenant.tenant_id,
            external_user_id: &q.external_user_id,
            account_key: &account_key,
        },
    )
    .await?;
    // The one legitimate exposure: handing the caller the token they asked for. For
    // tenant-scoped providers, `instance` carries the customer's host/tenant so the caller
    // can build the provider API base; it is a JSON object (or absent).
    let instance = resp
        .instance
        .as_deref()
        .and_then(|s| serde_json::from_str::<Value>(s).ok());
    Ok(Json(json!({
        "access_token": resp.access_token.expose_secret(),
        "token_type": resp.token_type,
        "expires_at": resp.expires_at.and_then(|d| d.format(&Rfc3339).ok()),
        "scopes": resp.scopes,
        "instance": instance,
    })))
}

// ----------------------------- management ----------------------------------- //
async fn list_connections(
    tenant: TenantPrincipal,
    State(st): State<AppState>,
) -> Result<Json<Value>, Error> {
    let rows = service::list_connections(&st.pool, &tenant.tenant_id).await?;
    let public: Vec<_> = rows.iter().map(|c| c.public()).collect();
    Ok(Json(json!({ "connections": public })))
}

async fn delete_connection(
    tenant: TenantPrincipal,
    State(st): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, Error> {
    if !service::disconnect(
        &st.pool,
        st.transport.as_ref(),
        st.keyring.as_ref(),
        &tenant.tenant_id,
        &id,
    )
    .await?
    {
        return Err(Error::NotConnected);
    }
    Ok(Json(json!({ "deleted": id })))
}
