-- SQLite-dialect schema mirroring migrations/0001_initial.sql (which is Postgres-only).
-- TEXT ids, RFC3339/UTC timestamps that round-trip into OffsetDateTime, and the same
-- unique identity index and partial "due" index as Postgres.
--
-- Single source of truth: the in-process SQLite test suite (tests/service_sqlite.rs)
-- and the OpenAPI conformance harness (scripts/openapi-conformance.sh) both load this
-- file, so the schema they exercise can never drift apart.
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
