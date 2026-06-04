-- Initial schema. Owned solely by migrations; the app never CREATE TABLEs on boot.

CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    -- SHA-256 (base64url) of the tenant's API key. The plaintext key is shown once at
    -- creation and never stored; requests authenticate by presenting it.
    api_key_hash  TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Bearer-token lookups hit this on every authenticated request.
CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_api_key ON tenants (api_key_hash);

CREATE TABLE IF NOT EXISTS connections (
    id                  TEXT PRIMARY KEY,
    tenant_id           TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider            TEXT NOT NULL,
    external_user_id    TEXT NOT NULL,
    account_key         TEXT NOT NULL DEFAULT 'default',
    enc_access_token    TEXT NOT NULL,
    enc_refresh_token   TEXT,
    token_type          TEXT NOT NULL DEFAULT 'Bearer',
    scopes              TEXT NOT NULL DEFAULT '',
    expires_at          TIMESTAMPTZ,
    status              TEXT NOT NULL DEFAULT 'active',
    refresh_attempts    INTEGER NOT NULL DEFAULT 0,
    last_refresh_at     TIMESTAMPTZ,
    last_error          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One connection per (tenant, provider, end-user, account). The upsert target.
CREATE UNIQUE INDEX IF NOT EXISTS uq_connection_identity
    ON connections (tenant_id, provider, external_user_id, account_key);

-- Worker scan: "active, expiring soon, refreshable".
CREATE INDEX IF NOT EXISTS ix_connections_due
    ON connections (status, expires_at)
    WHERE enc_refresh_token IS NOT NULL;

CREATE INDEX IF NOT EXISTS ix_connections_tenant ON connections (tenant_id);

-- Pending OAuth authorization flows. One row is written at authorize time and claimed
-- exactly once at the callback (single-use, so an intercepted code+state cannot be
-- replayed). It also holds the encrypted, per-flow PKCE verifier — generated server-side
-- and never derived from the front-channel state.
CREATE TABLE IF NOT EXISTS oauth_flows (
    nonce             TEXT PRIMARY KEY,
    provider          TEXT NOT NULL,
    tenant_id         TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    external_user_id  TEXT NOT NULL,
    account_key       TEXT NOT NULL DEFAULT 'default',
    pkce_verifier     TEXT,                       -- encrypted; NULL when provider !uses_pkce
    expires_at        TIMESTAMPTZ NOT NULL,
    consumed_at       TIMESTAMPTZ,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Expiry sweep by the worker.
CREATE INDEX IF NOT EXISTS ix_oauth_flows_expiry ON oauth_flows (expires_at);
