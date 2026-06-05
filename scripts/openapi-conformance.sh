#!/usr/bin/env bash
#
# OpenAPI conformance: prove the running server matches docs/openapi.yaml.
#
# Boots credvault on an ephemeral SQLite database (no external services, mirroring the
# `db-sqlite` CI job), bootstraps a tenant, then fuzzes every operation with Schemathesis
# and asserts each response honors the documented status codes, schemas, and content types.
#
# The server is configured with *dummy* OAuth client credentials for every provider. The
# `start` endpoint only renders an authorize URL (no network call), so dummy creds make
# every provider "configured" and exercise that path without real secrets — the callback,
# which would actually talk to a provider, is never driven here.
#
# Requirements: cargo, sqlite3, jq, curl, and Schemathesis (`schemathesis` on PATH, or set
# SCHEMATHESIS to a different entrypoint, e.g. a venv's binary).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PORT="${PORT:-8000}"
BASE="http://127.0.0.1:${PORT}"
SCHEMATHESIS="${SCHEMATHESIS:-schemathesis}"
SPEC="docs/openapi.yaml"
SCHEMA_SQL="crates/credvault/tests/fixtures/sqlite_schema.sql"
BIN="./target/debug/credvault"
DB="$(mktemp -t credvault-openapi-XXXXXX).db"
ADMIN_TOKEN="conformance-admin-token-0123456789abcdef"
N="${SCHEMATHESIS_EXAMPLES:-25}"

# Checks excluded from the fuzz, each for a documented reason (enforced separately below):
#   ignored_auth            — a static `-H Authorization` header can't be stripped by the
#                             probe; auth enforcement is asserted directly with no-auth curls.
#   positive_data_acceptance— some schema-valid inputs are *semantically* invalid in ways
#                             OpenAPI can't express: an OAuth op on an api-key provider (and
#                             vice-versa) is a documented 400 bad_provider, and any generated
#                             `state` at the callback is a documented 400 bad_state.
#   negative_data_rejection — the server, per normal HTTP, ignores unknown query parameters
#                             rather than rejecting them; that is not a contract violation.
EXCLUDE_CHECKS="ignored_auth,positive_data_acceptance,negative_data_rejection"

for tool in cargo sqlite3 jq curl "$SCHEMATHESIS"; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "error: required tool '$tool' not found on PATH" >&2
    [[ "$tool" == "$SCHEMATHESIS" ]] && echo "  install it with: pip install schemathesis  (or set SCHEMATHESIS=...)" >&2
    exit 127
  }
done

SERVER_PID=""
cleanup() {
  [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
  rm -f "$DB"
}
trap cleanup EXIT

echo "==> building credvault (sqlite backend)"
cargo build -p credvault --features sqlite

echo "==> seeding ephemeral sqlite schema"
sqlite3 "$DB" < "$SCHEMA_SQL"

echo "==> minting an encryption key"
KEY="$("$BIN" gen-key 2>/dev/null | tail -n1)"

echo "==> booting web server on $BASE"
# Required secrets (>=32 bytes), the SQLite DB, the seed plugin catalog, and dummy OAuth
# client creds for every provider so none reports `not_configured` (503).
env \
  VAULT_PROCESS=web \
  VAULT_DATABASE_URL="sqlite://${DB}?mode=rwc" \
  VAULT_ALLOW_INSECURE_HTTP=1 \
  VAULT_STATE_SECRET="conformance-state-secret-0123456789abcdef" \
  VAULT_ADMIN_TOKEN="$ADMIN_TOKEN" \
  VAULT_KEYS="{\"1\":\"${KEY}\"}" \
  VAULT_ACTIVE_KEY=1 \
  VAULT_PLUGIN_DIRS="plugins/default" \
  VAULT_BIND_HOST=127.0.0.1 \
  PORT="$PORT" \
  VAULT_RATE_LIMIT_PER_MINUTE=0 \
  VAULT_PUBLIC_BASE_URL="$BASE" \
  GITHUB_CLIENT_ID=dummy GITHUB_CLIENT_SECRET=dummy \
  GITLAB_CLIENT_ID=dummy GITLAB_CLIENT_SECRET=dummy \
  GOOGLE_CLIENT_ID=dummy GOOGLE_CLIENT_SECRET=dummy \
  MICROSOFT_CLIENT_ID=dummy MICROSOFT_CLIENT_SECRET=dummy \
  NOTION_CLIENT_ID=dummy NOTION_CLIENT_SECRET=dummy \
  SLACK_CLIENT_ID=dummy SLACK_CLIENT_SECRET=dummy \
  SPOTIFY_CLIENT_ID=dummy SPOTIFY_CLIENT_SECRET=dummy \
  X_CLIENT_ID=dummy X_CLIENT_SECRET=dummy \
  ZOOM_CLIENT_ID=dummy ZOOM_CLIENT_SECRET=dummy \
  "$BIN" web &
SERVER_PID=$!

echo "==> waiting for readiness"
for _ in $(seq 1 50); do
  if curl -fsS -o /dev/null "$BASE/healthz" 2>/dev/null; then break; fi
  sleep 0.2
done
curl -fsS -o /dev/null "$BASE/healthz"

echo "==> bootstrapping a tenant + a connection"
TENANT_KEY="$(curl -fsS -XPOST "$BASE/v1/tenants" \
  -H "authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"name":"conformance"}' | jq -r .api_key)"
CONN_ID="$(curl -fsS -XPOST "$BASE/v1/connect/stripe/api-key" \
  -H "authorization: Bearer $TENANT_KEY" -H 'content-type: application/json' \
  -d '{"external_user_id":"user-1","api_key":"sk_test_seed"}' | jq -r .id)"

# --- Hard assertions the fuzz can't make (substitute for the excluded checks) ----------
fail() { echo "ASSERTION FAILED: $*" >&2; exit 1; }
assert_code() { # method path expected [authheader]
  local method="$1" path="$2" want="$3" auth="${4:-}"
  local -a args=(-s -o /dev/null -w '%{http_code}' -X "$method" "$BASE$path")
  [[ -n "$auth" ]] && args+=(-H "$auth")
  local got
  got="$(curl "${args[@]}")"
  [[ "$got" == "$want" ]] || fail "$method $path expected $want, got $got"
}

echo "==> asserting auth enforcement (replaces ignored_auth)"
for p in "/v1/connections" "/v1/credentials/stripe?external_user_id=user-1" \
         "/v1/connect/github/start?external_user_id=user-1"; do
  assert_code GET "$p" 401                                   # no credential
  assert_code GET "$p" 401 "authorization: Bearer cvk_wrong" # bad credential
done
assert_code POST "/v1/tenants" 401 "authorization: Bearer $TENANT_KEY"  # tenant key != admin

echo "==> asserting connection delete reaches core logic"
assert_code DELETE "/v1/connections/$CONN_ID" 200 "authorization: Bearer $TENANT_KEY"
assert_code DELETE "/v1/connections/$CONN_ID" 404 "authorization: Bearer $TENANT_KEY"

# `start` 303-redirects to the provider's authorize URL — off our API — so a
# redirect-following fuzzer can't evaluate it in isolation. It is excluded from the fuzz
# (below) and its documented outcomes are asserted directly instead.
echo "==> asserting start outcomes (excluded from fuzz: 303 leaves the API)"
AUTH="authorization: Bearer $TENANT_KEY"
assert_code GET "/v1/connect/github/start?external_user_id=u" 200 "$AUTH"               # oauth provider
assert_code GET "/v1/connect/github/start?external_user_id=u&redirect=true" 303 "$AUTH" # redirect form
assert_code GET "/v1/connect/nope/start?external_user_id=u" 404 "$AUTH"                 # unknown provider
assert_code GET "/v1/connect/stripe/start?external_user_id=u" 400 "$AUTH"               # api-key provider
curl -fsS "$BASE/v1/connect/github/start?external_user_id=u" -H "$AUTH" \
  | jq -e .authorize_url >/dev/null || fail "start 200 missing authorize_url"
loc="$(curl -s -o /dev/null -D - "$BASE/v1/connect/github/start?external_user_id=u&redirect=true" \
  -H "$AUTH" | tr -d '\r' | awk -F': ' 'tolower($1)=="location"{print $2}')"
[[ "$loc" == https://github.com/* ]] || fail "start 303 Location not a provider URL: $loc"

# --- Schemathesis: two auth realms (tenant-scoped ops, and the admin-only tenants op) ---
echo "==> conformance fuzz: tenant realm"
"$SCHEMATHESIS" run "$SPEC" \
  --url "$BASE" \
  -H "authorization: Bearer $TENANT_KEY" \
  --exclude-path /v1/tenants \
  --exclude-path '/v1/connect/{provider}/start' \
  --exclude-checks "$EXCLUDE_CHECKS" \
  --max-redirects 0 \
  -n "$N"

echo "==> conformance fuzz: admin realm (/v1/tenants)"
"$SCHEMATHESIS" run "$SPEC" \
  --url "$BASE" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  --include-path /v1/tenants \
  --exclude-checks "$EXCLUDE_CHECKS" \
  --max-redirects 0 \
  -n "$N"

echo "==> OpenAPI conformance passed"
