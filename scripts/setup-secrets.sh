#!/usr/bin/env bash
# Generate the local development secrets that docker-compose mounts as Docker secrets.
# These are dev-only credentials written to ./secrets/ (which is gitignored — never
# committed). For production, deliver equivalent material through your platform's secret
# manager, not this script. See docs/DEPLOYMENT.md.
#
#   ./scripts/setup-secrets.sh        # create any missing secret files
#   FORCE=1 ./scripts/setup-secrets.sh  # overwrite existing ones
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p secrets

write() {
  local path="$1" value="$2"
  if [[ -s "$path" && "${FORCE:-0}" != "1" ]]; then
    echo "  keep   $path (exists; FORCE=1 to overwrite)"
    return
  fi
  printf '%s' "$value" > "$path"
  chmod 600 "$path"
  echo "  wrote  $path"
}

# A 256-bit base64 secret for signing the OAuth `state` token.
write secrets/state_secret.txt "$(openssl rand -base64 32)"

# The admin bearer token that gates tenant provisioning.
write secrets/admin_token.txt "$(openssl rand -base64 32)"

# The encryption keyring: {version: base64url-32-bytes}. Generated via the binary's own
# gen-key so the format matches exactly what the keyring loader expects.
key="$(cargo run -p credvault --quiet -- gen-key)"
write secrets/vault_keys.txt "$(printf '{"1":"%s"}' "$key")"

echo "Done. 'docker compose up --build' will mount these. Do not commit secrets/."
