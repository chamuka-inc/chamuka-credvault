# ─── Build stage ──────────────────────────────────────────────────────────────
# Base images are pinned by digest for reproducible, tamper-evident builds; the tag is
# kept for readability. Dependabot bumps the digest when the upstream tag moves.
FROM rust:1.96-slim-bookworm@sha256:b5f842fac1e3b4ff718a652a8e0173b62d9403ec826ef4998880b9347db30684 AS builder
WORKDIR /app

# Cache dependencies separately from source for fast incremental image builds.
# Copy only the manifests first; the source arrives in a later layer.
COPY Cargo.toml Cargo.lock ./
COPY crates/credvault/Cargo.toml crates/credvault/Cargo.toml
COPY crates/credvault-import-pipedream/Cargo.toml crates/credvault-import-pipedream/Cargo.toml
# Stub every target Cargo requires (each crate's [[bin]]/[lib] path must exist) so the
# dependency graph builds and caches with no real source present.
RUN mkdir -p crates/credvault/src crates/credvault-import-pipedream/src \
 && echo 'fn main() {}' > crates/credvault/src/main.rs \
 && echo '' > crates/credvault/src/lib.rs \
 && echo 'fn main() {}' > crates/credvault-import-pipedream/src/main.rs \
 && cargo build --release --locked --quiet \
 && rm -rf crates/credvault/src crates/credvault-import-pipedream/src

# Real source (migrations live under crates/credvault/ and arrive with this copy).
COPY crates ./crates
# Bust the cached lib/bin fingerprints, then build the real binaries.
RUN touch crates/credvault/src/main.rs crates/credvault/src/lib.rs \
      crates/credvault-import-pipedream/src/main.rs \
 && cargo build --release --locked --quiet

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home vault

WORKDIR /app
COPY --from=builder /app/target/release/credvault /usr/local/bin/credvault
COPY --from=builder /app/crates/credvault/migrations /app/migrations
# The default provider plugins ship as files, loaded through the same mechanism as any
# third-party plugin. The binary embeds none; this directory is what makes it useful
# out of the box. Operators add their own by appending dirs to VAULT_PLUGIN_DIRS.
COPY plugins/default /app/plugins/default

USER vault
EXPOSE 8000
ENV PORT=8000 RUST_LOG=info VAULT_PLUGIN_DIRS=/app/plugins/default

# Uses the binary's own healthcheck subcommand — no curl/wget in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["credvault", "healthcheck"]

# Default to the web tier; compose overrides the command for worker/migrate.
ENTRYPOINT ["credvault"]
CMD ["web"]
