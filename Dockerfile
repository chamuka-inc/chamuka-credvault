# ─── Build stage ──────────────────────────────────────────────────────────────
# Base images are pinned by digest for reproducible, tamper-evident builds; the tag is
# kept for readability. Dependabot bumps the digest when the upstream tag moves.
FROM rust:1.96-slim-bookworm@sha256:b5f842fac1e3b4ff718a652a8e0173b62d9403ec826ef4998880b9347db30684 AS builder
WORKDIR /app

# Cache dependencies separately from source for fast incremental image builds.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && echo '' > src/lib.rs \
 && cargo build --release --locked --quiet \
 && rm -rf src

COPY src ./src
COPY migrations ./migrations
# Bust the cached lib/bin fingerprint, then build the real binary.
RUN touch src/main.rs src/lib.rs && cargo build --release --locked --quiet

# ─── Runtime stage ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home vault

WORKDIR /app
COPY --from=builder /app/target/release/credvault /usr/local/bin/credvault
COPY --from=builder /app/migrations /app/migrations

USER vault
EXPOSE 8000
ENV PORT=8000 RUST_LOG=info

# Uses the binary's own healthcheck subcommand — no curl/wget in the image.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["credvault", "healthcheck"]

# Default to the web tier; compose overrides the command for worker/migrate.
ENTRYPOINT ["credvault"]
CMD ["web"]
