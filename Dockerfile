# ─── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.96-slim-bookworm AS builder
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
FROM debian:bookworm-slim AS runtime
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
