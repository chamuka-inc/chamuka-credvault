# credvault developer tasks. These mirror the CI gates 1:1 (.github/workflows/ci.yml)
# so `make ci` locally is exactly what a pull request must clear. No hidden steps.

CARGO ?= cargo

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'

# ── Build ──────────────────────────────────────────────────────────────────
.PHONY: build
build: ## Debug build of the whole workspace
	$(CARGO) build --workspace

.PHONY: release
release: ## Release build (LTO, stripped) — the deployment artifact
	$(CARGO) build --release --locked

# ── Quality gates (these four are what CI's lint-and-unit job runs) ──────────
.PHONY: fmt
fmt: ## Apply rustfmt
	$(CARGO) fmt --all

.PHONY: fmt-check
fmt-check: ## Check formatting (fails on any deviation)
	$(CARGO) fmt --all --check

.PHONY: lint
lint: ## Clippy with warnings as errors
	$(CARGO) clippy --workspace --all-targets --all-features -- -D warnings

.PHONY: test
test: ## Unit + integration tests (Postgres-only tests auto-skip without DATABASE_URL)
	$(CARGO) test --workspace --all-targets

.PHONY: test-sqlite
test-sqlite: ## Full DB lifecycle in-process on SQLite — no external services
	$(CARGO) test -p credvault --features sqlite

# ── Database ─────────────────────────────────────────────────────────────────
.PHONY: migrate
migrate: ## Apply migrations (needs VAULT_DATABASE_URL)
	$(CARGO) run -p credvault --quiet -- migrate

# ── Supply chain (CI's security workflow) ────────────────────────────────────
.PHONY: audit
audit: ## Known RUSTSEC advisories (needs cargo-audit)
	$(CARGO) audit

.PHONY: deny
deny: ## Advisories, licenses, bans, sources (needs cargo-deny)
	$(CARGO) deny check

# ── Aggregate ────────────────────────────────────────────────────────────────
.PHONY: ci
ci: fmt-check lint test test-sqlite ## Run the full PR gate set locally

# ── Container / local stack ──────────────────────────────────────────────────
.PHONY: docker
docker: ## Build the production container image
	docker build -t credvault:dev .

.PHONY: secrets
secrets: ## Generate local dev secrets for docker-compose
	./scripts/setup-secrets.sh

.PHONY: up
up: ## Bring up the local stack (db + migrate + web + worker)
	docker compose up --build

.PHONY: clean
clean: ## Remove build artifacts
	$(CARGO) clean
