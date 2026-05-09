# PoolPay API task runner.
#
# Install: `brew install just` (macOS) — one-time. Then `just --list` to see
# recipes, or `just <recipe>` to run one. All recipes wrap commands documented
# in docs/RUNBOOK.md and docs/CONTRIBUTING.md; using `just` is optional.

# Default recipe — list available targets when `just` is run with no args.
default:
    @just --list --unsorted

# Run SurrealDB as a standalone server (Terminal 1).
# Holds the RocksDB lock and exposes ws://127.0.0.1:8000 so Surrealist can
# attach to the same DB the API is using. Pair with `just dev` in another
# terminal. See docs/RUNBOOK.md § SurrealDB Connection for details.
surreal:
    surreal start --user root --pass root --bind 127.0.0.1:8000 rocksdb:./data.surreal

# Run the API as a client of the standalone SurrealDB server (Terminal 2).
# Use this when you want Surrealist GUI access alongside the API. Requires
# `just surreal` running in another terminal first.
dev:
    SURREAL_URL=ws://127.0.0.1:8000 SURREAL_USER=root SURREAL_PASS=root cargo run

# Run the API in embedded mode (default — simplest setup).
# Cargo opens RocksDB directly; Surrealist cannot attach while this is up.
# Use when you don't need GUI database access.
dev-embedded:
    cargo run

# Wipe the local DB. Next `just dev` / `just dev-embedded` reseeds fixtures
# (requires SEED_ON_EMPTY=true in .env; the dev-only dummy admin fixtures
# additionally require APP_ENV=development or APP_ENV=test). Stop whichever
# process currently holds the RocksDB lock first: `just surreal` (in remote
# mode) or `just dev-embedded` / embedded `cargo run` (in embedded mode).
reset-db:
    rm -rf ./data.surreal
    @echo "data.surreal removed. Restart the API with SEED_ON_EMPTY=true to reseed."

# Run all tests (currently 328 across 6 binaries).
test:
    cargo test

# Fast type-check without producing a binary.
check:
    cargo check

# Format + lint, gating on warnings (matches pre-commit).
lint:
    cargo fmt --check
    cargo clippy --all-targets -- -D warnings

# Auto-fix formatting issues.
fmt:
    cargo fmt
