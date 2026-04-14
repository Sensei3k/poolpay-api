# Contributing to PoolPay

Last Updated: 2026-04-14

## Prerequisites

### Rust Toolchain

Install Rust and Cargo via [rustup.rs](https://rustup.rs/):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
rustup update
```

Verify installation:

```bash
cargo --version
rustc --version
```

### System Dependencies

The project requires Tesseract OCR and Poppler for PDF-to-image conversion.

**macOS:**

```bash
brew install tesseract poppler pkgconf
```

**Linux (Ubuntu/Debian):**

```bash
sudo apt-get update
sudo apt-get install -y libtesseract-dev poppler-utils pkg-config
```

**Linux (Fedora/RHEL):**

```bash
sudo dnf install -y tesseract-devel poppler-utils pkgconf-pkg-config
```

Verify installation:

```bash
tesseract --version
pdftoppm -v
```

### Environment Setup

1. Copy the example env file and fill in credentials:

   ```bash
   cp .env.example .env
   ```

2. Set required environment variables in `.env`:

   ```env
   GREEN_API_INSTANCE_ID=<your_instance_id>
   GREEN_API_TOKEN=<your_api_token>
   ADMIN_TOKEN=<generate with: openssl rand -hex 32>
   ```

   See [Environment Variables](#environment-variables) below for all options.

## Development Workflow

### Building

```bash
# Fast type-check without producing a binary
cargo check

# Build a debug binary
cargo build

# Build an optimized release binary
cargo build --release
```

### Running

Start the service locally:

```bash
cargo run
```

The service will:
- Start the Axum API server on `0.0.0.0:8080` (configurable via `API_BIND_ADDR`)
- Initialize SurrealDB at `./data.surreal`
- Seed fixture data if `SEED_ON_EMPTY=true` and all tables are empty
- Begin polling Green API for incoming messages every 5 seconds

The API becomes available at `http://localhost:8080`.

### Running with Debug Logging

```bash
RUST_LOG=debug cargo run
```

Or set a specific module:

```bash
RUST_LOG=poolpay::parser=debug,poolpay::api=debug cargo run
```

Supported log levels: `debug`, `info`, `warn`, `error`.

## Testing

### Running All Tests

```bash
cargo test
```

Runs 193 tests across unit + integration suites:
- **Unit tests** — models, parser, password hashing, HMAC primitives
- **Parser integration** — amount extraction, sender detection, bank matching
- **API integration** — admin CRUD, auth, validation, soft delete, version conflicts, route handlers
- **Auth integration** — HMAC-gated `verify-credentials` / `ensure-user`, bootstrap idempotency, field-length caps
- **Routing / ingestion integration** — chat→group resolution, receipt ingestion pipeline

Tests use an in-memory SurrealDB instance and do not touch the filesystem or call external APIs.

### Running Specific Test Groups

```bash
# Run only parser tests
cargo test parser_

# Run only API integration tests
cargo test api_integration

# Run a specific test by name
cargo test test_extract_naira_symbol
```

### Watch Mode

For interactive development, use [cargo-watch](https://github.com/watchexec/cargo-watch):

```bash
cargo install cargo-watch
cargo watch -x test -x clippy
```

This watches for file changes and runs tests + linter on save.

## Linting & Formatting

### Check formatting

```bash
cargo fmt --check
```

### Auto-format

```bash
cargo fmt
```

### Run linter

```bash
cargo clippy -- -D warnings
```

Both must pass before committing. The pre-commit hook will enforce this.

## Project Structure

```
src/
├── lib.rs              — crate root; declares all modules
├── main.rs             — entry point; receipt loop (5s) + API server
├── models.rs           — core structs: ReceiptRow, ParsedReceipt, etc.
├── parser.rs           — OCR text parsing (sender, bank, amount extraction)
├── extractor.rs        — Tesseract OCR bindings for images and PDFs
├── whatsapp.rs         — Green API client (send, receive, delete, download)
├── db.rs               — SurrealDB initialization and seeding
├── api/
│   ├── mod.rs          — router setup, CORS configuration
│   ├── auth.rs         — AdminToken extractor (Bearer token via ADMIN_TOKEN)
│   ├── auth_endpoints.rs — HMAC-gated NextAuth endpoints (verify-credentials, ensure-user)
│   ├── handlers.rs     — HTTP handlers (GET/POST/PATCH/DELETE)
│   └── models.rs       — API request/response types, EntityId alias, DB/API structs
├── auth/
│   ├── mod.rs          — auth module root
│   ├── bootstrap.rs    — seed super_admin user on first boot
│   ├── hmac.rs         — HMAC-SHA256 request signing extractor
│   └── password.rs     — Argon2id hashing + constant-time verify_or_dummy

tests/
├── parser_tests.rs          — parser module integration tests
├── api_integration.rs       — API route and database integration tests
├── auth_integration.rs      — HMAC + bootstrap + password-flow integration tests
├── ingestion_integration.rs — receipt ingestion pipeline tests
└── routing_integration.rs   — chat→group / phone→member resolution tests
```

### Adding a New Module

1. Create `src/<module_name>.rs`
2. Add to `src/lib.rs`:
   ```rust
   pub mod <module_name>;
   ```
3. Create `tests/<module_name>_tests.rs` for integration tests
4. Add unit tests as a `#[cfg(test)]` module in the source file if appropriate

## Cargo Commands Reference

| Command | Purpose |
|---------|---------|
| `cargo check` | Fast type-check without building |
| `cargo build` | Build debug binary |
| `cargo build --release` | Build optimized binary |
| `cargo run` | Build and run the service |
| `cargo test` | Run all tests |
| `cargo test <pattern>` | Run tests matching pattern |
| `cargo fmt` | Auto-format code |
| `cargo fmt --check` | Check if formatting is needed |
| `cargo clippy` | Run linter |
| `cargo clippy -- -D warnings` | Linter with warnings as errors |
| `cargo doc --open` | Generate and open documentation |
| `cargo tree` | Show dependency tree |
| `cargo outdated` | Check for outdated dependencies |

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GREEN_API_INSTANCE_ID` | Yes | — | Green API instance ID from dashboard |
| `GREEN_API_TOKEN` | Yes | — | Green API authentication token |
| `ADMIN_TOKEN` | Yes | — | Bearer token for all `/api/admin/*` endpoints. Generate with `openssl rand -hex 32` |
| `NEXTAUTH_BACKEND_SECRET` | Yes | — | Shared secret for NextAuth→backend HMAC signing (min 32 bytes; panics in production if shorter). Generate with `openssl rand -hex 32` |
| `APP_ENV` | No | unset | `production` enables strict CORS; `development` or `test` mounts `/api/test/reset`. Anything else (including unset) is treated as production for the reset gate |
| `DASHBOARD_ORIGIN` | No (required if `APP_ENV=production`) | — | CORS origin for production (e.g., `https://dashboard.example.com`) |
| `BOOTSTRAP_ADMIN_EMAIL` | No | — | Email seeded on first boot if no active admin exists. Rotate the password immediately after first login |
| `BOOTSTRAP_ADMIN_PASSWORD` | No | — | Password for the bootstrap admin; stored as Argon2id, flagged `must_reset_password=true` |
| `API_BIND_ADDR` | No | `0.0.0.0:8080` | Socket address for the HTTP server |
| `SEED_ON_EMPTY` | No | `false` | Set to `true` to seed fixture data when all database tables are empty |
| `RECEIPT_DOWNLOAD_DIR` | No | OS temp dir | Directory for temporary receipt files during OCR |
| `RUST_LOG` | No | `info` | Log level filter: `debug`, `info`, `warn`, `error` |

## Git Workflow

1. Always fetch and branch from `origin/main`:

   ```bash
   git fetch origin
   git checkout -b feat/your-feature origin/main
   ```

2. Make atomic commits with clear messages:

   ```bash
   git commit -m "[PREFIX] - Description"
   ```

   Prefixes (from CLAUDE.md):
   - `[FEAT]` — New feature
   - `[FIX]` — Bug fix
   - `[REFACTOR]` — Code reorganization
   - `[TEST]` — Test additions/changes
   - `[DOCS]` — Documentation only
   - `[PERF]` — Performance improvement
   - `[UPDATE]` — Dependency updates

3. Push your branch and create a PR:

   ```bash
   git push -u origin feat/your-feature
   ```

4. Keep PRs small and focused — one feature per PR.

5. Never commit directly to `main`.

## Code Standards

- **Simple over clever** — if it needs explaining, rewrite it
- **No dead code** — remove commented-out code before committing
- **No debug logs** — use tracing only for operational insights
- **No hardcoded secrets** — always use environment variables
- **Early returns** — reduce nesting with early returns and guards
- **One responsibility per function** — keep functions focused
- **Self-documenting** — clear names, comments explain *why* not *what*

## Common Development Tasks

### Adding a New Parser Pattern

1. Add a regex to `src/parser.rs`
2. Add tests in `tests/parser_tests.rs`
3. Test against real receipts before merging

### Adding an API Endpoint

1. Add handler to `src/api/handlers.rs`
2. Add route to `src/api/mod.rs`
3. Add integration tests to `tests/api_integration.rs`
4. Document the endpoint in the API section of README.md

### Debugging

Enable verbose logging:

```bash
RUST_LOG=debug cargo run
```

Use `dbg!()` macro for quick inspection (remove before committing):

```rust
let value = dbg!(some_function());
```

Use the Rust debugger (lldb on macOS):

```bash
rust-lldb target/debug/poolpay
(lldb) run
```

## Troubleshooting

### Compilation Errors

**"Tesseract not found":**
```bash
brew install tesseract  # macOS
sudo apt-get install libtesseract-dev  # Linux
```

**"pkg-config not found":**
```bash
brew install pkgconf  # macOS
sudo apt-get install pkg-config  # Linux
```

### Test Failures

Run with verbose output:

```bash
cargo test -- --nocapture --test-threads=1
```

This shows println! output and runs tests sequentially (helpful for debugging timing issues).

### Database Issues

If the local SurrealDB gets corrupted:

```bash
rm -rf data.surreal
SEED_ON_EMPTY=true cargo run  # Will reinitialize with fixture data
```

## Pre-Commit Hook

The pre-commit hook runs:
1. `cargo fmt --check` — fails if code isn't formatted
2. `cargo clippy -- -D warnings` — fails if linter finds issues

Fix violations:
```bash
cargo fmt
cargo clippy --fix
```

Then re-stage and commit.

## Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Axum Documentation](https://docs.rs/axum/latest/axum/)
- [SurrealDB Docs](https://surrealdb.com/docs)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract/wiki)
- [Green API Documentation](https://green-api.com/docs)
