# poolpay

A Rust service that manages PoolPay savings groups with a REST API and WhatsApp receipt OCR. Built with Axum, SurrealDB, and Green API.

> Docs index: [`docs/INDEX.md`](./docs/INDEX.md). For AI-assisted development setup see [`docs/ai-workflow.md`](./docs/ai-workflow.md) (optional).

## What it does

**REST API** for managing multi-group PoolPay savings groups:
- CRUD for groups, members, cycles, and payments
- Admin endpoints secured with bearer token auth
- Soft delete for groups/members/payments, hard delete for cycles
- Optimistic concurrency control via version fields
- Fixture seeding for development

**Receipt OCR** via WhatsApp:
1. Polls a WhatsApp number via the Green API for incoming messages
2. Detects image and PDF attachments and downloads them
3. Runs Tesseract OCR to extract raw text (PDFs are first converted to images via `pdftoppm`)
4. Parses the OCR text to extract sender name, bank, and amount
5. Replies to the chat with a formatted summary:
   ```
   Sender: FULL NAME
   Bank: BankName
   Amount: ₦97,800.00
   ```

## Project structure

```
src/
├── lib.rs         — crate root; declares all public modules
├── main.rs        — entry point; receipt loop (5s) + API server
├── models.rs      — all structs and types
├── whatsapp.rs    — Green API calls (receive, delete, send, download, quote-reply)
├── extractor.rs   — Tesseract OCR for images and PDFs
├── parser.rs      — receipt parsing (sender, bank, amount)
├── db.rs          — SurrealDB initialization and seeding
├── api/
│   ├── mod.rs     — router setup, CORS configuration
│   ├── handlers.rs — HTTP handlers (GET/POST/PATCH/DELETE)
│   └── models.rs  — API request/response types, EntityId alias, DB/API structs
tests/
├── api_integration.rs       — API route, auth, CRUD, optimistic concurrency control (OCC) integration tests
├── auth_integration.rs      — HMAC + bootstrap + password + JWT integration tests
├── ingestion_integration.rs — receipt ingestion pipeline tests
├── parser_tests.rs          — receipt parser (sender / bank / amount) tests
└── routing_integration.rs   — chat→group / phone→member resolution tests
```

The project uses a **lib + bin** layout: `src/lib.rs` exposes all modules as a library crate (`poolpay`), and `src/main.rs` is the binary entry point that imports from it. This allows `tests/` to import the public API directly, keeping integration tests separate from source files.

New modules should be added to `src/lib.rs` as `pub mod <name>` and tested in a corresponding `tests/<name>_tests.rs` file.

## Prerequisites

- [Rust](https://rustup.rs/)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [Poppler](https://poppler.freedesktop.org/) (for `pdftoppm`)
- [pkgconf](https://github.com/pkgconf/pkgconf)
- A [Green API](https://green-api.com/) account with an active WhatsApp instance

On macOS:
```bash
brew install tesseract poppler pkgconf
```

## Setup

1. Clone the repo and copy the env template:
   ```bash
   cp .env.example .env
   ```
   Fill in your Green API credentials and NextAuth backend HMAC secret (see [Environment variables](#environment-variables) below).

2. Build and run:
   ```bash
   cargo run
   ```

## Commands

| Command | Description |
|---------|-------------|
| `cargo run` | Build and start the polling service |
| `cargo build --release` | Compile an optimised production binary |
| `cargo test` | Run the test suite |
| `cargo check` | Fast type-check without producing a binary |
| `RUST_LOG=debug cargo run` | Run with verbose debug logging |

The repo also ships a [`justfile`](./justfile) with convenience recipes (`just dev`, `just surreal`, `just reset-db`, `just test`, …). Optional: `brew install just`, then `just --list`. See [docs/CONTRIBUTING.md § just Recipes](./docs/CONTRIBUTING.md#just-recipes-optional).

## Environment variables

The full list — including auth rate-limiting, JWT keys, and SurrealDB connection options — lives in [`.env.example`](./.env.example) and [`docs/RUNBOOK.md`](./docs/RUNBOOK.md#environment-configuration). The brief overview below covers what most contributors need to get a dev instance running.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GREEN_API_INSTANCE_ID` | Yes | — | Instance ID from the Green API dashboard |
| `GREEN_API_TOKEN` | Yes | — | API token shown next to your instance |
| `NEXTAUTH_BACKEND_SECRET` | Yes | — | Shared HMAC secret for NextAuth → backend signing (≥ 32 bytes; generate with `openssl rand -hex 32`) |
| `APP_ENV` | No | unset | Set to `production` to enable strict CORS and disable `/api/test/reset`; `development` / `test` mounts the reset endpoint and unlocks dev-only fixture seeders. For local dev set `APP_ENV=development` (or provide `JWT_KEYS`) — JWT verifier init fails closed otherwise and the service won't boot |
| `DASHBOARD_ORIGIN` | No (required if `APP_ENV=production`) | — | CORS origin for the dashboard (e.g., `https://dashboard.example.com`) |
| `API_BIND_ADDR` | No | `0.0.0.0:8080` | Socket address for the HTTP server |
| `SURREAL_URL` | No | embedded RocksDB at `./data.surreal` | Embedded (`rocksdb://` / `mem://` / `surrealkv://`) or remote (`ws://` / `wss://` / `http://` / `https://`, case-insensitive). Remote schemes require `SURREAL_USER` + `SURREAL_PASS` |
| `SURREAL_USER` / `SURREAL_PASS` | Conditional | — | Required when `SURREAL_URL` is a network scheme. No defaults — boot fails with a typed error if missing, empty, or whitespace-only |
| `SEED_ON_EMPTY` | No | `false` | Seed fixture data when all database tables are empty |
| `RECEIPT_DOWNLOAD_DIR` | No | OS temp dir | Directory where receipt files are saved during OCR |
| `RUST_LOG` | No | `info` | Log verbosity — `debug`, `info`, `warn`, `error` |

## Testing

```bash
cargo test
```

328 tests across 6 binaries (in-memory SurrealDB; no filesystem or external API calls):

| Binary | Tests | What's covered |
|---|---|---|
| `src/lib.rs` (unit) | 36 | Inline `#[cfg(test)]` modules — models, password hashing, HMAC primitives, scheme detection, URL redaction, env-credential gates |
| `tests/api_integration.rs` | 132 | Admin CRUD (groups, members, cycles, payments), bearer auth, JWT verification, validation, soft-delete guards, optimistic concurrency, cross-group constraints, admin-user CRUD, group-admin grants |
| `tests/auth_integration.rs` | 105 | HMAC `verify-credentials` / `ensure-user`, bootstrap idempotency, change-password (wrong-current 400 + token-version invalidation), refresh rotation + reuse detection, dev-fixture seeder gates |
| `tests/parser_tests.rs` | 35 | Amount (`₦`, `#`-normalisation, OCR spacing, `NGN` prefix), sender (primary + fallback labels), bank (line-after, pipe stripping, known-bank fallback), combined receipts |
| `tests/routing_integration.rs` | 12 | Chat-id → group + phone → member resolution; soft-delete handling on routing lookups |
| `tests/ingestion_integration.rs` | 8 | End-to-end receipt ingestion pipeline (Green API webhook → OCR → parse → persist → reply) |

## Known limitations

**Sender name truncation** — The parser captures at most 41 characters for a sender name (`[A-Za-z][A-Za-z ]{2,40}`). Names longer than this are silently truncated. Real Nigerian names fit well within this limit; the cap exists to prevent runaway matches on garbled OCR paragraphs.

**Hyphenated and apostrophe names** — The capture groups only allow letters and spaces. Names like `Adewale-Okonkwo` or `O'Brien` will be truncated at the first non-letter, non-space character (`Adewale` and `O` respectively). This is a known gap to be addressed when such names are encountered in production receipts.

**`#` → `₦` order dependency** — Amount normalisation replaces `#` with `₦` before stripping an `NGN` prefix. A string like `#NGN97,800.00` would survive as `₦NGN97,800.00` rather than `₦97,800.00`. This edge case does not occur on real receipts — no bank produces both artefacts simultaneously.

**OCR accuracy** — All parsing relies on Tesseract output quality. Low-resolution or skewed receipt images will produce degraded OCR text that the parser may not handle correctly. PDFs consistently produce cleaner results than phone photos.

## Notes

- All IDs are SurrealDB-generated strings. The `EntityId` type alias (`String`) is the single point of control for ID representation.
- The Green API free plan only allows sending messages to whitelisted numbers. Upgrade to a Business plan to send replies to groups.
- OCR accuracy depends on receipt image quality. PDFs generally produce cleaner results than photos.
- `idMessage` in the Green API notification JSON lives at the `body` level (sibling of `senderData`/`messageData`), not inside `messageData`. The `NotificationBody` struct reflects this. Placing it on `MessageData` would cause quoted replies to silently fall back to plain (unquoted) sends.
