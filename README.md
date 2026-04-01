# rust-receipt-engine

A Rust service that manages Ajo savings circles with a REST API and WhatsApp receipt OCR. Built with Axum, SurrealDB, and Green API.

## What it does

**REST API** for managing multi-group Ajo circles:
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
│   ├── auth.rs    — AdminToken extractor (Bearer token via ADMIN_TOKEN)
│   ├── handlers.rs — HTTP handlers (GET/POST/PATCH/DELETE)
│   └── models.rs  — API request/response types, EntityId alias, DB/API structs
tests/
├── parser_tests.rs     — 28 parser integration tests
└── api_integration.rs  — 75 API route and database integration tests
```

The project uses a **lib + bin** layout: `src/lib.rs` exposes all modules as a library crate (`receipt_engine`), and `src/main.rs` is the binary entry point that imports from it. This allows `tests/` to import the public API directly, keeping integration tests separate from source files.

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
   Fill in your Green API credentials and admin token (see [Environment variables](#environment-variables) below).

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

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GREEN_API_INSTANCE_ID` | Yes | — | Instance ID from the Green API dashboard |
| `GREEN_API_TOKEN` | Yes | — | API token shown next to your instance |
| `ADMIN_TOKEN` | Yes | — | Bearer token for `/api/admin/*` endpoints. Generate with `openssl rand -hex 32` |
| `APP_ENV` | No | `development` | Set to `production` to enable CORS restrictions and disable `/api/test/reset` |
| `DASHBOARD_ORIGIN` | No (required if `APP_ENV=production`) | — | CORS origin for the dashboard (e.g., `https://dashboard.example.com`) |
| `API_BIND_ADDR` | No | `0.0.0.0:8080` | Socket address for the HTTP server |
| `SEED_ON_EMPTY` | No | `false` | Set to `true` to seed fixture data when all database tables are empty |
| `RECEIPT_DOWNLOAD_DIR` | No | OS temp dir | Directory where receipt files are saved during OCR |
| `RUST_LOG` | No | `info` | Log verbosity — `debug`, `info`, `warn`, `error` |

## Testing

```bash
cargo test
```

106 tests total — 3 models + 28 parser + 75 API integration:

**Models** (`src/models.rs` — `#[cfg(test)]` module, 3 tests):

| Group | Tests | What's covered |
|---|---|---|
| `notification_id_message` | 3 | `idMessage` deserialises from body level (not messageData), absent field is `None`, `MessageData` does not contain `idMessage` |

**Parser** (`tests/parser_tests.rs`, 28 tests):

| Group | Tests | What's covered |
|---|---|---|
| Amount | 11 | `₦` symbol, `#` → `₦` normalisation, mid-number OCR spaces, `NGN` prefix, trailing zeros, no decimal, absent amount |
| Sender | 8 | Primary label, case insensitivity, fallback labels (`Sender:`, `From:`, `Originator:`), OCR garbage after name, absent sender, whitespace trimming |
| Bank | 7 | Next-line extraction, pipe-separator stripping, known-bank fallback, case insensitivity, absent bank, leading-space trimming |
| Combined | 2 | Full realistic receipts (OPay style, heavy OCR noise) |

**API Integration** (`tests/api_integration.rs`, 75 tests):

Covers admin CRUD for groups, members, cycles, and payments including auth (bearer token validation, missing/invalid token rejection), validation (empty names, invalid dates, negative amounts), soft delete guards (cannot delete group with members, member with active cycles), optimistic concurrency (version mismatch conflicts), cross-group validation (member and cycle must belong to same group), and fixture seeding.

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
