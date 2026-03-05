# rust-receipt-engine

A Rust service that watches a WhatsApp chat or group for payment receipts (images and PDFs), extracts structured data from them using Tesseract OCR, and replies with a formatted summary.

## What it does

1. Polls a WhatsApp number via the Green API for incoming messages
2. Detects image and PDF attachments and downloads them
3. Runs Tesseract OCR to extract raw text (PDFs are first converted to images via `pdftoppm`)
4. Parses the OCR text to extract sender name, bank, and amount
5. Replies to the chat with:
   ```
   ✅ Sender: FULL NAME
   Bank: BankName
   Amount: ₦97,800.00
   ```

## Project structure

```
src/
├── lib.rs         — crate root; declares all public modules
├── main.rs        — entry point and polling loop (thin — orchestration only)
├── models.rs      — all structs and types
├── whatsapp.rs    — Green API calls (receive, delete, send, download)
├── extractor.rs   — Tesseract OCR for images and PDFs
└── parser.rs      — receipt parsing (sender, bank, amount)
tests/
└── parser_tests.rs — integration tests for the parser module
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
   Fill in your credentials from the [Green API dashboard](https://green-api.com/).

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
| `RECEIPT_DOWNLOAD_DIR` | No | OS temp dir | Directory where receipt files are saved during OCR |
| `RUST_LOG` | No | `info` | Log verbosity — `debug`, `info`, `warn`, `error` |

## Notes

- The Green API free plan only allows sending messages to whitelisted numbers. Upgrade to a Business plan to send replies to groups.
- OCR accuracy depends on receipt image quality. PDFs generally produce cleaner results than photos.
