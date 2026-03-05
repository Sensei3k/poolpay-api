# rust-receipt-engine

A Rust service that watches a WhatsApp chat or group for payment receipts (images and PDFs), extracts structured data from them using Tesseract OCR, and replies with a formatted summary.

## What it does

1. Polls a WhatsApp number via the Green API for incoming messages
2. Detects image and PDF attachments and downloads them
3. Runs Tesseract OCR to extract raw text (PDFs are first converted to images via `pdftoppm`)
4. Parses the OCR text to extract sender name, bank, and amount
5. Replies to the chat with a formatted summary:
   ```
   ✅ Sender: FULL NAME
   Bank: BankName
   Amount: ₦97,800.00
   ```
6. Writes a row to a Google Sheet for record-keeping and human review
7. Every 30 seconds, checks the sheet for rows the user has marked **Confirmed** and sends a quoted "Acknowledged" reply back to the original WhatsApp chat

## Project structure

```
src/
├── lib.rs         — crate root; declares all public modules
├── main.rs        — entry point; receipt loop (5 s) + confirmation loop (30 s)
├── models.rs      — all structs and types
├── whatsapp.rs    — Green API calls (receive, delete, send, download, quote-reply)
├── extractor.rs   — Tesseract OCR for images and PDFs
├── parser.rs      — receipt parsing (sender, bank, amount)
└── sheets.rs      — Google Sheets v4 REST client (append, fetch, mark-acknowledged)
tests/
├── parser_tests.rs — 28 integration tests for the parser module
└── (sheets unit tests live in src/sheets.rs as a #[cfg(test)] module)
```

The project uses a **lib + bin** layout: `src/lib.rs` exposes all modules as a library crate (`receipt_engine`), and `src/main.rs` is the binary entry point that imports from it. This allows `tests/` to import the public API directly, keeping integration tests separate from source files.

New modules should be added to `src/lib.rs` as `pub mod <name>` and tested in a corresponding `tests/<name>_tests.rs` file.

## Google Sheets integration

### Sheet setup

Create a Google Sheet with the following headers in row 1:

| A | B | C | D | E | F | G |
|---|---|---|---|---|---|---|
| Sender | Bank | Amount | Confirmed | MessageID | AcknowledgedAt | ChatID |

Column D must be formatted as a **checkbox** (Insert → Checkbox in Google Sheets). The engine reads it as the string `"TRUE"` or `"FALSE"`.

The engine writes columns A, B, C, E, and G automatically. Column D is for you to tick. Column F is written by the engine when it sends the acknowledgement reply.

### Service account setup

1. Create a GCP project and enable the **Google Sheets API**
2. Create a **Service Account** and download the JSON key file
3. Share your spreadsheet with the service account email (`... @...iam.gserviceaccount.com`) — Editor access is required
4. Set `GOOGLE_SERVICE_ACCOUNT_KEY_PATH` in `.env` to the path of the JSON key file
5. Set `GOOGLE_SPREADSHEET_ID` in `.env` to the spreadsheet ID or full URL — both forms work:
   - `1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms`
   - `https://docs.google.com/spreadsheets/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms/edit`

### How confirmation works

```
Receipt arrives
    ↓
Engine parses → replies ✅ summary → writes row to sheet (D and F blank)
    ↓
You tick D (Confirmed checkbox) in the sheet
    ↓
Confirmation loop (every 30 s) detects D="TRUE", F=""
    ↓
Engine sends "✅ Acknowledged" as a quoted WhatsApp reply
    ↓
Engine writes RFC 3339 timestamp to column F — row is never reprocessed
```

Acknowledgement is idempotent — if the write to column F fails after the reply is sent, the next poll will attempt to send again. The user sees a duplicate reply in that case, but no receipts are silently lost.

## Prerequisites

- [Rust](https://rustup.rs/)
- [Tesseract OCR](https://github.com/tesseract-ocr/tesseract)
- [Poppler](https://poppler.freedesktop.org/) (for `pdftoppm`)
- [pkgconf](https://github.com/pkgconf/pkgconf)
- A [Green API](https://green-api.com/) account with an active WhatsApp instance
- A Google Cloud project with the Sheets API enabled and a service account key

On macOS:
```bash
brew install tesseract poppler pkgconf
```

## Setup

1. Clone the repo and copy the env template:
   ```bash
   cp .env.example .env
   ```
   Fill in your Green API credentials and Google Sheets credentials (see [Google Sheets integration](#google-sheets-integration) above).

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
| `GOOGLE_SERVICE_ACCOUNT_KEY_PATH` | Yes | — | Path to the GCP service account JSON key file |
| `GOOGLE_SPREADSHEET_ID` | Yes | — | Bare spreadsheet ID or full Google Sheets URL |
| `RECEIPT_DOWNLOAD_DIR` | No | OS temp dir | Directory where receipt files are saved during OCR |
| `RUST_LOG` | No | `info` | Log verbosity — `debug`, `info`, `warn`, `error` |

## Testing

```bash
cargo test
```

48 tests total — 28 parser integration tests + 20 sheets unit tests:

**Sheets** (`src/sheets.rs` — `#[cfg(test)]` module, 20 tests):

| Group | Tests | What's covered |
|---|---|---|
| `extract_spreadsheet_id` | 5 | Bare ID passthrough, full URL `/edit`, `#gid` anchor, `?usp` query param, combined |
| `col_str` | 6 | Valid strings, out-of-bounds index, JSON null, boolean, number |
| `pending_from_rows` | 9 | Empty input, header-only, confirmed+unacknowledged included, already-acknowledged excluded, not-confirmed excluded, row index arithmetic, mixed rows, short rows with missing trailing cols, non-array entries skipped |

**Parser** (`tests/parser_tests.rs`, 28 tests):

| Group | Tests | What's covered |
|---|---|---|
| Amount | 11 | `₦` symbol, `#` → `₦` normalisation, mid-number OCR spaces, `NGN` prefix, trailing zeros, no decimal, absent amount |
| Sender | 8 | Primary label, case insensitivity, fallback labels (`Sender:`, `From:`, `Originator:`), OCR garbage after name, absent sender, whitespace trimming |
| Bank | 7 | Next-line extraction, pipe-separator stripping, known-bank fallback, case insensitivity, absent bank, leading-space trimming |
| Combined | 2 | Full realistic receipts (OPay style, heavy OCR noise) |

## Known limitations

**Sender name truncation** — The parser captures at most 41 characters for a sender name (`[A-Za-z][A-Za-z ]{2,40}`). Names longer than this are silently truncated. Real Nigerian names fit well within this limit; the cap exists to prevent runaway matches on garbled OCR paragraphs.

**Hyphenated and apostrophe names** — The capture groups only allow letters and spaces. Names like `Adewale-Okonkwo` or `O'Brien` will be truncated at the first non-letter, non-space character (`Adewale` and `O` respectively). This is a known gap to be addressed when such names are encountered in production receipts.

**`#` → `₦` order dependency** — Amount normalisation replaces `#` with `₦` before stripping an `NGN` prefix. A string like `#NGN97,800.00` would survive as `₦NGN97,800.00` rather than `₦97,800.00`. This edge case does not occur on real receipts — no bank produces both artefacts simultaneously.

**OCR accuracy** — All parsing relies on Tesseract output quality. Low-resolution or skewed receipt images will produce degraded OCR text that the parser may not handle correctly. PDFs consistently produce cleaner results than phone photos.

## Notes

- The Green API free plan only allows sending messages to whitelisted numbers. Upgrade to a Business plan to send replies to groups.
- OCR accuracy depends on receipt image quality. PDFs generally produce cleaner results than photos.
