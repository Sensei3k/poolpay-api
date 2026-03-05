# rust-receipt-engine

A Rust service that watches a WhatsApp chat or group for payment receipts (images and PDFs), extracts structured data from them using Tesseract OCR, and replies with a formatted summary.

## What it does

1. Polls a WhatsApp number via the Green API for incoming messages
2. Detects image and PDF attachments and downloads them
3. Runs Tesseract OCR to extract raw text (PDFs are first converted to images via `pdftoppm`)
4. Parses the OCR text to extract sender name, bank, and amount
5. Replies to the chat with:
   ```
   ✅ Sender: FULL NAME | Bank: BankName | Amount: ₦97,800.00
   ```

## Project structure

```
src/
├── main.rs        — entry point and polling loop
├── models.rs      — all structs and types
├── whatsapp.rs    — Green API calls (receive, delete, send, download)
├── extractor.rs   — Tesseract OCR for images and PDFs
└── parser.rs      — receipt parsing (sender, bank, amount)
```

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

1. Clone the repo and create a `.env` file in the project root:
   ```
   GREEN_API_INSTANCE_ID=your_instance_id
   GREEN_API_TOKEN=your_api_token
   ```

2. Build and run:
   ```bash
   cargo run
   ```

Downloaded files are saved to `/tmp/receipt_engine/`.

## Notes

- The Green API free plan only allows sending messages to whitelisted numbers. Upgrade to a Business plan to send replies to groups.
- OCR accuracy depends on receipt image quality. PDFs generally produce cleaner results than photos.
