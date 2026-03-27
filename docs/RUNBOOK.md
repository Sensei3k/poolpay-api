# Runbook: Receipt Engine Service

Last Updated: 2026-03-27

Operational guide for running and troubleshooting the Receipt Engine service in development and production.

## Quick Start

### Development

```bash
# Install dependencies (see CONTRIBUTING.md)
brew install tesseract poppler pkgconf  # macOS

# Set up environment
cp .env.example .env
# Edit .env with your credentials

# Run the service
cargo run

# Or with debug logging
RUST_LOG=debug cargo run
```

Service will be ready when you see:
```
INFO receipt_engine: API server listening addr=0.0.0.0:8080
INFO receipt_engine: Receipt engine started receipt_poll_secs=5 confirm_poll_secs=30
```

### Production

```bash
# Build optimized binary
cargo build --release

# Run in production (set APP_ENV=production and DASHBOARD_ORIGIN)
APP_ENV=production DASHBOARD_ORIGIN=https://dashboard.example.com \
  ./target/release/receipt-engine
```

## Environment Configuration

### Required Variables

```env
# Green API credentials (from https://green-api.com/en/)
GREEN_API_INSTANCE_ID=7103538567
GREEN_API_TOKEN=68e409f84c9f47549a370f0ca1ba5bd01122559cdfce45a180

# Google Cloud (service account credentials and spreadsheet)
GOOGLE_SERVICE_ACCOUNT_KEY_PATH=/path/to/service-account.json
GOOGLE_SPREADSHEET_ID=1U5Dgh6F_p5LwYzV4DXmiZDLkRGy9cN271suEcrZj83E
```

### Optional Variables

```env
# Environment mode (default: development)
# Set to "production" to enable CORS restrictions and disable /api/test/reset
APP_ENV=development

# CORS origin for production (required if APP_ENV=production)
DASHBOARD_ORIGIN=https://dashboard.example.com

# HTTP server binding (default: 0.0.0.0:8080)
API_BIND_ADDR=0.0.0.0:8080

# Temporary receipt file storage (default: OS temp directory)
RECEIPT_DOWNLOAD_DIR=/tmp/receipts

# Log verbosity (default: info)
# Options: debug, info, warn, error
RUST_LOG=info
```

### Production Security

- Set `APP_ENV=production` to enable CORS restrictions
- Set `DASHBOARD_ORIGIN` to the dashboard URL
- The `/api/test/reset` endpoint is disabled in production
- Never commit `.env` with real credentials
- Store `GOOGLE_SERVICE_ACCOUNT_KEY_PATH` securely (not in git)

## Service Architecture

The service runs three concurrent tasks:

### Receipt Loop (Main Task)
- Polls Green API every 5 seconds
- Downloads receipt attachments (images and PDFs)
- Runs Tesseract OCR to extract text
- Parses extracted text for sender, bank, and amount
- Sends formatted reply back to WhatsApp
- Writes row to Google Sheet
- Acknowledges and deletes notification

### Confirmation Loop (Async Task)
- Polls Google Sheet every 30 seconds
- Checks for rows marked "Confirmed" (checkbox = TRUE) in column D
- Sends "✅ Acknowledged" reply as quoted message to original chat
- Writes RFC 3339 timestamp to column F when acknowledged

### API Server (Async Task)
- Serves HTTP API on port 8080
- Routes for members, cycles, and payments management
- Dev-only `/api/test/reset` endpoint to reset database to fixture state
- CORS configured based on `APP_ENV`

All three tasks are monitored — if any fails, the process exits rather than silently degrading.

## Database

### SurrealDB (Embedded)

The service uses SurrealDB with RocksDB storage, persisting to `./data.surreal/`.

**Initialization:**
- On startup, checks if database is empty
- If empty, seeds with fixture data (members, cycles, payments)
- Creates namespace `circle` and database `main`

**Resetting the Database (Development Only):**

```bash
# Delete the local database (will reinitialize on next run)
rm -rf ./data.surreal

# Or use the API endpoint (only available when APP_ENV != production)
curl -X POST http://localhost:8080/api/test/reset
```

### Data Model

**Members** — Ajo circle participants
```json
{
  "id": 1,
  "name": "Adaeze Okonkwo",
  "phone": "2348101234567",
  "position": 1,
  "status": "active"
}
```

**Cycles** — Payment rounds (monthly)
```json
{
  "id": 1,
  "cycle_number": 1,
  "start_date": "2026-01-01",
  "end_date": "2026-01-31",
  "contribution_per_member": 1000000,
  "total_amount": 6000000,
  "recipient_member_id": 1,
  "status": "closed"
}
```

**Payments** — Individual contributions
```json
{
  "id": 1234567890,
  "member_id": 1,
  "cycle_id": 3,
  "amount": 1000000,
  "currency": "NGN",
  "payment_date": "2026-03-02"
}
```

## API Routes

All routes return JSON.

### GET /api/members

List all ajo circle members.

**Response:**
```json
[
  {
    "id": 1,
    "name": "Adaeze Okonkwo",
    "phone": "2348101234567",
    "position": 1,
    "status": "active"
  }
]
```

### GET /api/cycles

List all payment cycles.

**Response:**
```json
[
  {
    "id": 1,
    "cycleNumber": 1,
    "startDate": "2026-01-01",
    "endDate": "2026-01-31",
    "contributionPerMember": 1000000,
    "totalAmount": 6000000,
    "recipientMemberId": 1,
    "status": "closed"
  }
]
```

### GET /api/payments?cycleId=3

List all payments, optionally filtered by cycle.

**Query Parameters:**
- `cycleId` (optional, integer) — filter by cycle ID

**Response:**
```json
[
  {
    "id": 1234567890,
    "memberId": 1,
    "cycleId": 3,
    "amount": 1000000,
    "currency": "NGN",
    "paymentDate": "2026-03-02"
  }
]
```

### POST /api/payments

Create a new payment record.

**Request:**
```json
{
  "member_id": 1,
  "cycle_id": 3,
  "amount": 1000000,
  "currency": "NGN",
  "payment_date": "2026-03-02"
}
```

**Response:**
```json
{
  "id": 1234567891,
  "memberId": 1,
  "cycleId": 3,
  "amount": 1000000,
  "currency": "NGN",
  "paymentDate": "2026-03-02"
}
```

Returns `201 Created` on success, `400` on validation error, `404` if member/cycle doesn't exist.

### DELETE /api/payments/{member_id}/{cycle_id}

Delete all payments for a member in a cycle.

**Response:**
```json
{
  "deleted": 3
}
```

### POST /api/test/reset (Development Only)

Reset the database to fixture state. Only available when `APP_ENV != production`.

**Response:**
```json
{
  "message": "Database reset to fixture state"
}
```

## Health Check

The API server becomes ready when it starts listening on the configured address. Check connectivity:

```bash
curl http://localhost:8080/api/members
```

If it responds with JSON, the service is healthy.

## Logging

Log output includes structured fields for debugging:

```
INFO receipt_engine: API server listening addr=0.0.0.0:8080
INFO receipt_engine: Receipt engine started receipt_poll_secs=5 confirm_poll_secs=30
INFO receipt_engine::whatsapp: Message sent chat_id=120363023024259121@g.us
INFO receipt_engine::parser: Parsed receipt sender="John Doe" bank="GTBank" amount="₦50,000.00"
```

Enable debug logging with `RUST_LOG=debug`:

```bash
RUST_LOG=debug cargo run
```

Or target specific modules:

```bash
RUST_LOG=receipt_engine::sheets=debug,receipt_engine::parser=debug cargo run
```

## Common Issues & Fixes

### Service Won't Start

**Error: "GREEN_API_INSTANCE_ID must be set in .env"**

```bash
# Check .env exists and has all required variables
cat .env | grep GREEN_API

# If missing, copy the template and fill in credentials
cp .env.example .env
# Edit .env with your actual values
```

**Error: "Failed to initialise SheetsClient"**

Causes:
1. `GOOGLE_SERVICE_ACCOUNT_KEY_PATH` file doesn't exist or isn't readable
2. Service account email not shared with the spreadsheet
3. Key file is corrupted or has wrong format

Fix:
```bash
# Verify key file exists
ls -la /path/to/service-account.json

# Re-share spreadsheet with service account (Editor access required)
# Service account email is in the JSON key file under "client_email"
```

**Error: "tesseract not found"**

```bash
# macOS
brew install tesseract poppler pkgconf

# Ubuntu/Debian
sudo apt-get install -y libtesseract-dev poppler-utils pkg-config

# Verify installation
tesseract --version
```

### Service Crashes or Exits

The service monitors three concurrent tasks. If any crashes, the entire process exits (fail-fast design).

Check logs for the failing task:
```bash
RUST_LOG=debug cargo run 2>&1 | grep -i error
```

Common causes:
- Green API credentials invalid or instance has no balance
- Google Sheet quota exceeded or service account revoked
- Tesseract missing or corrupted
- Disk full (for `./data.surreal`)

### Receipts Not Being Processed

**Check logs:**
```bash
RUST_LOG=debug cargo run
```

Look for:
- "No new messages" — Green API queue is empty (normal)
- "Error polling Green API" — credential or network issue
- "OCR failed" — Tesseract error or unsupported image format
- "Failed to write row to sheet" — spreadsheet permissions or quota

**Check Green API balance:**

Visit https://green-api.com/ and verify your instance has available credits.

**Check Google Sheets permissions:**

1. Verify service account email has Editor access to the spreadsheet
2. Verify sheet has correct column headers in row 1:
   `Sender | Bank | Amount | Confirmed | MessageID | AcknowledgedAt | ChatID`

### Database Corruption

If `./data.surreal` becomes corrupted:

```bash
# Delete and reinitialize
rm -rf ./data.surreal
cargo run  # Will seed with fixture data on startup
```

**Warning:** This deletes all stored payment records. Back up important data first.

### High Memory Usage

SurrealDB with RocksDB may use more RAM as the dataset grows. Monitor with:

```bash
ps aux | grep receipt-engine
```

To reduce memory overhead:
1. Archive old payment records to an external database
2. Create a new cycle and reset the database
3. Run on a machine with more available RAM

### API Not Responding

```bash
# Check if server is listening
lsof -i :8080

# If not listening, check logs for startup errors
RUST_LOG=debug cargo run

# If port is in use by another process, either:
# 1. Kill the other process
# 2. Change API_BIND_ADDR to a different port
API_BIND_ADDR=0.0.0.0:9000 cargo run
```

## Performance Tuning

### Reducing Poll Frequency

In `src/main.rs`, modify the constants:
```rust
const RECEIPT_POLL_SECS: u64 = 5;      // Receipt polling (default: 5s)
const CONFIRM_POLL_SECS: u64 = 30;     // Confirmation polling (default: 30s)
```

Longer intervals reduce API calls and network bandwidth, but increase latency.

### Optimizing OCR

OCR accuracy and speed depend on image quality:
- **PDFs:** Consistently high quality, clean text extraction
- **Photos:** Quality varies; best results with well-lit, straight-on receipt images
- **Low-res or skewed images:** May fail to extract correct amounts/names

Advise users to:
1. Send PDFs when possible (use WhatsApp's document upload)
2. Take photos in good lighting, straight-on
3. Avoid blurry or rotated images

## Monitoring in Production

### Key Metrics to Watch

1. **API latency** — Should be < 100ms for GET endpoints
2. **Receipt processing time** — Typically 2-10s (OCR is the bottleneck)
3. **Google Sheets write errors** — Check quota usage in GCP console
4. **Green API errors** — Check instance balance and plan limits
5. **Database size** — Monitor `./data.surreal` growth

### Deployment

For production, consider:
1. Running in a container (Docker)
2. Using a process manager (systemd, supervisord)
3. Centralizing logs (ELK, Datadog, etc.)
4. Setting up alerts for process crashes
5. Backing up `./data.surreal` regularly

Example systemd service file:

```ini
[Unit]
Description=Receipt Engine
After=network.target

[Service]
Type=simple
User=receipt-engine
WorkingDirectory=/opt/receipt-engine
EnvironmentFile=/opt/receipt-engine/.env
ExecStart=/opt/receipt-engine/receipt-engine
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable receipt-engine
sudo systemctl start receipt-engine
sudo systemctl status receipt-engine
```

## Troubleshooting Tools

### Capture Raw Green API Responses

Add detailed logging in `src/whatsapp.rs`:
```bash
RUST_LOG=receipt_engine::whatsapp=debug cargo run
```

### Test Google Sheets Connection

```bash
# Create a small test script
cat > test_sheets.rs << 'EOF'
use receipt_engine::sheets::SheetsClient;

#[tokio::main]
async fn main() {
    let client = SheetsClient::new(
        "/path/to/service-account.json",
        "your-spreadsheet-id"
    ).await.expect("Failed to initialize");

    let rows = client.fetch_rows().await.expect("Failed to fetch");
    println!("Fetched {} rows", rows.len());
}
EOF

rustc test_sheets.rs && ./test_sheets
```

### Test Tesseract OCR

```bash
# Verify Tesseract works on a sample image
tesseract sample-receipt.jpg output.txt
cat output.txt
```

## Restart Procedures

### Graceful Restart

The service can be stopped with Ctrl+C and restarted without data loss:

```bash
# Stop (Ctrl+C or kill)
# Restart
cargo run
```

State is persisted to `./data.surreal`, so the database is preserved.

### Emergency Stop

If the process is hung:

```bash
pkill -f receipt-engine
```

This forcefully terminates all matching processes. Data in `./data.surreal` is safe (persisted to disk).

## Support

For detailed development info, see [CONTRIBUTING.md](./CONTRIBUTING.md).

For API integration questions, see the [API Routes](#api-routes) section above.
