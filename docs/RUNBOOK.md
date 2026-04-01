# Runbook: Receipt Engine Service

Last Updated: 2026-04-01

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
INFO receipt_engine: Receipt engine started receipt_poll_secs=5
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

# Admin bearer token for all /api/admin/* endpoints
# Generate with: openssl rand -hex 32
ADMIN_TOKEN=your_admin_token_here
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

# Seed fixture data when all database tables are empty (default: false)
SEED_ON_EMPTY=true

# Temporary receipt file storage (default: OS temp directory)
RECEIPT_DOWNLOAD_DIR=/tmp/receipts

# Log verbosity (default: info)
# Options: debug, info, warn, error
RUST_LOG=info
```

### Production Security

- Set `APP_ENV=production` to enable CORS restrictions
- Set `DASHBOARD_ORIGIN` to the dashboard URL
- Set a strong `ADMIN_TOKEN` (at least 32 hex characters)
- The `/api/test/reset` endpoint is disabled in production
- Never commit `.env` with real credentials

## Service Architecture

The service runs two concurrent tasks:

### Receipt Loop (Main Task)
- Polls Green API every 5 seconds
- Downloads receipt attachments (images and PDFs)
- Runs Tesseract OCR to extract text
- Parses extracted text for sender, bank, and amount
- Sends formatted reply back to WhatsApp
- Acknowledges and deletes notification

### API Server (Async Task)
- Serves HTTP API on port 8080
- Public read endpoints for groups, members, cycles, and payments
- Admin write endpoints (behind `ADMIN_TOKEN` bearer auth) for CRUD operations
- Dev-only `/api/test/reset` endpoint to reset database to fixture state
- CORS configured based on `APP_ENV`

Both tasks are monitored — if either fails, the process exits rather than silently degrading.

## Database

### SurrealDB (Embedded)

The service uses SurrealDB with RocksDB storage, persisting to `./data.surreal/`.

**Initialization:**
- On startup, creates namespace `circle` and database `main`
- If `SEED_ON_EMPTY=true` and all tables are empty, seeds with fixture data (groups, members, cycles, payments)

**Resetting the Database (Development Only):**

```bash
# Delete the local database (will reinitialize on next run with SEED_ON_EMPTY=true)
rm -rf ./data.surreal

# Or use the API endpoint (only available when APP_ENV != production)
curl -X POST http://localhost:8080/api/test/reset
```

### Data Model

All IDs are SurrealDB-generated strings (not integers). The `EntityId` type alias (`String`) is the single point of control for ID representation across the codebase.

**Groups** — Ajo savings circles
```json
{
  "id": "abc123",
  "name": "Family Circle",
  "status": "active",
  "description": "Monthly family ajo",
  "createdAt": "2026-01-01T00:00:00Z",
  "updatedAt": "2026-01-01T00:00:00Z",
  "version": 1
}
```

**Members** — Circle participants (scoped to a group)
```json
{
  "id": "def456",
  "name": "Adaeze Okonkwo",
  "phone": "2348101234567",
  "position": 1,
  "status": "active",
  "groupId": "abc123",
  "createdAt": "2026-01-01T00:00:00Z",
  "updatedAt": "2026-01-01T00:00:00Z",
  "version": 1
}
```

**Cycles** — Payment rounds (monthly, scoped to a group)
```json
{
  "id": "ghi789",
  "cycleNumber": 1,
  "startDate": "2026-01-01",
  "endDate": "2026-01-31",
  "contributionPerMember": 1000000,
  "totalAmount": 6000000,
  "recipientMemberId": "def456",
  "status": "closed",
  "groupId": "abc123",
  "createdAt": "2026-01-01T00:00:00Z",
  "updatedAt": "2026-01-01T00:00:00Z",
  "version": 1
}
```

**Payments** — Individual contributions
```json
{
  "id": "jkl012",
  "memberId": "def456",
  "cycleId": "ghi789",
  "amount": 1000000,
  "currency": "NGN",
  "paymentDate": "2026-03-02",
  "createdAt": "2026-01-15T00:00:00Z",
  "updatedAt": "2026-01-15T00:00:00Z"
}
```

**Soft delete:** Groups, members, and payments use soft delete (`deletedAt` timestamp). Cycles use hard delete (but only when they have no payments).

## API Routes

All routes return JSON. Admin endpoints require `Authorization: Bearer <ADMIN_TOKEN>` header.

### Public Read Endpoints

#### GET /api/groups

List all active groups (soft-deleted groups are excluded).

#### GET /api/members?groupId={id}

List all active members. Optional `groupId` query parameter filters by group.

#### GET /api/cycles?groupId={id}

List all cycles. Optional `groupId` query parameter filters by group.

#### GET /api/payments?cycleId={id}

List all active payments. Optional `cycleId` query parameter filters by cycle.

### Admin Group Endpoints

All require `Authorization: Bearer <ADMIN_TOKEN>`.

#### POST /api/admin/groups

Create a new group.

**Request:**
```json
{
  "name": "Family Circle",
  "description": "Optional description"
}
```

Returns `201 Created`.

#### PATCH /api/admin/groups/{id}

Update a group. Requires `version` for optimistic concurrency control.

**Request:**
```json
{
  "name": "New Name",
  "status": "closed",
  "description": "Updated description",
  "version": 1
}
```

Returns `409 Conflict` on version mismatch.

#### DELETE /api/admin/groups/{id}

Soft-delete a group. Fails if the group still has active members or cycles.

Returns `204 No Content`.

### Admin Member Endpoints

#### POST /api/admin/groups/{gid}/members

Create a member in a group. Phone number must be unique within the group.

**Request:**
```json
{
  "name": "Adaeze Okonkwo",
  "phone": "2348101234567",
  "position": 1,
  "notes": "Optional notes",
  "joinedAt": "2026-01-01"
}
```

Returns `201 Created`.

#### PATCH /api/admin/members/{id}

Update a member. Requires `version` for optimistic concurrency control.

#### DELETE /api/admin/members/{id}

Soft-delete a member. Fails if the member is the recipient of an active cycle.

Returns `204 No Content`.

### Admin Cycle Endpoints

#### POST /api/admin/groups/{gid}/cycles

Create a cycle in a group. `totalAmount` is auto-calculated from `contributionPerMember` and active member count.

**Request:**
```json
{
  "cycleNumber": 1,
  "startDate": "2026-01-01",
  "endDate": "2026-01-31",
  "contributionPerMember": 1000000,
  "recipientMemberId": "def456",
  "notes": "Optional notes"
}
```

Returns `201 Created`.

#### PATCH /api/admin/cycles/{id}

Update a cycle. Requires `version` for optimistic concurrency control.

#### DELETE /api/admin/cycles/{id}

Hard-delete a cycle. Fails if the cycle has any payments.

Returns `204 No Content`.

### Payment Endpoints

#### POST /api/payments

Create a new payment. Requires admin auth. Member and cycle must belong to the same group.

**Request:**
```json
{
  "memberId": "def456",
  "cycleId": "ghi789",
  "amount": 1000000,
  "currency": "NGN",
  "paymentDate": "2026-03-02"
}
```

Returns `201 Created`.

#### DELETE /api/payments/{member_id}/{cycle_id}

Soft-delete all payments for a member in a cycle. Requires admin auth.

Returns `204 No Content`.

### Dev-Only Endpoint

#### POST /api/test/reset

Reset the database to fixture state. Only available when `APP_ENV != production`.

Returns `200 OK`.

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
INFO receipt_engine: Receipt engine started receipt_poll_secs=5
INFO receipt_engine::whatsapp: Message sent chat_id=120363023024259121@g.us
INFO receipt_engine::parser: Parsed receipt sender="John Doe" bank="GTBank" amount="₦50,000.00"
```

Enable debug logging with `RUST_LOG=debug`:

```bash
RUST_LOG=debug cargo run
```

Or target specific modules:

```bash
RUST_LOG=receipt_engine::parser=debug,receipt_engine::api=debug cargo run
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

The service monitors two concurrent tasks. If either crashes, the entire process exits (fail-fast design).

Check logs for the failing task:
```bash
RUST_LOG=debug cargo run 2>&1 | grep -i error
```

Common causes:
- Green API credentials invalid or instance has no balance
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

**Check Green API balance:**

Visit https://green-api.com/ and verify your instance has available credits.

### Database Corruption

If `./data.surreal` becomes corrupted:

```bash
# Delete and reinitialize
rm -rf ./data.surreal
SEED_ON_EMPTY=true cargo run  # Will seed with fixture data on startup
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

In `src/main.rs`, modify the constant:
```rust
const RECEIPT_POLL_SECS: u64 = 5;      // Receipt polling (default: 5s)
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
3. **Green API errors** — Check instance balance and plan limits
4. **Database size** — Monitor `./data.surreal` growth

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
