# Runbook: PoolPay Service

Last Updated: 2026-04-14

Operational guide for running and troubleshooting the PoolPay service in development and production.

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
INFO poolpay: API server listening addr=0.0.0.0:8080
INFO poolpay: Receipt engine started receipt_poll_secs=5
```

### Production

```bash
# Build optimized binary
cargo build --release

# Run in production (set APP_ENV=production and DASHBOARD_ORIGIN)
APP_ENV=production DASHBOARD_ORIGIN=https://dashboard.example.com \
  ./target/release/poolpay
```

## Environment Configuration

### Required Variables

```env
# Green API credentials (from https://green-api.com/en/)
GREEN_API_INSTANCE_ID=your_instance_id_here
GREEN_API_TOKEN=your_api_token_here

# Shared secret for NextAuth → backend HMAC signing
# Must be at least 32 bytes; panics at boot in production if shorter
# Generate with: openssl rand -hex 32
NEXTAUTH_BACKEND_SECRET=your_nextauth_backend_secret_here
```

### Optional Variables

```env
# Environment mode (default: unset)
# - "production" enables strict CORS (requires DASHBOARD_ORIGIN)
# - "development" or "test" mounts the destructive /api/test/reset endpoint
# - Anything else (including unset) is treated as production for the reset gate (fail-closed)
APP_ENV=development

# Bootstrap admin — seeded on first boot if no active admin user exists.
# The seeded user is flagged must_reset_password=true; remove these from
# deployed env once the first rotation has happened.
BOOTSTRAP_ADMIN_EMAIL=admin@example.com
BOOTSTRAP_ADMIN_PASSWORD=change-me-immediately

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

# --- Auth rate limiting (Plan 3 / BE-2) ---
# Per-IP limiter on the full /api/auth/* sub-router — /api/auth/verify-credentials,
# /api/auth/ensure-user, /api/auth/issue, /api/auth/refresh, and /api/auth/logout.
AUTH_RATE_LIMIT_PER_MINUTE=60
AUTH_RATE_LIMIT_BURST=10

# Composite (ip, email) failure limiter on /api/auth/verify-credentials.
# Only failed logins consume quota; successful logins never count.
AUTH_CREDENTIAL_FAILURE_LIMIT=5
AUTH_CREDENTIAL_FAILURE_WINDOW_SECS=900

# Trust X-Forwarded-For as the client IP. Only set when the service sits
# behind a reverse proxy that strips user-supplied copies of that header
# (Fly, Vercel edge, nginx). Default false.
TRUST_PROXY_HEADERS=false

# --- JWT verifier (Plan 3 / BE-3) ---
# RS256 key material. JSON array of entries:
#   [{"kid":"...","active":true,"public_pem":"...","private_pem":"..."}]
# Exactly one entry must be active — that key mints new access tokens;
# inactive entries are accepted during rotation. Required in production.
# JWT_KEYS=...

# Audience / issuer claims the verifier enforces on every access token.
JWT_AUDIENCE=poolpay-api
JWT_ISSUER=poolpay-nextauth

# Access-token lifetime (seconds). Short on purpose — refresh rotates.
JWT_ACCESS_TTL_SECS=900

# Clock-skew tolerance for exp/nbf/iat validation.
JWT_LEEWAY_SECS=60

# Refresh-token lifetime (seconds). Default: 14 days.
JWT_REFRESH_TTL_SECS=1209600
```

### Auth Rate Limiting

Two layers protect the `/api/auth/*` surface (per-IP covers the full sub-router; the composite limiter covers only `verify-credentials`):

- **Per-IP (`tower_governor`)** — a steady quota of `AUTH_RATE_LIMIT_PER_MINUTE`
  requests per minute with a burst of `AUTH_RATE_LIMIT_BURST`, applied to the
  entire `/api/auth/*` sub-router: `/api/auth/verify-credentials`,
  `/api/auth/ensure-user`, `/api/auth/issue`, `/api/auth/refresh`, and
  `/api/auth/logout`. Runs before HMAC / refresh-token verification so
  anonymous floods are dropped cheaply.
- **Composite `(ip, email_normalised)`** — in-handler limiter on
  `/api/auth/verify-credentials`. Token-bucket with burst
  `AUTH_CREDENTIAL_FAILURE_LIMIT` that refills one slot every
  `AUTH_CREDENTIAL_FAILURE_WINDOW_SECS / AUTH_CREDENTIAL_FAILURE_LIMIT`
  seconds — an average rate of `LIMIT` failures per `WINDOW_SECS` with
  burst tolerance. Attackers spacing attempts out can exceed `LIMIT`
  within a rolling `WINDOW_SECS` interval; if you need a strict fixed-
  window guarantee, switch the implementation to a counter. Successful
  logins do not consume quota, so legitimate users are never penalised.

When a limit is hit the response is `429 Too Many Requests` with a
`Retry-After` header in seconds. Legitimate callers should honour it.

**Tuning:** raise the per-IP numbers if a single shared office NAT hits
the limit; lower the credential-failure numbers if brute-force attempts
show up in the `auth_event` log with `reason="rate_limited"`. Values are
loaded at boot — restart the service after edits.

**Trust headers only behind a trusted proxy.** With `TRUST_PROXY_HEADERS=false`
(default), the limiter keys on the direct peer IP. Behind a proxy that
leaves that as the proxy's own IP, set `TRUST_PROXY_HEADERS=true` so the
proxy's `X-Forwarded-For` is honoured — but only if the proxy strips any
client-supplied copy of that header, otherwise callers can spoof their IP.

### JWT Verification + Refresh Rotation

The API verifies RS256 access tokens and rotates refresh tokens. BE-4
wires NextAuth to call this surface; today the extractors ride behind
`#[allow(dead_code)]`.

- **`JWT_KEYS`** — JSON array of keypairs:
  `[{ "kid": "...", "active": true, "public_pem": "...", "private_pem": "..." }]`.
  Exactly one active entry is required. The active key mints tokens
  inside `/api/auth/refresh`; any listed key verifies incoming access
  tokens (staged rotation: publish the new key as inactive, flip
  `active` once the upstream minter has picked it up, then remove
  the old entry one refresh cycle later).
- **`JWT_AUDIENCE` / `JWT_ISSUER`** — enforced on every access token.
  Must match whatever the upstream minter stamps on tokens; a mismatch
  is a hard 401 with no body hint.
- **`JWT_ACCESS_TTL_SECS`** — access-token lifetime. Default 900 (15 min).
  Short on purpose: `token_version` bumps on role changes and refresh
  reuse detection take effect within this window. Keep comfortably above
  360; the FE proactively refreshes at 360s remaining (see poolpay-app
  `auth.ts` `REFRESH_SKEW_SECS`), and a TTL at or below 360s causes every
  session read to hit `/api/auth/refresh`.
- **`JWT_LEEWAY_SECS`** — clock-skew tolerance for exp/nbf/iat. Default 60.
- **`JWT_REFRESH_TTL_SECS`** — refresh-token lifetime. Default 1209600 (14 days).

**Production requires `JWT_KEYS`.** With `APP_ENV=production` the
process panics at boot if `JWT_KEYS` is missing or contains no active
entry. When `APP_ENV` is explicitly set to `development` or `test`, an
ephemeral RSA-2048 keypair is generated on boot and a warning is logged —
this keeps `cargo run` frictionless but is unsafe to deploy (every
restart invalidates every outstanding token). Missing or unrecognised
`APP_ENV` values fail closed, so local setups must set `APP_ENV`
explicitly.

**Refresh rotation = theft detection.** The rotation endpoint follows
OAuth 2.0 Security BCP (RFC 9700) §4.12: every use of a refresh token revokes the original
row and issues a new one in the same family. Presenting an already-
rotated token is treated as evidence of compromise — the entire family
is revoked, the user's `token_version` is bumped (which invalidates any
outstanding access tokens within the 15-minute TTL), and an
`auth_event{refresh_reuse_detected}` is written. The caller receives
a generic 401 so the signal is not exposed to the attacker.

### Production Security

- Set `APP_ENV=production` to enable CORS restrictions
- Set `DASHBOARD_ORIGIN` to the dashboard URL
- Set `NEXTAUTH_BACKEND_SECRET` to a value with ≥ 32 bytes — the process panics at boot in production if it is shorter or unset
- Set `JWT_KEYS` with at least one active RS256 entry — the process panics at boot in production if it is missing (ephemeral-key fallback is disabled outside dev/test)
- The `/api/test/reset` endpoint is fail-closed: it only mounts when `APP_ENV=development` or `APP_ENV=test`. Unset `APP_ENV` on a staging/prod host and the endpoint stays unreachable
- After the bootstrap admin's first password rotation, remove `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD` from deployed env
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
- Admin write endpoints guarded by RS256 admin JWTs — `SuperAdminUser` for group/WhatsApp-link CRUD, `GroupScopedAdmin` for member/cycle/payment/receipt CRUD
- HMAC-gated auth endpoints (`/api/auth/verify-credentials`, `/api/auth/ensure-user`, `/api/auth/issue`) called by NextAuth — signed with `NEXTAUTH_BACKEND_SECRET`
- Dev/test-only `/api/test/reset` endpoint (fail-closed gate on `APP_ENV`)
- CORS configured based on `APP_ENV`

Both tasks are monitored — if either fails, the process exits rather than silently degrading.

## Database

### SurrealDB (Embedded)

The service uses SurrealDB with RocksDB storage, persisting to `./data.surreal/`.

**Initialization:**
- On startup, creates namespace `circle` and database `main`
- If `SEED_ON_EMPTY=true` and all tables are empty, seeds with fixture data (groups, members, cycles, payments)
- If `SEED_ON_EMPTY=true` **and** `APP_ENV` is `development` or `test`, also seeds two dev-only admin users after the bootstrap super-admin runs:
  - `admin1@poolpay.test` — active admin, granted group-admin on fixture group `1`
  - `admin2@poolpay.test` — active admin, no group grants (use this one to exercise grant creation from the dashboard)
  - Both use password `PoolPayQA2026!` and `must_reset_password=false` so login is one-shot
  - Idempotent across restarts; existing users are re-used and admin1's fixture grant is re-asserted if it was manually removed
  - Guard is fail-closed on two axes: either an unset/misconfigured `APP_ENV` **or** `SEED_ON_EMPTY!=true` prevents any writes on this path. Both must be satisfied.

**Resetting the Database (Development Only):**

```bash
# Delete the local database (will reinitialize on next run with SEED_ON_EMPTY=true)
rm -rf ./data.surreal

# Or use the API endpoint (only available when APP_ENV != production)
curl -X POST http://localhost:8080/api/test/reset
```

### Data Model

All IDs are SurrealDB-generated strings (not integers). The `EntityId` type alias (`String`) is the single point of control for ID representation across the codebase.

**Groups** — PoolPay savings groups
```json
{
  "id": "abc123",
  "name": "Family Circle",
  "status": "active",
  "description": "Monthly family pool",
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

All routes return JSON. Admin endpoints require an RS256 admin access token in `Authorization: Bearer <jwt>` — minted by NextAuth via `/api/auth/verify-credentials` and verified against `JWT_KEYS`. Group/WhatsApp-link CRUD requires `role: super_admin`; member/cycle/payment/receipt CRUD requires `role: super_admin` or a matching `group_admin(user_id, group_id)` grant.

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

All require an admin access token (see [API Routes](#api-routes)).

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

### Admin User Management

All routes under `/api/admin/users` require the caller to be a `super_admin`, enforced from the caller's persisted DB role rather than the JWT `role` claim — the access token is only trusted for `sub` and `token_version`. Mutations only invalidate in-flight access tokens when they explicitly bump the target's `token_version`: `PATCH` bumps on role or status change, `DELETE` always bumps, `revoke` bumps (scope shrinks), and `grant` does not (scope grows, existing tokens already fail the group-scope check).

#### POST /api/admin/users

Provision a new admin-tier user (role must be `admin` or `super_admin`). Member users are minted via the social/credentials sign-in path, not this surface. `mustResetPassword` is forced to `true` on the new row so the user is pushed onto the change-password flow on first login.

**Request:**
```json
{
  "email": "new-admin@example.com",
  "initialPassword": "temporary-strong-passphrase",
  "role": "admin"
}
```

Returns `201 Created` with the user record. `409 Conflict` if the email is already in use (both the pre-check and the post-insert UNIQUE race paths collapse to 409).

#### PATCH /api/admin/users/{id}

Flip `role` and/or `status` on an existing user. Requires `version` for optimistic concurrency. Self-mutation is refused (`403`) — another super-admin must act.

**Request:**
```json
{
  "role": "super_admin",
  "status": "active",
  "version": 3
}
```

Both `role` and `status` are optional; at least one field should change for the patch to be meaningful (a no-op still bumps `version` but not `token_version`). Status transitions `active ↔ disabled`; `disabled` revokes every live refresh token for the target and emits `user_disabled`. `active` (re-enable) emits `user_enabled`. Role changes emit `role_changed` with the `before -> after` transition as the reason.

Returns `409 Conflict` on version mismatch or on a concurrent update between SELECT and guarded UPDATE.

#### DELETE /api/admin/users/{id}

Soft-delete (sets `deleted_at`, bumps `token_version`, revokes every refresh token). Self-delete is refused (`403`). The user row and all grants persist for audit. Replaying a delete on an already-deleted row returns `404`.

Returns `204 No Content`.

#### POST /api/admin/users/{id}/groups/{group_id}

Grant `admin`-role user scope over one group. A row in `group_admin` is the RBAC primitive the group-scope extractor looks up — super-admins bypass the extractor, so granting on a super-admin returns `409`. Granting on a member also returns `409` (grants are admin-tier only). Target must be active.

Path-only — no request body. Returns `201 Created`:

```json
{
  "userId": "abc123",
  "groupId": "xyz789",
  "createdAt": "2026-04-22T01:45:00Z",
  "createdBy": "super-admin-id"
}
```

`404` if the target user or group does not exist (or is soft-deleted). `409` if the grant already exists (duplicate `(user_id, group_id)`), if the target is disabled, or if the target role is not `admin`.

Audit: `group_admin_granted` row with `actor_id = caller`, `user_id = target`, `reason = "group:<group_id>"`.

#### DELETE /api/admin/users/{id}/groups/{group_id}

Revoke a previously-issued grant. Two-part mutation: drops the `group_admin` row and bumps the target's `token_version` so in-flight access tokens re-verify on the next call (scope shrank, so cached tokens would otherwise let the user act on the revoked group for up to one access-token TTL). Refresh tokens intentionally survive — the target still has a valid session, they just lost scope on this group.

Returns `204 No Content`. `404` if no matching grant exists (including replay after a successful revoke) — the handler does not silently swallow missing rows because an out-of-band manual revoke is exactly the signal ops should see.

Audit: `group_admin_revoked` row with `actor_id = caller`, `user_id = target`, `reason = "group:<group_id>"`.

### HMAC-Gated Auth Endpoints (NextAuth)

All requests must carry `x-timestamp` (unix seconds, within ±60s) and
`x-signature: sha256=<hex>` where the signature is
`HMAC-SHA256(NEXTAUTH_BACKEND_SECRET, "<ts>.<body>")`. Any signing, replay,
or body-parse failure returns `401`.

#### POST /api/auth/verify-credentials

Verify a password against the stored Argon2id hash. Constant-time regardless
of whether the email exists (dummy-hash verify pre-warmed at boot).

**Request:**
```json
{ "email": "user@example.com", "password": "..." }
```

**Response (200):**
```json
{ "userId": "abc123", "email": "user@example.com", "role": "super_admin", "mustResetPassword": true }
```

Returns `401` on bad password, unknown email, or disabled user.

#### POST /api/auth/ensure-user

Idempotent JIT provisioning for social providers. Never auto-links on email —
a new `(provider, providerSubject)` always creates a fresh user.

**Request:**
```json
{ "provider": "google", "providerSubject": "sub-12345", "email": "user@example.com" }
```

**Response (200):**
```json
{ "userId": "abc123", "email": "user@example.com", "role": "member", "created": true }
```

#### POST /api/auth/issue

HMAC-gated. Mints the initial `(accessToken, refreshToken)` pair for a user
just authenticated via `/api/auth/verify-credentials` (credentials sign-in)
or `/api/auth/ensure-user` (social sign-in). Used by the NextAuth `jwt`
callback on first sign-in so subsequent requests can silent-refresh.

**Request:**
```json
{ "userId": "abc123" }
```

**Response (200):** same shape as `/api/auth/refresh` (`accessToken`,
`refreshToken`, `expiresAt`).

Returns `401` on HMAC failure (rejected inside `HmacVerifiedJson` before
the handler runs — no audit event) and on unknown, disabled, or
soft-deleted users (handler writes a `token_issue_failure` audit event
with `reason` in `{unknown_user, disabled, soft_deleted}`). `500` on DB
or signing failure, also with a `token_issue_failure` audit row
(`reason` in `{db_error, mint_access_failed}`). `400` on empty or
oversized `userId` (>128 chars).

#### POST /api/auth/change-password

Bearer-authenticated. Rotates the caller's password (change path) or attaches
a credentials identity to a social-only account (set path). Bumps
`token_version` so in-flight access tokens invalidate within one access-TTL;
the change path additionally revokes every live refresh token for the user.

**Request:**
```json
{ "currentPassword": "...", "newPassword": "..." }
```

`currentPassword` is required when the user already has a `password_hash`
and is omitted on the social set-path. Body is capped at 5 KiB pre-parse.

**Response:** `204 No Content` on success.

| Status | Body | When |
|---|---|---|
| `204` | — | Success. |
| `400` | `{ "code": "bad_current", "message": "Current password is incorrect." }` | `currentPassword` did not match the stored hash. Typed so the FE can tell a wrong-password failure from a dead session without inference (see [issue #39](https://github.com/Sensei3k/poolpay-api/issues/39)). Writes a `password_change_failure` audit row with `reason=bad_current`. |
| `400` | `{ "error": "..." }` | Shape or policy violation — missing `newPassword`, whitespace-only, oversized (>1 KiB), or `currentPassword` omitted when a hash already exists. Not audited. |
| `401` | `{ "error": "unauthorized" }` | Bearer missing, malformed, expired, or `token_version` stale (post-rotation replay, role change, etc.). **Does not include wrong-current-password.** |
| `409` | `{ "error": "..." }` | Set path only: the `(provider='credentials', provider_subject=email_normalised)` identity is already owned by a different user. No hash is written. |
| `500` | `{ "error": "an internal error occurred" }` | DB or Argon2 hashing failure. |

On success the change path writes `password_changed` (no `reason`) and the
set path writes `password_changed` with `reason=set`. The wrong-password
branch writes `password_change_failure` with `reason=bad_current` before
responding.

### Dev-Only Endpoint

#### POST /api/test/reset

Reset the database to fixture state. Fail-closed: only mounted when
`APP_ENV` is explicitly `development` or `test`. Any other value (including
unset) leaves the route unreachable.

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
INFO poolpay: API server listening addr=0.0.0.0:8080
INFO poolpay: Receipt engine started receipt_poll_secs=5
INFO poolpay::whatsapp: Message sent chat_id=120363023024259121@g.us
INFO poolpay::parser: Parsed receipt sender="John Doe" bank="GTBank" amount="₦50,000.00"
```

Enable debug logging with `RUST_LOG=debug`:

```bash
RUST_LOG=debug cargo run
```

Or target specific modules:

```bash
RUST_LOG=poolpay::parser=debug,poolpay::api=debug cargo run
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
ps aux | grep poolpay
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
Description=PoolPay
After=network.target

[Service]
Type=simple
User=poolpay
WorkingDirectory=/opt/poolpay
EnvironmentFile=/opt/poolpay/.env
ExecStart=/opt/poolpay/poolpay
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable poolpay
sudo systemctl start poolpay
sudo systemctl status poolpay
```

## Troubleshooting Tools

### Capture Raw Green API Responses

Add detailed logging in `src/whatsapp.rs`:
```bash
RUST_LOG=poolpay::whatsapp=debug cargo run
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
pkill -f poolpay
```

This forcefully terminates all matching processes. Data in `./data.surreal` is safe (persisted to disk).

## Support

For detailed development info, see [CONTRIBUTING.md](./CONTRIBUTING.md).

For API integration questions, see the [API Routes](#api-routes) section above.
