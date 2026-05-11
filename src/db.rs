use std::sync::Arc;

use surrealdb::Surreal;
use surrealdb::engine::any::{Any, connect};
use surrealdb::opt::auth::Root;
use tracing::info;

use crate::api::models::{
    CycleContent, DbCycle, DbGroup, DbGroupLink, DbMember, DbPayment, DbReceipt, GroupContent,
    MemberContent, PaymentContent, ReceiptContent,
};

/// The shared SurrealDB connection type — passed as Axum state.
///
/// Uses the `any` engine so the same handle can back either an embedded
/// RocksDB file or a remote SurrealDB server reached over WebSocket
/// (`ws://`, `wss://`) or HTTP (`http://`, `https://`). The scheme of
/// `SURREAL_URL` picks the backend at runtime.
pub type DbConn = Arc<Surreal<Any>>;

/// Default connection string. Matches the legacy embedded-RocksDB path so
/// existing dev workflows keep working unless the operator opts into a
/// standalone server by setting `SURREAL_URL`.
const DEFAULT_SURREAL_URL: &str = "rocksdb://./data.surreal";

/// Boxed error returned by [`init`] so the function can surface both
/// `surrealdb::Error` from the driver and our own boot-time validation
/// failures (e.g. missing credentials for a remote URL) through the same
/// fallible `Result` instead of panicking. `Send + Sync` so callers can
/// propagate the error across `await` points and threads.
pub type InitError = Box<dyn std::error::Error + Send + Sync>;

/// Initialise SurrealDB using `SURREAL_URL` (default: embedded RocksDB at
/// `./data.surreal`), apply namespace/database, and seed fixture data only
/// when `SEED_ON_EMPTY=true`.
///
/// Set `SURREAL_URL=ws://127.0.0.1:8000` to connect to a standalone server
/// — required if a GUI (e.g. Surrealist) needs to attach to the same DB,
/// since embedded RocksDB takes an exclusive file lock.
///
/// Returns [`InitError`] (rather than panicking) when `SURREAL_URL` points
/// at a remote scheme but `SURREAL_USER` / `SURREAL_PASS` are unset — that
/// keeps fallibility visible to callers and lets `main.rs` surface the
/// underlying message via its `.expect(...)` rather than a generic abort.
pub async fn init() -> Result<DbConn, InitError> {
    let url = std::env::var("SURREAL_URL").unwrap_or_else(|_| DEFAULT_SURREAL_URL.to_string());

    // Validate remote credentials *before* opening the connection so a
    // misconfigured deployment fails fast with a clear "must be set" error
    // instead of performing an outbound handshake first and then surfacing the
    // credential check after the fact. Embedded schemes (e.g. `rocksdb://`,
    // `mem://`) skip this and connect straight through.
    //
    // Fail closed when `SURREAL_URL` points at a remote server but credentials
    // are not explicitly provided — defaulting to `root`/`root` against a
    // non-local server is a footgun, especially in production. Operators must
    // set `SURREAL_USER` and `SURREAL_PASS` themselves.
    let remote_credentials = if is_remote_scheme(&url) {
        let user = require_remote_credential("SURREAL_USER")?;
        let pass = require_remote_credential("SURREAL_PASS")?;
        Some((user, pass))
    } else {
        None
    };

    let db = connect(&url).await?;

    // Remote endpoints require signin before `use_ns/use_db`; embedded engines
    // don't. Keep the branch narrow so we don't mint root creds against local
    // RocksDB for no reason.
    if let Some((user, pass)) = remote_credentials {
        db.signin(Root {
            username: user,
            password: pass,
        })
        .await?;
    }

    db.use_ns("circle").use_db("main").await?;

    define_tables(&db).await?;

    if std::env::var("SEED_ON_EMPTY").as_deref() == Ok("true") {
        seed(&db).await?;
    }

    info!(url = %redact_url_userinfo(&url), "SurrealDB connected");
    Ok(Arc::new(db))
}

/// Fetch a required env var for remote SurrealDB signin, or return a clear
/// boxed error explaining which variable is missing. Centralised so the two
/// callers (`SURREAL_USER`, `SURREAL_PASS`) report identically-shaped
/// messages.
///
/// Treats an unset, empty, or whitespace-only value as missing — otherwise
/// `SURREAL_USER=` would pass through to `signin` and surface as an opaque
/// driver error rather than the "must be set" message operators expect.
fn require_remote_credential(var: &str) -> Result<String, InitError> {
    let raw = std::env::var(var).map_err(|_| missing_remote_credential_error(var))?;
    if raw.trim().is_empty() {
        return Err(missing_remote_credential_error(var));
    }
    Ok(raw)
}

fn missing_remote_credential_error(var: &str) -> InitError {
    format!(
        "{var} must be set when SURREAL_URL points at a remote server \
         (ws/wss/http/https) — refusing to default to root/root"
    )
    .into()
}

/// Initialise an in-memory SurrealDB instance — used in integration tests
/// to avoid touching the filesystem and to keep each test isolated.
pub async fn init_memory() -> Result<DbConn, surrealdb::Error> {
    let db = connect("mem://").await?;
    db.use_ns("circle").use_db("main").await?;
    define_tables(&db).await?;
    seed(&db).await?;
    Ok(Arc::new(db))
}

/// URL schemes are case-insensitive (RFC 3986 §3.1), so we lowercase the
/// scheme prefix before matching. Otherwise `WS://...` / `Wss://...` would
/// slip past this gate, skip credential validation, *and* skip `signin`,
/// silently undermining the fail-closed remote-mode contract.
fn is_remote_scheme(url: &str) -> bool {
    let Some(scheme_end) = url.find("://") else {
        return false;
    };
    let scheme = url[..scheme_end].to_ascii_lowercase();
    matches!(scheme.as_str(), "ws" | "wss" | "http" | "https")
}

/// Strip `user:pass@` from a connection URL before logging.
///
/// SurrealDB URLs typically pull credentials from `SURREAL_USER` /
/// `SURREAL_PASS`, but operators sometimes embed them inline (e.g.
/// `wss://user:pass@host:8000`). Logging the raw string would leak those
/// credentials to whatever log sink is attached, so we drop the userinfo
/// segment and replace it with `***@` to keep the rest of the URL useful
/// for debugging.
fn redact_url_userinfo(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after_scheme = &url[scheme_end + 3..];
    // `@` only carries userinfo when it appears before the first `/` (path)
    // or `?` (query); otherwise it's a literal in the path/query.
    let host_end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    let authority = &after_scheme[..host_end];
    let Some(at_idx) = authority.find('@') else {
        return url.to_string();
    };
    let host = &authority[at_idx + 1..];
    let rest = &after_scheme[host_end..];
    format!("{}://***@{host}{rest}", &url[..scheme_end])
}

/// Idempotently define every table the application reads from.
///
/// In SurrealDB 3, `SELECT` against an undefined table returns an error rather
/// than an empty result. Tables seeded via `upsert` in `insert_fixtures` are
/// defined implicitly, but tables that start empty (e.g. `group_link`) must be
/// declared here so handlers can query them without special-casing.
async fn define_tables(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    db.query(
        "DEFINE TABLE IF NOT EXISTS group SCHEMALESS;
         DEFINE TABLE IF NOT EXISTS member SCHEMALESS;
         DEFINE TABLE IF NOT EXISTS cycle SCHEMALESS;
         DEFINE TABLE IF NOT EXISTS payment SCHEMALESS;
         DEFINE TABLE IF NOT EXISTS group_link SCHEMALESS;
         DEFINE TABLE IF NOT EXISTS receipt SCHEMALESS;",
    )
    .await?
    .check()?;

    define_receipt_extensions(db).await?;
    define_inbox_table(db).await?;
    define_auth_tables(db).await?;
    Ok(())
}

/// Slice 5 additions to the receipt table.
///
/// Two new optional fields:
///   - `raw_image_url`     — direct URL to the WhatsApp screenshot, captured
///                           by the bot and persisted so admins can review
///                           the original artefact during confirm/reject.
///   - `rejection_reason`  — short human note recorded when an admin rejects
///                           or flags a receipt. Must NOT contain PII
///                           (sender phone, OCR text, member name) — that
///                           is a handler-side invariant; the schema is
///                           open-ended so legacy rows stay readable.
///
/// Two new indexes:
///   - `receipt_sender_received` over `(sender_phone, received_at)` powers
///     the "show every receipt this phone has ever sent" admin-side history
///     lookups landing in the FE slice 5 modal.
///   - `receipt_status_received` over `(status, received_at)` powers the
///     admin queue's "pending, newest first" default sort without a table
///     scan as receipt volume grows.
///
/// The receipt table itself stays SCHEMALESS so existing fixtures and
/// in-flight writes are unaffected — new fields land as plain optional
/// columns. SCHEMAFULL would force a destructive backfill on every
/// existing row.
async fn define_receipt_extensions(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    db.query(
        "DEFINE FIELD IF NOT EXISTS raw_image_url ON receipt TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS rejection_reason ON receipt TYPE option<string>;
         DEFINE INDEX IF NOT EXISTS receipt_sender_received
             ON receipt FIELDS sender_phone, received_at;
         DEFINE INDEX IF NOT EXISTS receipt_status_received
             ON receipt FIELDS status, received_at;",
    )
    .await?
    .check()?;
    Ok(())
}

/// `inbox_item` is the per-user notification stream rendered by the FE
/// `/inbox` route (HANDOFF §4 and §5.1). SCHEMAFULL because the `kind`
/// vocabulary is contract-bearing: the FE switches presentation on the
/// value, and an unknown kind would render as a blank row. The DB-side
/// `ASSERT $value IN [...]` guarantees the contract holds even if a
/// future handler forgets to validate.
///
/// Indexes:
///   - `inbox_item_user_created` powers the "newest first" feed query —
///     `WHERE user_id = $uid ORDER BY created_at DESC`.
///   - `inbox_item_user_unread`  powers the inbox-bell unread count and the
///     "you have N pending items" badges on the home page.
async fn define_inbox_table(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    db.query(
        "DEFINE TABLE IF NOT EXISTS inbox_item SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS user_id ON inbox_item TYPE string;
         DEFINE FIELD IF NOT EXISTS kind ON inbox_item TYPE string
             ASSERT $value IN ['receipt_confirmed', 'cycle_starting', 'payout_scheduled', 'admin_message', 'overdue'];
         DEFINE FIELD IF NOT EXISTS title ON inbox_item TYPE string;
         DEFINE FIELD IF NOT EXISTS body ON inbox_item TYPE string;
         DEFINE FIELD IF NOT EXISTS pool_id ON inbox_item TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS cycle_id ON inbox_item TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS receipt_id ON inbox_item TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS read_at ON inbox_item TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS created_at ON inbox_item TYPE string;
         DEFINE INDEX IF NOT EXISTS inbox_item_user_created
             ON inbox_item FIELDS user_id, created_at;
         DEFINE INDEX IF NOT EXISTS inbox_item_user_unread
             ON inbox_item FIELDS user_id, read_at;",
    )
    .await?
    .check()?;
    Ok(())
}

/// Auth-specific tables are SCHEMAFULL so the security-critical shape is
/// enforced at the DB layer rather than relying on application checks alone.
async fn define_auth_tables(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    db.query(
        "DEFINE TABLE IF NOT EXISTS user SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS email ON user TYPE string;
         DEFINE FIELD IF NOT EXISTS email_normalised ON user TYPE string;
         DEFINE FIELD IF NOT EXISTS password_hash ON user TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS role ON user TYPE string
             ASSERT $value IN ['super_admin', 'admin', 'member'];
         DEFINE FIELD IF NOT EXISTS status ON user TYPE string ASSERT $value IN ['active', 'disabled'];
         DEFINE FIELD IF NOT EXISTS token_version ON user TYPE int;
         DEFINE FIELD IF NOT EXISTS must_reset_password ON user TYPE bool;
         DEFINE FIELD IF NOT EXISTS version ON user TYPE int;
         UPDATE user SET version = 1 WHERE version IS NONE;
         DEFINE FIELD IF NOT EXISTS created_at ON user TYPE string;
         DEFINE FIELD IF NOT EXISTS updated_at ON user TYPE string;
         DEFINE FIELD IF NOT EXISTS deleted_at ON user TYPE option<string>;
         DEFINE INDEX IF NOT EXISTS user_email_normalised ON user FIELDS email_normalised;

         DEFINE TABLE IF NOT EXISTS user_identity SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS user_id ON user_identity TYPE string;
         DEFINE FIELD IF NOT EXISTS provider ON user_identity TYPE string
             ASSERT $value IN ['google', 'github', 'apple', 'credentials'];
         DEFINE FIELD IF NOT EXISTS provider_subject ON user_identity TYPE string;
         DEFINE FIELD IF NOT EXISTS email_at_link ON user_identity TYPE string;
         DEFINE FIELD IF NOT EXISTS created_at ON user_identity TYPE string;
         DEFINE INDEX IF NOT EXISTS user_identity_provider_subject
             ON user_identity FIELDS provider, provider_subject UNIQUE;

         DEFINE TABLE IF NOT EXISTS auth_event SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS user_id ON auth_event TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS actor_id ON auth_event TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS event_type ON auth_event TYPE string;
         DEFINE FIELD IF NOT EXISTS ip ON auth_event TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS user_agent ON auth_event TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS success ON auth_event TYPE bool;
         DEFINE FIELD IF NOT EXISTS reason ON auth_event TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS created_at ON auth_event TYPE string;

         DEFINE TABLE IF NOT EXISTS refresh_token SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS user_id ON refresh_token TYPE string;
         DEFINE FIELD IF NOT EXISTS hashed_token ON refresh_token TYPE string;
         DEFINE FIELD IF NOT EXISTS family_id ON refresh_token TYPE string;
         DEFINE FIELD IF NOT EXISTS issued_at ON refresh_token TYPE string;
         DEFINE FIELD IF NOT EXISTS expires_at ON refresh_token TYPE string;
         DEFINE FIELD IF NOT EXISTS revoked_at ON refresh_token TYPE option<string>;
         DEFINE FIELD IF NOT EXISTS replaced_by ON refresh_token TYPE option<string>;
         DEFINE INDEX IF NOT EXISTS refresh_token_hashed
             ON refresh_token FIELDS hashed_token UNIQUE;
         DEFINE INDEX IF NOT EXISTS refresh_token_family ON refresh_token FIELDS family_id;
         DEFINE INDEX IF NOT EXISTS refresh_token_user ON refresh_token FIELDS user_id;

         DEFINE TABLE IF NOT EXISTS group_admin SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS user_id ON group_admin TYPE string;
         DEFINE FIELD IF NOT EXISTS group_id ON group_admin TYPE string;
         DEFINE FIELD IF NOT EXISTS created_at ON group_admin TYPE string;
         DEFINE FIELD IF NOT EXISTS created_by ON group_admin TYPE string;
         DEFINE INDEX IF NOT EXISTS group_admin_user_group
             ON group_admin FIELDS user_id, group_id UNIQUE;
         DEFINE INDEX IF NOT EXISTS group_admin_group ON group_admin FIELDS group_id;",
    )
    .await?
    .check()?;
    Ok(())
}

/// Seed the database with fixture data.
///
/// Only runs if all tables are empty — skips if any table already has
/// records to avoid duplicating data on restart.
async fn seed(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    let groups: Vec<DbGroup> = select_or_empty(db, "group").await?;
    let members: Vec<DbMember> = select_or_empty(db, "member").await?;
    let cycles: Vec<DbCycle> = select_or_empty(db, "cycle").await?;
    let payments: Vec<DbPayment> = select_or_empty(db, "payment").await?;
    let group_links: Vec<DbGroupLink> = select_or_empty(db, "group_link").await?;
    let receipts: Vec<DbReceipt> = select_or_empty(db, "receipt").await?;

    if !groups.is_empty()
        || !members.is_empty()
        || !cycles.is_empty()
        || !payments.is_empty()
        || !group_links.is_empty()
        || !receipts.is_empty()
    {
        info!("SurrealDB already has data — skipping seed");
        return Ok(());
    }

    info!("Seeding SurrealDB with fixture data");
    insert_fixtures(db).await?;
    let (g, m, c, p, r) = (
        fixture_groups().len(),
        fixture_members().len(),
        fixture_cycles().len(),
        fixture_payments().len(),
        fixture_receipts().len(),
    );
    info!("Seed complete: {g} groups, {m} members, {c} cycles, {p} payments, {r} receipts");
    Ok(())
}

/// Reseed all tables back to fixture state.
///
/// Clears all tables, then re-inserts the full fixture set.
/// Used by the dev-only /api/test/reset endpoint so E2E tests get a clean slate.
pub async fn reseed(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    let _: Vec<DbGroup> = db.delete("group").await?;
    let _: Vec<DbMember> = db.delete("member").await?;
    let _: Vec<DbCycle> = db.delete("cycle").await?;
    let _: Vec<DbPayment> = db.delete("payment").await?;
    let _: Vec<DbGroupLink> = db.delete("group_link").await?;
    let _: Vec<DbReceipt> = db.delete("receipt").await?;

    insert_fixtures(db).await?;

    let (g, m, c, p, r) = (
        fixture_groups().len(),
        fixture_members().len(),
        fixture_cycles().len(),
        fixture_payments().len(),
        fixture_receipts().len(),
    );
    info!(
        "Reseed complete: {g} groups, {m} members, {c} cycles, {p} payments, {r} receipts restored"
    );
    Ok(())
}

/// Insert all fixture data into the database using upsert (idempotent).
async fn insert_fixtures(db: &Surreal<Any>) -> Result<(), surrealdb::Error> {
    for (id, content) in fixture_groups() {
        let _: Option<DbGroup> = db.upsert(("group", id)).content(content).await?;
    }
    for (id, content) in fixture_members() {
        let _: Option<DbMember> = db.upsert(("member", id)).content(content).await?;
    }
    for (id, content) in fixture_cycles() {
        let _: Option<DbCycle> = db.upsert(("cycle", id)).content(content).await?;
    }
    for (id, content) in fixture_payments() {
        let _: Option<DbPayment> = db.upsert(("payment", id)).content(content).await?;
    }
    for (id, content) in fixture_receipts() {
        let _: Option<DbReceipt> = db.upsert(("receipt", id)).content(content).await?;
    }
    Ok(())
}

/// SELECT a table and return an empty vec if the table does not yet exist.
pub(crate) async fn select_or_empty<T>(
    db: &Surreal<Any>,
    table: &str,
) -> Result<Vec<T>, surrealdb::Error>
where
    T: serde::de::DeserializeOwned + surrealdb_types::SurrealValue,
{
    match db.select(table).await {
        Ok(rows) => Ok(rows),
        Err(e) if e.to_string().contains("does not exist") => Ok(vec![]),
        Err(e) => Err(e),
    }
}

/// Substring-based detector for SurrealDB unique-constraint violations.
///
/// SurrealDB surfaces UNIQUE index collisions as opaque error strings — there
/// is no structured error variant to match on. We sniff the lowercased message
/// for the three phrases the engine is known to use ("already contains",
/// "unique", "duplicate"). Keeping this centralised avoids the two insert
/// paths (`auth_endpoints::ensure_user` and `admin_users::create_admin_user`)
/// drifting apart if SurrealDB tweaks its wording in a future release.
pub(crate) fn is_unique_constraint_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("already contains") || lower.contains("unique") || lower.contains("duplicate")
}

// ── Fixture data ──────────────────────────────────────────────────────────────

/// The seeded group ID used across all fixtures. Exposed `pub(crate)` so
/// the dev-only `auth::bootstrap::seed_dummy_admins` path can target the
/// same group without a duplicated string literal — keeps both seed paths
/// compile-break together if the fixture group id ever changes.
pub(crate) const FIXTURE_GROUP_ID: &str = "1";

fn fixture_groups() -> Vec<(&'static str, GroupContent)> {
    vec![
        (FIXTURE_GROUP_ID, GroupContent {
            name: "PoolPay Group Alpha".into(),
            status: "active".into(),
            description: Some("First PoolPay savings group — 6 members, ₦10k monthly".into()),
            created_at: "2025-06-15T00:00:00+00:00".into(),
            updated_at: "2025-06-15T00:00:00+00:00".into(),
            deleted_at: None,
            version: 1,
        }),
    ]
}

fn fixture_members() -> Vec<(&'static str, MemberContent)> {
    let group_id = FIXTURE_GROUP_ID.to_string();
    let created_at = "2025-06-15T00:00:00+00:00";
    vec![
        ("1", MemberContent { name: "Adaeze Okonkwo".into(),  phone: "2348101234567".into(), position: 1, status: "active".into(), group_id: group_id.clone(), notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
        ("2", MemberContent { name: "Chukwuemeka Eze".into(), phone: "2347031234567".into(), position: 2, status: "active".into(), group_id: group_id.clone(), notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
        ("3", MemberContent { name: "Ngozi Adeyemi".into(),   phone: "2349061234567".into(), position: 3, status: "active".into(), group_id: group_id.clone(), notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
        ("4", MemberContent { name: "Tunde Bakare".into(),    phone: "2348031234567".into(), position: 4, status: "active".into(), group_id: group_id.clone(), notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
        ("5", MemberContent { name: "Amaka Nwosu".into(),     phone: "2348161234567".into(), position: 5, status: "active".into(), group_id: group_id.clone(), notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
        ("6", MemberContent { name: "Seun Okafor".into(),     phone: "2347061234567".into(), position: 6, status: "active".into(), group_id, notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
    ]
}

fn fixture_cycles() -> Vec<(&'static str, CycleContent)> {
    let group_id = FIXTURE_GROUP_ID.to_string();
    let created_at = "2025-06-15T00:00:00+00:00";
    vec![
        // Round 1: Jul–Dec 2025 (cycles 1–6, full rotation of all 6 members)
        ("4", CycleContent {
            cycle_number: 1, start_date: "2025-07-01".into(), end_date: "2025-07-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "1".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("5", CycleContent {
            cycle_number: 2, start_date: "2025-08-01".into(), end_date: "2025-08-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "2".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("6", CycleContent {
            cycle_number: 3, start_date: "2025-09-01".into(), end_date: "2025-09-30".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "3".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("7", CycleContent {
            cycle_number: 4, start_date: "2025-10-01".into(), end_date: "2025-10-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "4".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("8", CycleContent {
            cycle_number: 5, start_date: "2025-11-01".into(), end_date: "2025-11-30".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "5".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("9", CycleContent {
            cycle_number: 6, start_date: "2025-12-01".into(), end_date: "2025-12-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "6".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        // Round 2: Jan–Mar 2026 (cycles 7–9, second rotation begins)
        ("1", CycleContent {
            cycle_number: 7, start_date: "2026-01-01".into(), end_date: "2026-01-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "1".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("2", CycleContent {
            cycle_number: 8, start_date: "2026-02-01".into(), end_date: "2026-02-28".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "2".into(), status: "closed".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("3", CycleContent {
            cycle_number: 9, start_date: "2026-03-01".into(), end_date: "2026-03-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "3".into(), status: "active".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        // Round 2 upcoming: Apr–Jun 2026 (cycles 10–12, pending). Scheduled
        // but not yet started — gives the dashboard a `pending` cycle state
        // to render alongside closed/active, and extends the rotation preview
        // through end-of-round without disturbing the active-cycle id (3).
        ("10", CycleContent {
            cycle_number: 10, start_date: "2026-04-01".into(), end_date: "2026-04-30".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "4".into(), status: "pending".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("11", CycleContent {
            cycle_number: 11, start_date: "2026-05-01".into(), end_date: "2026-05-31".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "5".into(), status: "pending".into(), group_id: group_id.clone(), notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
        ("12", CycleContent {
            cycle_number: 12, start_date: "2026-06-01".into(), end_date: "2026-06-30".into(),
            contribution_per_member: 1_000_000, total_amount: 6_000_000,
            recipient_member_id: "6".into(), status: "pending".into(), group_id, notes: None,
            created_at: created_at.into(), updated_at: created_at.into(), version: 1,
        }),
    ]
}

fn fixture_payments() -> Vec<(&'static str, PaymentContent)> {
    let created_at = "2025-06-15T00:00:00+00:00";
    let payment = |member_id: &str, cycle_id: &str, date: &str| PaymentContent {
        member_id: member_id.into(), cycle_id: cycle_id.into(), amount: 1_000_000,
        currency: "NGN".into(), payment_date: date.into(),
        payment_method: None, reference: None,
        confirmed_at: None, confirmed_by: None,
        created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None,
        rejected_by: None, deleted_by: None,
    };
    vec![
        // Cycle 3 — March 2026 (Ngozi excluded as recipient; 3 of 5 contributing paid)
        ("1",  payment("1", "3", "2026-03-02")),
        ("2",  payment("2", "3", "2026-03-03")),
        ("4",  payment("5", "3", "2026-03-07")),
        // Cycle 1 — January 2026 (all 6 members paid)
        ("5",  payment("1", "1", "2026-01-02")),
        ("6",  payment("2", "1", "2026-01-03")),
        ("7",  payment("3", "1", "2026-01-04")),
        ("8",  payment("4", "1", "2026-01-05")),
        ("9",  payment("5", "1", "2026-01-06")),
        ("10", payment("6", "1", "2026-01-08")),
        // Cycle 2 — February 2026 (all 6 members paid)
        ("11", payment("1", "2", "2026-02-02")),
        ("12", payment("2", "2", "2026-02-03")),
        ("13", payment("3", "2", "2026-02-05")),
        ("14", payment("4", "2", "2026-02-06")),
        ("15", payment("5", "2", "2026-02-07")),
        ("16", payment("6", "2", "2026-02-09")),
        // Cycle 4 — July 2025 (all 6 members paid)
        ("17", payment("1", "4", "2025-07-03")),
        ("18", payment("2", "4", "2025-07-04")),
        ("19", payment("3", "4", "2025-07-05")),
        ("20", payment("4", "4", "2025-07-07")),
        ("21", payment("5", "4", "2025-07-08")),
        ("22", payment("6", "4", "2025-07-09")),
        // Cycle 5 — August 2025 (5 of 6 paid; member 3 missed)
        ("23", payment("1", "5", "2025-08-02")),
        ("24", payment("2", "5", "2025-08-04")),
        ("25", payment("4", "5", "2025-08-05")),
        ("26", payment("5", "5", "2025-08-06")),
        ("27", payment("6", "5", "2025-08-08")),
        // Cycle 6 — September 2025 (all 6 members paid)
        ("28", payment("1", "6", "2025-09-02")),
        ("29", payment("2", "6", "2025-09-03")),
        ("30", payment("3", "6", "2025-09-04")),
        ("31", payment("4", "6", "2025-09-05")),
        ("32", payment("5", "6", "2025-09-06")),
        ("33", payment("6", "6", "2025-09-08")),
        // Cycle 7 — October 2025 (5 of 6 paid; member 4 missed)
        ("34", payment("1", "7", "2025-10-03")),
        ("35", payment("2", "7", "2025-10-04")),
        ("36", payment("3", "7", "2025-10-05")),
        ("37", payment("5", "7", "2025-10-06")),
        ("38", payment("6", "7", "2025-10-07")),
        // Cycle 8 — November 2025 (all 6 members paid)
        ("39", payment("1", "8", "2025-11-03")),
        ("40", payment("2", "8", "2025-11-04")),
        ("41", payment("3", "8", "2025-11-05")),
        ("42", payment("4", "8", "2025-11-06")),
        ("43", payment("5", "8", "2025-11-07")),
        ("44", payment("6", "8", "2025-11-09")),
        // Cycle 9 — December 2025 (all 6 members paid)
        ("45", payment("1", "9", "2025-12-03")),
        ("46", payment("2", "9", "2025-12-04")),
        ("47", payment("3", "9", "2025-12-05")),
        ("48", payment("4", "9", "2025-12-06")),
        ("49", payment("5", "9", "2025-12-07")),
        ("50", payment("6", "9", "2025-12-09")),
    ]
}

/// Two fixture receipts against the active cycle (9) — one pending (awaiting
/// admin review) and one soft-deleted (to verify list filtering). The real
/// pipeline will write these via Green API polling; until then the fixtures
/// give the dashboard something to render.
fn fixture_receipts() -> Vec<(&'static str, ReceiptContent)> {
    let created_at = "2026-03-02T10:30:00+00:00";
    let group_id = FIXTURE_GROUP_ID.to_string();
    vec![
        (
            "1",
            ReceiptContent {
                whatsapp_message_id: "3EB0C123ABCD4567EF89".into(),
                group_id: group_id.clone(),
                chat_id: "2349000000001@g.us".into(),
                sender_phone: "2348031234567".into(),
                member_id: Some("4".into()),
                cycle_id: Some("3".into()),
                extracted_amount: Some(1_000_000),
                expected_amount: Some(1_000_000),
                amount_matches: Some(true),
                status: "pending".into(),
                ocr_text: Some("NGN 10,000.00\nFrom: Tunde Bakare\nBank: GTBank".into()),
                sender_label: Some("Tunde Bakare".into()),
                bank_label: Some("GTBank".into()),
                raw_image_url: None,
                rejection_reason: None,
                received_at: "2026-03-02T10:29:45+00:00".into(),
                created_at: created_at.into(),
                updated_at: created_at.into(),
                deleted_at: None,
                confirmed_by: None,
                rejected_by: None,
                deleted_by: None,
            },
        ),
        (
            "2",
            ReceiptContent {
                whatsapp_message_id: "3EB0C9876FEDC543210".into(),
                group_id,
                chat_id: "2349000000001@g.us".into(),
                sender_phone: "2347031234567".into(),
                member_id: Some("2".into()),
                cycle_id: Some("3".into()),
                extracted_amount: Some(500_000),
                expected_amount: Some(1_000_000),
                amount_matches: Some(false),
                status: "rejected".into(),
                ocr_text: Some("NGN 5,000.00\nFrom: Chukwuemeka Eze".into()),
                sender_label: Some("Chukwuemeka Eze".into()),
                bank_label: None,
                raw_image_url: None,
                rejection_reason: None,
                received_at: "2026-03-03T14:15:00+00:00".into(),
                created_at: "2026-03-03T14:15:30+00:00".into(),
                updated_at: "2026-03-03T16:00:00+00:00".into(),
                deleted_at: Some("2026-03-03T16:00:00+00:00".into()),
                confirmed_by: None,
                rejected_by: None,
                deleted_by: None,
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_url_userinfo_strips_inline_credentials() {
        assert_eq!(
            redact_url_userinfo("wss://user:secret@host:8000"),
            "wss://***@host:8000"
        );
        assert_eq!(
            redact_url_userinfo("https://root:hunter2@db.example.com/path?q=1"),
            "https://***@db.example.com/path?q=1"
        );
    }

    #[test]
    fn redact_url_userinfo_passes_through_when_no_userinfo() {
        assert_eq!(
            redact_url_userinfo("ws://127.0.0.1:8000"),
            "ws://127.0.0.1:8000"
        );
        assert_eq!(
            redact_url_userinfo("rocksdb://./data.surreal"),
            "rocksdb://./data.surreal"
        );
        assert_eq!(redact_url_userinfo("mem://"), "mem://");
    }

    #[test]
    fn redact_url_userinfo_does_not_treat_at_in_path_as_userinfo() {
        // `@` after the path delimiter is not userinfo and must be preserved.
        assert_eq!(
            redact_url_userinfo("https://host/some@path"),
            "https://host/some@path"
        );
    }

    /// Single global lock serializing every `set_var`/`remove_var` call in this
    /// test module. Unique per-test var names alone don't satisfy the safety
    /// precondition for `set_var`/`remove_var`: those require *no other thread*
    /// to be reading or writing *any* env var concurrently. Holding this mutex
    /// for the full mutate → run → cleanup window makes that precondition hold
    /// across parallel tests in this binary.
    fn env_lock() -> &'static std::sync::Mutex<()> {
        static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> =
            std::sync::OnceLock::new();
        ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    /// Use a unique env var name per case so tests don't race on a shared key,
    /// and serialize all env mutations on `env_lock()` so concurrent
    /// `set_var`/`remove_var` calls (process-global) don't violate their
    /// safety precondition under multi-threaded `cargo test`.
    fn with_env_var<F: FnOnce(&str)>(name: &str, value: Option<&str>, f: F) {
        let _guard = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialized by `env_lock()` above; var names are unique per
        // case so no other test reads/writes them while we hold the guard.
        unsafe {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
        f(name);
        // SAFETY: same guard still held; cleanup mirrors the mutation above.
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn require_remote_credential_rejects_unset_value() {
        with_env_var("POOLPAY_TEST_REQUIRE_UNSET", None, |name| {
            let err = require_remote_credential(name).expect_err("unset must fail");
            assert!(err.to_string().contains("must be set"));
        });
    }

    #[test]
    fn require_remote_credential_rejects_empty_value() {
        with_env_var("POOLPAY_TEST_REQUIRE_EMPTY", Some(""), |name| {
            let err = require_remote_credential(name).expect_err("empty must fail");
            assert!(err.to_string().contains("must be set"));
        });
    }

    #[test]
    fn require_remote_credential_rejects_whitespace_value() {
        with_env_var("POOLPAY_TEST_REQUIRE_WS", Some("   \t  "), |name| {
            let err = require_remote_credential(name).expect_err("whitespace must fail");
            assert!(err.to_string().contains("must be set"));
        });
    }

    #[test]
    fn require_remote_credential_accepts_non_empty_value() {
        with_env_var("POOLPAY_TEST_REQUIRE_OK", Some("root"), |name| {
            let value = require_remote_credential(name).expect("non-empty must succeed");
            assert_eq!(value, "root");
        });
    }

    #[test]
    fn is_remote_scheme_recognises_supported_remote_schemes() {
        for url in [
            "ws://127.0.0.1:8000",
            "wss://db.example.com",
            "http://127.0.0.1:8000",
            "https://db.example.com",
        ] {
            assert!(is_remote_scheme(url), "expected remote: {url}");
        }
    }

    #[test]
    fn is_remote_scheme_is_case_insensitive() {
        // RFC 3986 §3.1: scheme matching is case-insensitive. Mixed-case must
        // not bypass the credential gate.
        for url in [
            "WS://127.0.0.1:8000",
            "Wss://db.example.com",
            "HTTP://127.0.0.1:8000",
            "HttpS://db.example.com",
        ] {
            assert!(is_remote_scheme(url), "expected remote: {url}");
        }
    }

    #[test]
    fn is_remote_scheme_rejects_embedded_and_malformed_urls() {
        for url in [
            "rocksdb://./data.surreal",
            "mem://",
            "file:///tmp/db",
            "not-a-url",
        ] {
            assert!(!is_remote_scheme(url), "expected non-remote: {url}");
        }
    }
}
