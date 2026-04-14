use std::sync::Arc;

use surrealdb::Surreal;
use surrealdb::engine::local::{Db, RocksDb};
use tracing::info;

use crate::api::models::{
    CycleContent, DbCycle, DbGroup, DbGroupLink, DbMember, DbPayment, DbReceipt, GroupContent,
    MemberContent, PaymentContent, ReceiptContent,
};

/// The shared SurrealDB connection type — passed as Axum state.
pub type DbConn = Arc<Surreal<Db>>;

/// Initialise the embedded SurrealDB instance backed by RocksDB, apply
/// namespace/database, and seed fixture data only when `SEED_ON_EMPTY=true`.
pub async fn init() -> Result<DbConn, surrealdb::Error> {
    let db = Surreal::new::<RocksDb>("./data.surreal").await?;
    db.use_ns("circle").use_db("main").await?;

    define_tables(&db).await?;

    if std::env::var("SEED_ON_EMPTY").as_deref() == Ok("true") {
        seed(&db).await?;
    }

    Ok(Arc::new(db))
}

/// Initialise an in-memory SurrealDB instance — used in integration tests
/// to avoid touching the filesystem and to keep each test isolated.
pub async fn init_memory() -> Result<DbConn, surrealdb::Error> {
    use surrealdb::engine::local::Mem;
    let db = Surreal::new::<Mem>(()).await?;
    db.use_ns("circle").use_db("main").await?;
    define_tables(&db).await?;
    seed(&db).await?;
    Ok(Arc::new(db))
}

/// Idempotently define every table the application reads from.
///
/// In SurrealDB 3, `SELECT` against an undefined table returns an error rather
/// than an empty result. Tables seeded via `upsert` in `insert_fixtures` are
/// defined implicitly, but tables that start empty (e.g. `group_link`) must be
/// declared here so handlers can query them without special-casing.
async fn define_tables(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
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
    Ok(())
}

/// Seed the database with fixture data.
///
/// Only runs if all tables are empty — skips if any table already has
/// records to avoid duplicating data on restart.
async fn seed(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
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
pub async fn reseed(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
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
async fn insert_fixtures(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
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
    db: &Surreal<Db>,
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

// ── Fixture data ──────────────────────────────────────────────────────────────

/// The seeded group ID used across all fixtures.
const FIXTURE_GROUP_ID: &str = "1";

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
        ("6", MemberContent { name: "Seun Okafor".into(),     phone: "2347061234567".into(), position: 6, status: "active".into(), group_id: group_id, notes: None, joined_at: Some("2025-06-15".into()), created_at: created_at.into(), updated_at: created_at.into(), deleted_at: None, version: 1 }),
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
            recipient_member_id: "3".into(), status: "active".into(), group_id: group_id, notes: None,
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
                received_at: "2026-03-02T10:29:45+00:00".into(),
                created_at: created_at.into(),
                updated_at: created_at.into(),
                deleted_at: None,
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
                received_at: "2026-03-03T14:15:00+00:00".into(),
                created_at: "2026-03-03T14:15:30+00:00".into(),
                updated_at: "2026-03-03T16:00:00+00:00".into(),
                deleted_at: Some("2026-03-03T16:00:00+00:00".into()),
            },
        ),
    ]
}
