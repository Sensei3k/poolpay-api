use std::sync::Arc;

use surrealdb::Surreal;
use surrealdb::engine::local::{Db, RocksDb};
use tracing::info;

use crate::api::models::{
    CycleContent, DbCycle, DbMember, DbPayment, MemberContent, PaymentContent,
};

/// The shared SurrealDB connection type — passed as Axum state.
pub type DbConn = Arc<Surreal<Db>>;

/// Initialise the embedded SurrealDB instance backed by RocksDB, apply
/// namespace/database, and seed fixture data if all tables are empty.
pub async fn init() -> Result<DbConn, surrealdb::Error> {
    let db = Surreal::new::<RocksDb>("./data.surreal").await?;
    db.use_ns("circle").use_db("main").await?;
    seed(&db).await?;
    Ok(Arc::new(db))
}

/// Initialise an in-memory SurrealDB instance — used in integration tests
/// to avoid touching the filesystem and to keep each test isolated.
pub async fn init_memory() -> Result<DbConn, surrealdb::Error> {
    use surrealdb::engine::local::Mem;
    let db = Surreal::new::<Mem>(()).await?;
    db.use_ns("circle").use_db("main").await?;
    seed(&db).await?;
    Ok(Arc::new(db))
}

/// Seed the database with fixture data.
///
/// Only runs if all three tables are empty — skips if any table already has
/// records to avoid duplicating data on restart. A partial-seed state (some
/// tables populated, some not) is treated as an empty DB and re-seeded.
async fn seed(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
    let cycles: Vec<DbCycle> = select_or_empty(db, "cycle").await?;
    let members: Vec<DbMember> = select_or_empty(db, "member").await?;
    let payments: Vec<DbPayment> = select_or_empty(db, "payment").await?;

    if !cycles.is_empty() && !members.is_empty() && !payments.is_empty() {
        info!("SurrealDB already seeded — skipping");
        return Ok(());
    }

    info!("Seeding SurrealDB with fixture data");
    insert_fixtures(db).await?;
    let (m, c, p) = (
        fixture_members().len(),
        fixture_cycles().len(),
        fixture_payments().len(),
    );
    info!("Seed complete: {m} members, {c} cycles, {p} payments");
    Ok(())
}

/// Reseed all tables back to fixture state.
///
/// Clears members, cycles, and payments, then re-inserts the full fixture set.
/// Used by the dev-only /api/test/reset endpoint so E2E tests get a clean slate.
pub async fn reseed(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
    let _: Vec<DbMember> = db.delete("member").await?;
    let _: Vec<DbCycle> = db.delete("cycle").await?;
    let _: Vec<DbPayment> = db.delete("payment").await?;

    insert_fixtures(db).await?;

    let (m, c, p) = (
        fixture_members().len(),
        fixture_cycles().len(),
        fixture_payments().len(),
    );
    info!("Reseed complete: {m} members, {c} cycles, {p} payments restored");
    Ok(())
}

/// Insert all fixture data into the database using upsert (idempotent).
async fn insert_fixtures(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
    for (id, content) in fixture_members() {
        let _: Option<DbMember> = db.upsert(("member", id)).content(content).await?;
    }
    for (id, content) in fixture_cycles() {
        let _: Option<DbCycle> = db.upsert(("cycle", id)).content(content).await?;
    }
    for (id, content) in fixture_payments() {
        let _: Option<DbPayment> = db.upsert(("payment", id)).content(content).await?;
    }
    Ok(())
}

/// SELECT a table and return an empty vec if the table does not yet exist.
///
/// Only treats NotFound errors as empty — all other errors propagate so real
/// DB issues (locked store, deserialisation failures) are not silently swallowed.
async fn select_or_empty<T>(
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

fn fixture_members() -> Vec<(i64, MemberContent)> {
    vec![
        (1, MemberContent { name: "Adaeze Okonkwo".into(),  phone: "2348101234567".into(), position: 1, status: "active".into() }),
        (2, MemberContent { name: "Chukwuemeka Eze".into(), phone: "2347031234567".into(), position: 2, status: "active".into() }),
        (3, MemberContent { name: "Ngozi Adeyemi".into(),   phone: "2349061234567".into(), position: 3, status: "active".into() }),
        (4, MemberContent { name: "Tunde Bakare".into(),    phone: "2348031234567".into(), position: 4, status: "active".into() }),
        (5, MemberContent { name: "Amaka Nwosu".into(),     phone: "2348161234567".into(), position: 5, status: "active".into() }),
        (6, MemberContent { name: "Seun Okafor".into(),     phone: "2347061234567".into(), position: 6, status: "active".into() }),
    ]
}

fn fixture_cycles() -> Vec<(i64, CycleContent)> {
    vec![
        (1, CycleContent {
            cycle_number: 1,
            start_date: "2026-01-01".into(),
            end_date: "2026-01-31".into(),
            contribution_per_member: 1_000_000,
            total_amount: 6_000_000,
            recipient_member_id: 1,
            status: "closed".into(),
        }),
        (2, CycleContent {
            cycle_number: 2,
            start_date: "2026-02-01".into(),
            end_date: "2026-02-28".into(),
            contribution_per_member: 1_000_000,
            total_amount: 6_000_000,
            recipient_member_id: 2,
            status: "closed".into(),
        }),
        (3, CycleContent {
            cycle_number: 3,
            start_date: "2026-03-01".into(),
            end_date: "2026-03-31".into(),
            contribution_per_member: 1_000_000,
            total_amount: 6_000_000,
            recipient_member_id: 3,
            status: "active".into(),
        }),
    ]
}

/// The canonical fixture payment set.
///
/// IDs:
///   1, 2, 4   → cycle 3 payments (March 2026, 3 of 5 contributing members paid)
///   5–10      → cycle 1 payments (January 2026, all 6 members paid)
///   11–16     → cycle 2 payments (February 2026, all 6 members paid)
///
/// Non-sequential ordering is intentional: cycle-3 records were inserted first
/// during development. Timestamp-based IDs from create_payment (ms since epoch,
/// ~1.7 trillion) will never collide with these low fixture IDs.
fn fixture_payments() -> Vec<(i64, PaymentContent)> {
    vec![
        // Cycle 3 — March 2026 (Ngozi excluded as recipient; 3 of 5 contributing paid)
        (1,  PaymentContent { member_id: 1, cycle_id: 3, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-03-02".into() }),
        (2,  PaymentContent { member_id: 2, cycle_id: 3, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-03-03".into() }),
        (4,  PaymentContent { member_id: 5, cycle_id: 3, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-03-07".into() }),
        // Cycle 1 — January 2026 (all 6 members paid)
        (5,  PaymentContent { member_id: 1, cycle_id: 1, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-01-02".into() }),
        (6,  PaymentContent { member_id: 2, cycle_id: 1, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-01-03".into() }),
        (7,  PaymentContent { member_id: 3, cycle_id: 1, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-01-04".into() }),
        (8,  PaymentContent { member_id: 4, cycle_id: 1, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-01-05".into() }),
        (9,  PaymentContent { member_id: 5, cycle_id: 1, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-01-06".into() }),
        (10, PaymentContent { member_id: 6, cycle_id: 1, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-01-08".into() }),
        // Cycle 2 — February 2026 (all 6 members paid)
        (11, PaymentContent { member_id: 1, cycle_id: 2, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-02-02".into() }),
        (12, PaymentContent { member_id: 2, cycle_id: 2, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-02-03".into() }),
        (13, PaymentContent { member_id: 3, cycle_id: 2, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-02-05".into() }),
        (14, PaymentContent { member_id: 4, cycle_id: 2, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-02-06".into() }),
        (15, PaymentContent { member_id: 5, cycle_id: 2, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-02-07".into() }),
        (16, PaymentContent { member_id: 6, cycle_id: 2, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-02-09".into() }),
    ]
}
