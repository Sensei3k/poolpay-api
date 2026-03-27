use std::sync::Arc;

use surrealdb::Surreal;
use surrealdb::engine::local::{Db, RocksDb};
use tracing::info;

use crate::api::models::{CycleContent, DbCycle, DbMember, DbPayment, MemberContent, PaymentContent};

/// The shared SurrealDB connection type — passed as Axum state.
pub type DbConn = Arc<Surreal<Db>>;

/// Initialise the embedded SurrealDB instance, apply namespace/database, and seed
/// fixture data if the members table is empty.
pub async fn init() -> Result<DbConn, surrealdb::Error> {
    let db = Surreal::new::<RocksDb>("./data.surreal").await?;
    db.use_ns("circle").use_db("main").await?;
    seed(&db).await?;
    Ok(Arc::new(db))
}

/// Seed the database with fixture data matching the mock data in circle-dashboard.
///
/// Only runs if the members table is empty — safe to call on every startup without
/// duplicating records.
async fn seed(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
    // Use a select to check whether the DB is already populated.
    // A NotFound error means the table doesn't exist yet — treat as empty and seed.
    let existing_cycles: Vec<DbCycle> = db.select("cycle").await.unwrap_or_default();
    if !existing_cycles.is_empty() {
        info!("SurrealDB already seeded — skipping");
        return Ok(());
    }

    info!("Seeding SurrealDB with fixture data");

    // --- Members ---
    let members: &[(i64, MemberContent)] = &[
        (1, MemberContent { name: "Adaeze Okonkwo".into(),  phone: "2348101234567".into(), position: 1, status: "active".into() }),
        (2, MemberContent { name: "Chukwuemeka Eze".into(), phone: "2347031234567".into(), position: 2, status: "active".into() }),
        (3, MemberContent { name: "Ngozi Adeyemi".into(),   phone: "2349061234567".into(), position: 3, status: "active".into() }),
        (4, MemberContent { name: "Tunde Bakare".into(),    phone: "2348031234567".into(), position: 4, status: "active".into() }),
        (5, MemberContent { name: "Amaka Nwosu".into(),     phone: "2348161234567".into(), position: 5, status: "active".into() }),
        (6, MemberContent { name: "Seun Okafor".into(),     phone: "2347061234567".into(), position: 6, status: "active".into() }),
    ];

    for (id, content) in members {
        let _: Option<DbMember> = db.upsert(("member", *id)).content(content.clone()).await?;
    }

    // --- Cycles ---
    // Amounts in kobo: 1,000,000 kobo = ₦10,000
    let cycles: &[(i64, CycleContent)] = &[
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
    ];

    for (id, content) in cycles {
        let _: Option<DbCycle> = db.upsert(("cycle", *id)).content(content.clone()).await?;
    }

    // --- Payments ---
    let payments = fixture_payments();
    for (id, content) in &payments {
        let _: Option<DbPayment> = db.upsert(("payment", *id)).content(content.clone()).await?;
    }

    info!("Seed complete: {} members, {} cycles, {} payments", members.len(), cycles.len(), payments.len());
    Ok(())
}

/// Reseed the payment table back to fixture state.
///
/// Clears all existing payment records and re-inserts the fixture set.
/// Used by the dev-only /api/test/reset endpoint so E2E tests get a clean slate.
pub async fn reseed(db: &Surreal<Db>) -> Result<(), surrealdb::Error> {
    let _: Vec<DbPayment> = db.delete("payment").await?;

    let payments = fixture_payments();
    for (id, content) in &payments {
        let _: Option<DbPayment> = db.upsert(("payment", *id)).content(content.clone()).await?;
    }

    info!("Reseed complete: {} payments restored", payments.len());
    Ok(())
}

/// The canonical fixture payment set — shared between seed() and reseed().
fn fixture_payments() -> Vec<(i64, PaymentContent)> {
    vec![
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
        // Cycle 3 — March 2026 (Ngozi excluded as recipient; 3 of 5 contributing paid)
        (1,  PaymentContent { member_id: 1, cycle_id: 3, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-03-02".into() }),
        (2,  PaymentContent { member_id: 2, cycle_id: 3, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-03-03".into() }),
        (4,  PaymentContent { member_id: 5, cycle_id: 3, amount: 1_000_000, currency: "NGN".into(), payment_date: "2026-03-07".into() }),
    ]
}
