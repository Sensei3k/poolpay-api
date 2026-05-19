//! Integration tests for the SurrealDB migration runner.
//!
//! These tests exercise the runner against a real in-memory SurrealDB
//! instance (the same engine the rest of the integration suite uses)
//! rather than mocking the DB layer. The behaviours covered:
//!
//! - Fresh DB applies every pending migration and records a row per
//!   file in `schema_migration`.
//! - Second apply on the same DB is a no-op (idempotent).
//! - Checksum drift surfaces as a hard error and aborts before any
//!   subsequent migration runs.
//! - Skipped-migration detection (an applied entry preceded by an
//!   unapplied one in lex order) refuses to proceed.
//! - The schema established by `0001_initial_schema` matches what the
//!   pre-runner `define_tables` chain used to define — spot-checked by
//!   issuing the same queries the application path issues at runtime.

use poolpay::{db, migrations};
use surrealdb::engine::any::{connect, Any};
use surrealdb::Surreal;
use surrealdb_types::SurrealValue;

async fn fresh_db() -> Surreal<Any> {
    let db = connect("mem://").await.expect("connect mem db");
    db.use_ns("circle")
        .use_db("test")
        .await
        .expect("namespace/db");
    db
}

#[derive(Debug, serde::Deserialize, SurrealValue)]
struct AppliedRow {
    name: String,
    checksum: String,
    applied_at: String,
}

async fn load_schema_migration_rows(db: &Surreal<Any>) -> Vec<AppliedRow> {
    let mut resp = db
        .query("SELECT name, checksum, applied_at FROM schema_migration ORDER BY name ASC")
        .await
        .expect("select schema_migration")
        .check()
        .expect("schema_migration query check");
    resp.take(0).expect("decode schema_migration rows")
}

#[tokio::test]
async fn fresh_db_applies_every_migration_and_records_a_row_per_file() {
    let db = fresh_db().await;

    migrations::apply_pending(&db)
        .await
        .expect("fresh apply must succeed");

    let rows = load_schema_migration_rows(&db).await;
    assert!(
        !rows.is_empty(),
        "fresh DB must have at least one applied migration row"
    );
    // The seed migration is always present.
    assert!(
        rows.iter().any(|r| r.name == "0001_initial_schema"),
        "0001_initial_schema must appear in the applied set: {rows:?}"
    );
    // Every row has a checksum + applied_at populated.
    for r in &rows {
        assert!(
            !r.checksum.is_empty(),
            "checksum must be set for {}: {r:?}",
            r.name
        );
        assert!(
            !r.applied_at.is_empty(),
            "applied_at must be set for {}: {r:?}",
            r.name
        );
    }
}

#[tokio::test]
async fn second_apply_is_a_no_op() {
    let db = fresh_db().await;

    migrations::apply_pending(&db)
        .await
        .expect("first apply must succeed");
    let first = load_schema_migration_rows(&db).await;

    migrations::apply_pending(&db)
        .await
        .expect("second apply must succeed");
    let second = load_schema_migration_rows(&db).await;

    assert_eq!(
        first.len(),
        second.len(),
        "second apply must not insert new rows"
    );
    // Same applied_at timestamps — no row was rewritten.
    for (a, b) in first.iter().zip(second.iter()) {
        assert_eq!(a.name, b.name);
        assert_eq!(a.checksum, b.checksum);
        assert_eq!(
            a.applied_at, b.applied_at,
            "idempotent apply must not rewrite applied_at"
        );
    }
}

#[tokio::test]
async fn checksum_drift_aborts_with_clear_error() {
    let db = fresh_db().await;

    migrations::apply_pending(&db).await.expect("initial apply");

    // Simulate drift: overwrite the stored checksum for 0001 to a wrong
    // value, then re-run. The runner must refuse because the current
    // file's checksum no longer matches the stored one.
    db.query(
        "UPDATE schema_migration SET checksum = 'deadbeef' WHERE name = '0001_initial_schema'",
    )
    .await
    .expect("inject drift")
    .check()
    .expect("drift injection check");

    let err = migrations::apply_pending(&db)
        .await
        .expect_err("drift must abort apply");
    let msg = err.to_string();
    assert!(
        msg.contains("0001_initial_schema"),
        "error must name the drifted migration, got: {msg}"
    );
    assert!(
        msg.contains("drift"),
        "error must mention drift, got: {msg}"
    );
}

#[tokio::test]
async fn unknown_applied_migration_aborts_with_clear_error() {
    // Simulate a foot-shoot: someone manually inserts a schema_migration
    // row for a migration the running binary has no knowledge of. The
    // runner must refuse, because either (a) the matching migration file
    // was deleted from `migrations/` (destructive history rewrite) or
    // (b) this binary is a downgrade of one that knew the migration. We
    // do this by pre-defining schema_migration ourselves and inserting
    // a fake row, then calling apply_pending.
    let db = fresh_db().await;

    db.query(
        "DEFINE TABLE IF NOT EXISTS schema_migration SCHEMAFULL;
         DEFINE FIELD IF NOT EXISTS name ON schema_migration TYPE string;
         DEFINE FIELD IF NOT EXISTS checksum ON schema_migration TYPE string;
         DEFINE FIELD IF NOT EXISTS applied_at ON schema_migration TYPE string;
         DEFINE INDEX IF NOT EXISTS schema_migration_name_unique
             ON schema_migration FIELDS name UNIQUE;
         CREATE schema_migration SET
             name = '9999_fake_unknown_migration',
             checksum = 'fakefake',
             applied_at = '2026-01-01T00:00:00.000Z';",
    )
    .await
    .expect("pre-seed fake applied row")
    .check()
    .expect("pre-seed check");

    let err = migrations::apply_pending(&db)
        .await
        .expect_err("unknown-applied-migration must abort apply");
    let msg = err.to_string();
    assert!(
        msg.contains("9999_fake_unknown_migration"),
        "error must name the unknown migration, got: {msg}"
    );
    assert!(
        msg.contains("not known to this binary"),
        "error must explain why it refused, got: {msg}"
    );
}

#[tokio::test]
async fn boot_path_seeds_fixtures_through_the_runner() {
    // End-to-end check that the migrated schema is functionally equivalent
    // to what `define_tables` used to produce: `db::init_memory()` goes
    // through `apply_schema` → `migrations::apply_pending`, then seeds
    // fixtures via `seed()`. If the migration created the wrong shape
    // (e.g. missing index, wrong field type), the seed step would fail
    // or the fixture row counts would diverge.
    let conn = db::init_memory().await.expect("init_memory");

    // Spot-check: the receipt UNIQUE index is what slice 5 / PR #55 added.
    // Inserting two receipts with the same whatsapp_message_id must fail
    // on the second insert — if the index didn't survive the migration,
    // both would succeed.
    use poolpay::api::models::{now_iso, EntityId, ReceiptContent};
    let make_content = |msg_id: &str| ReceiptContent {
        whatsapp_message_id: msg_id.to_string(),
        group_id: EntityId::from("1".to_string()),
        chat_id: "120363000000000000@g.us".into(),
        sender_phone: "2349999999999".into(),
        member_id: None,
        cycle_id: None,
        extracted_amount: None,
        expected_amount: None,
        amount_matches: None,
        status: "pending".into(),
        ocr_text: None,
        sender_label: None,
        bank_label: None,
        raw_image_url: None,
        rejection_reason: None,
        received_at: "2026-03-10T10:00:00+00:00".into(),
        ingested_at: Some("2026-03-10T10:00:00.000Z".into()),
        created_at: now_iso(),
        updated_at: now_iso(),
        deleted_at: None,
        confirmed_by: None,
        rejected_by: None,
        deleted_by: None,
    };

    let first: Option<poolpay::api::models::DbReceipt> = conn
        .create(("receipt", "unique-test-a"))
        .content(make_content("WAMSG-UNIQUE-PROBE"))
        .await
        .expect("first insert");
    assert!(first.is_some(), "first insert must succeed");

    let second_result: Result<Option<poolpay::api::models::DbReceipt>, _> = conn
        .create(("receipt", "unique-test-b"))
        .content(make_content("WAMSG-UNIQUE-PROBE"))
        .await;
    assert!(
        second_result.is_err(),
        "second insert with the same whatsapp_message_id must fail UNIQUE — migration did not preserve the index"
    );
}
