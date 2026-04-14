//! Integration tests for the WhatsApp receipt ingestion pipeline.
//!
//! Exercises `src/ingestion.rs` end-to-end against an in-memory SurrealDB
//! seeded with fixtures, avoiding the Axum router and Green API entirely.

use poolpay::api::models::{DbGroupLink, DbReceipt, GroupLinkContent, now_iso};
use poolpay::db::{self, DbConn};
use poolpay::ingestion::{IngestionInput, IngestionOutcome, ingest_receipt};
use poolpay::models::ParsedReceipt;

const FIXTURE_CHAT_ID: &str = "2349000000001@g.us";
const FIXTURE_GROUP_ID: &str = "1";
/// Fixture member 1 — matches FIXTURE_GROUP_ID's active cycle 3.
const FIXTURE_MEMBER_PHONE: &str = "2348101234567";
const FIXTURE_MEMBER_JID: &str = "2348101234567@c.us";

async fn fresh_db() -> DbConn {
    db::init_memory().await.expect("failed to init test DB")
}

async fn link_default_group(db: &DbConn) {
    let now = now_iso();
    let _: Option<DbGroupLink> = db
        .create("group_link")
        .content(GroupLinkContent {
            chat_id: FIXTURE_CHAT_ID.into(),
            group_id: FIXTURE_GROUP_ID.into(),
            created_at: now.clone(),
            updated_at: now,
            deleted_at: None,
        })
        .await
        .expect("seed link failed");
}

fn parsed(amount: Option<&str>) -> ParsedReceipt {
    ParsedReceipt {
        sender: Some("Adaeze Okonkwo".into()),
        bank: Some("GTBank".into()),
        amount: amount.map(str::to_string),
    }
}

fn input<'a>(
    chat_id: &'a str,
    sender: &'a str,
    message_id: &'a str,
    parsed: &'a ParsedReceipt,
) -> IngestionInput<'a> {
    IngestionInput {
        chat_id,
        sender_phone: sender,
        message_id,
        ocr_text: "raw OCR text",
        parsed,
        received_at: now_iso(),
    }
}

async fn ingested(outcome: IngestionOutcome) -> poolpay::ingestion::IngestedReceipt {
    match outcome {
        IngestionOutcome::Ingested(r) => r,
        other => panic!("expected Ingested, got {other:?}"),
    }
}

async fn count_receipts(db: &DbConn) -> usize {
    let rows: Vec<DbReceipt> = db.select("receipt").await.unwrap();
    rows.len()
}

#[tokio::test]
async fn ingest_returns_not_linked_when_chat_unknown() {
    let db = fresh_db().await;
    let p = parsed(Some("₦10,000.00"));
    let before = count_receipts(&db).await;

    let out = ingest_receipt(&db, input("9999@g.us", FIXTURE_MEMBER_JID, "MID1", &p))
        .await
        .unwrap();

    assert!(matches!(out, IngestionOutcome::NotLinked));
    assert_eq!(count_receipts(&db).await, before, "must not insert a row");
}

#[tokio::test]
async fn ingest_persists_full_match() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(Some("₦10,000.00"));

    let out = ingest_receipt(
        &db,
        input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_JID, "MID-FULL", &p),
    )
    .await
    .unwrap();

    let r = ingested(out).await;
    assert!(r.member_matched);
    assert!(r.cycle_matched);
    assert_eq!(r.extracted_amount, Some(1_000_000));
    assert_eq!(r.expected_amount, Some(1_000_000));
    assert_eq!(r.amount_matches, Some(true));

    let rows: Vec<DbReceipt> = db.select("receipt").await.unwrap();
    let persisted = rows
        .iter()
        .find(|r| r.whatsapp_message_id == "MID-FULL")
        .expect("persisted row missing");
    assert_eq!(persisted.status, "pending");
    assert_eq!(persisted.sender_phone, "2348101234567");
    assert_eq!(persisted.amount_matches, Some(true));
}

#[tokio::test]
async fn ingest_flags_amount_mismatch() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(Some("₦500.00"));

    let r = ingested(
        ingest_receipt(
            &db,
            input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_JID, "MID-MISM", &p),
        )
        .await
        .unwrap(),
    )
    .await;

    assert_eq!(r.extracted_amount, Some(50_000));
    assert_eq!(r.expected_amount, Some(1_000_000));
    assert_eq!(r.amount_matches, Some(false));
}

#[tokio::test]
async fn ingest_tolerates_one_naira_difference() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(Some("₦9,999.50")); // 999,950 kobo — 50 kobo below 1,000,000

    let r = ingested(
        ingest_receipt(
            &db,
            input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_JID, "MID-TOL", &p),
        )
        .await
        .unwrap(),
    )
    .await;

    assert_eq!(r.amount_matches, Some(true), "within 1 NGN must match");
}

#[tokio::test]
async fn ingest_leaves_member_empty_when_sender_not_registered() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(Some("₦10,000.00"));

    let r = ingested(
        ingest_receipt(
            &db,
            input(FIXTURE_CHAT_ID, "2349999999999@c.us", "MID-NM", &p),
        )
        .await
        .unwrap(),
    )
    .await;

    assert!(!r.member_matched);
    assert!(r.cycle_matched, "active cycle still resolves");

    let rows: Vec<DbReceipt> = db.select("receipt").await.unwrap();
    let row = rows
        .iter()
        .find(|r| r.whatsapp_message_id == "MID-NM")
        .unwrap();
    assert!(row.member_id.is_none());
    assert_eq!(row.sender_phone, "2349999999999");
}

#[tokio::test]
async fn ingest_returns_duplicate_for_repeated_message_id() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(Some("₦10,000.00"));

    let first = ingest_receipt(
        &db,
        input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_JID, "MID-DUP", &p),
    )
    .await
    .unwrap();
    assert!(matches!(first, IngestionOutcome::Ingested(_)));

    let second = ingest_receipt(
        &db,
        input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_JID, "MID-DUP", &p),
    )
    .await
    .unwrap();
    assert!(matches!(second, IngestionOutcome::DuplicateMessage));

    let rows: Vec<DbReceipt> = db.select("receipt").await.unwrap();
    let matches: Vec<_> = rows
        .iter()
        .filter(|r| r.whatsapp_message_id == "MID-DUP")
        .collect();
    assert_eq!(matches.len(), 1, "duplicate must not insert a second row");
}

#[tokio::test]
async fn ingest_leaves_amount_none_when_parse_fails() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(None);

    let r = ingested(
        ingest_receipt(
            &db,
            input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_JID, "MID-NO-AMT", &p),
        )
        .await
        .unwrap(),
    )
    .await;

    assert_eq!(r.extracted_amount, None);
    assert_eq!(r.amount_matches, None);
}

#[tokio::test]
async fn ingest_accepts_raw_phone_without_jid_suffix() {
    let db = fresh_db().await;
    link_default_group(&db).await;
    let p = parsed(Some("₦10,000.00"));

    let r = ingested(
        ingest_receipt(
            &db,
            input(FIXTURE_CHAT_ID, FIXTURE_MEMBER_PHONE, "MID-RAW", &p),
        )
        .await
        .unwrap(),
    )
    .await;

    assert!(r.member_matched, "raw phone must still match stored member");
}
