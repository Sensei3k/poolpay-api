//! Integration tests for the receipt-routing helpers.
//!
//! These tests exercise `src/routing.rs` directly against a fresh
//! in-memory SurrealDB seeded with the standard fixtures. They do not
//! go through the Axum router, so they isolate query behaviour from
//! handler/auth concerns.

use poolpay::api::models::{DbGroupLink, EntityId, GroupLinkContent, now_iso};
use poolpay::db::{self, DbConn};
use poolpay::routing::{
    find_active_cycle, find_group_by_chat_id, find_member_by_phone, find_receipt_by_message_id,
};

const FIXTURE_GROUP_ID: &str = "1";
const FIXTURE_CHAT_ID: &str = "2349000000001@g.us";

async fn fresh_db() -> DbConn {
    db::init_memory().await.expect("failed to init test DB")
}

async fn seed_link(db: &DbConn, chat_id: &str, group_id: &str) {
    let now = now_iso();
    let created: Option<DbGroupLink> = db
        .create("group_link")
        .content(GroupLinkContent {
            chat_id: chat_id.into(),
            group_id: group_id.into(),
            created_at: now.clone(),
            updated_at: now,
            deleted_at: None,
        })
        .await
        .expect("seed link failed");
    assert!(created.is_some(), "group_link insert returned None");
}

// ── find_group_by_chat_id ────────────────────────────────────────────────────

#[tokio::test]
async fn group_by_chat_id_returns_none_when_no_link() {
    let db = fresh_db().await;
    let g = find_group_by_chat_id(&db, FIXTURE_CHAT_ID).await.unwrap();
    assert!(g.is_none());
}

#[tokio::test]
async fn group_by_chat_id_returns_group_when_linked() {
    let db = fresh_db().await;
    seed_link(&db, FIXTURE_CHAT_ID, FIXTURE_GROUP_ID).await;
    let g = find_group_by_chat_id(&db, FIXTURE_CHAT_ID).await.unwrap();
    let g = g.expect("expected group lookup to succeed");
    assert_eq!(g.name, "PoolPay Group Alpha");
}

#[tokio::test]
async fn group_by_chat_id_ignores_soft_deleted_link() {
    let db = fresh_db().await;
    let now = now_iso();
    let _: Option<DbGroupLink> = db
        .create("group_link")
        .content(GroupLinkContent {
            chat_id: FIXTURE_CHAT_ID.into(),
            group_id: FIXTURE_GROUP_ID.into(),
            created_at: now.clone(),
            updated_at: now.clone(),
            deleted_at: Some(now),
        })
        .await
        .unwrap();

    let g = find_group_by_chat_id(&db, FIXTURE_CHAT_ID).await.unwrap();
    assert!(g.is_none(), "soft-deleted link must not resolve to a group");
}

#[tokio::test]
async fn group_by_chat_id_unknown_chat_returns_none() {
    let db = fresh_db().await;
    seed_link(&db, FIXTURE_CHAT_ID, FIXTURE_GROUP_ID).await;
    let g = find_group_by_chat_id(&db, "1111@g.us").await.unwrap();
    assert!(g.is_none());
}

// ── find_member_by_phone ─────────────────────────────────────────────────────

#[tokio::test]
async fn member_by_phone_returns_match_in_group() {
    let db = fresh_db().await;
    let group_id: EntityId = FIXTURE_GROUP_ID.into();
    let m = find_member_by_phone(&db, &group_id, "2348101234567")
        .await
        .unwrap();
    let m = m.expect("expected to find Adaeze");
    assert_eq!(m.name, "Adaeze Okonkwo");
}

#[tokio::test]
async fn member_by_phone_returns_none_for_unknown_phone() {
    let db = fresh_db().await;
    let group_id: EntityId = FIXTURE_GROUP_ID.into();
    let m = find_member_by_phone(&db, &group_id, "999")
        .await
        .unwrap();
    assert!(m.is_none());
}

#[tokio::test]
async fn member_by_phone_returns_none_for_unknown_group() {
    // A phone that matches a fixture member must not resolve when the
    // supplied group_id does not exist — the query is group-scoped.
    let db = fresh_db().await;
    let other: EntityId = "does-not-exist".into();
    let m = find_member_by_phone(&db, &other, "2348101234567")
        .await
        .unwrap();
    assert!(m.is_none());
}

// ── find_active_cycle ────────────────────────────────────────────────────────

#[tokio::test]
async fn active_cycle_returns_the_active_one() {
    let db = fresh_db().await;
    let group_id: EntityId = FIXTURE_GROUP_ID.into();
    let c = find_active_cycle(&db, &group_id).await.unwrap();
    let c = c.expect("expected one active cycle");
    assert_eq!(c.status, "active");
}

#[tokio::test]
async fn active_cycle_returns_none_for_unknown_group() {
    let db = fresh_db().await;
    let other: EntityId = "no-such-group".into();
    let c = find_active_cycle(&db, &other).await.unwrap();
    assert!(c.is_none());
}

// ── find_receipt_by_message_id ───────────────────────────────────────────────

#[tokio::test]
async fn receipt_by_message_id_returns_existing_receipt() {
    let db = fresh_db().await;
    let r = find_receipt_by_message_id(&db, "3EB0C123ABCD4567EF89")
        .await
        .unwrap();
    let r = r.expect("expected fixture receipt 1");
    assert_eq!(r.status, "pending");
}

#[tokio::test]
async fn receipt_by_message_id_returns_none_for_unknown_id() {
    let db = fresh_db().await;
    let r = find_receipt_by_message_id(&db, "no-such-message")
        .await
        .unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn receipt_by_message_id_excludes_soft_deleted() {
    // Fixture receipt 2 has deleted_at set.
    let db = fresh_db().await;
    let r = find_receipt_by_message_id(&db, "3EB0C9876FEDC543210")
        .await
        .unwrap();
    assert!(r.is_none(), "soft-deleted receipt must not be returned");
}
