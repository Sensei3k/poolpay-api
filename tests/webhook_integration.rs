//! Integration tests for `POST /api/webhooks/whatsapp` (Slice 5 BE).
//!
//! Covers the HMAC gate (mounted on `WA_WEBHOOK_SECRET`), payload validation,
//! and the bot-facing response shape produced by routing each
//! `IngestionOutcome` variant. Every helper here lives in this file rather
//! than the shared auth helpers because the webhook is signed with a
//! distinct secret — mixing the two would let an integration test
//! accidentally hide a secret-binding regression.

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use poolpay::{api, auth::hmac::sign_for_testing, db};
use std::sync::{Mutex, OnceLock};
use tower::ServiceExt;

const WEBHOOK_SECRET: &str = "test-wa-webhook-secret-for-integration-only";

/// Test-only chat id matching the seeded `group_link` row.
const LINKED_CHAT_ID: &str = "2349000000001@g.us";

/// Single global lock for env mutations across the whole binary.
///
/// `std::env::set_var` is `unsafe` and requires that no other thread
/// reads or writes any env var concurrently. Per-test `OnceLock`s keep
/// each helper's first-time setter to one call, but two distinct helpers
/// firing under parallel `cargo test` would still race without this lock.
fn env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

/// One-time env setup: pin `APP_ENV=test` (so the JWT verifier takes its
/// ephemeral-key branch) and bind the webhook secret to a known value.
/// Mirrors the pattern in `tests/auth_integration.rs`.
fn init_env() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _guard = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        // SAFETY: serialised by `env_lock()` above; called once before any
        // test reads these vars.
        unsafe {
            std::env::set_var("APP_ENV", "test");
            std::env::set_var("WA_WEBHOOK_SECRET", WEBHOOK_SECRET);
            std::env::remove_var("JWT_KEYS");
        }
    });
}

async fn webhook_app() -> Router {
    init_env();
    let conn = db::init_memory().await.expect("init test DB");
    seed_link(&conn).await;
    api::router(conn)
}

/// Seed a `group_link` for the fixture group so the matcher resolves
/// `LINKED_CHAT_ID` → group `1` (and therefore can find the seeded members).
/// Without this, every ingest path would short-circuit on `NotLinked`.
async fn seed_link(db: &poolpay::db::DbConn) {
    use poolpay::api::models::{GroupLinkContent, now_iso};
    let now = now_iso();
    let content = GroupLinkContent {
        chat_id: LINKED_CHAT_ID.into(),
        group_id: "1".into(),
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
    };
    let _: Option<poolpay::api::models::DbGroupLink> =
        db.create("group_link").content(content).await.expect("seed group_link");
}

fn now_ts() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Build a properly-signed webhook request.
fn signed_request(body: &serde_json::Value) -> Request<Body> {
    signed_request_with_ts(body, now_ts())
}

fn signed_request_with_ts(body: &serde_json::Value, ts: i64) -> Request<Body> {
    let bytes = serde_json::to_vec(body).unwrap();
    let sig = sign_for_testing(WEBHOOK_SECRET, ts, &bytes);
    Request::builder()
        .method(Method::POST)
        .uri("/api/webhooks/whatsapp")
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", format!("sha256={sig}"))
        .body(Body::from(bytes))
        .unwrap()
}

async fn call(app: Router, req: Request<Body>) -> Response {
    app.oneshot(req).await.unwrap()
}

async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body is not valid JSON")
}

/// Helper: a payload from a phone that matches member 4 (Tunde Bakare) in
/// the fixture group. Uses a fresh message id so each test can ingest
/// independently.
fn payload_matching_member(message_id: &str) -> serde_json::Value {
    serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2348031234567",
        "messageId": message_id,
        "ocrText": "NGN 10,000.00\nFrom: Tunde Bakare",
        "parsed": {
            "sender": "Tunde Bakare",
            "bank": "GTBank",
            "amount": "10,000"
        },
        "receivedAt": "2026-03-10T10:00:00+00:00",
        "rawImageUrl": "https://example.com/receipt.jpg"
    })
}

// ── Auth gate (HMAC) ──────────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_valid_hmac_ingests_returns_200() {
    let app = webhook_app().await;
    let resp = call(app, signed_request(&payload_matching_member("WAMSG-VALID-1"))).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["outcome"], "ingested");
    assert!(body["receiptId"].as_str().is_some_and(|s| !s.is_empty()));
}

#[tokio::test]
async fn webhook_wrong_secret_returns_401() {
    // The binary as a whole sets WA_WEBHOOK_SECRET on first use, so we
    // cannot un-set it without racing every other test in this file —
    // dedicated "unset secret" coverage lives in unit tests for
    // `resolve_secret`. Here we exercise the wrong-secret / invalid
    // signature branch: the resolver loads the real secret, but the
    // signature fails verification and the request collapses to 401.
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-MISSING-SECRET");
    let bytes = serde_json::to_vec(&body).unwrap();
    let ts = now_ts();
    // Different secret — produces a non-matching signature.
    let bad_sig = sign_for_testing("a-secret-the-server-does-not-have", ts, &bytes);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/webhooks/whatsapp")
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", format!("sha256={bad_sig}"))
        .body(Body::from(bytes))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_expired_timestamp_returns_401() {
    // 5 minutes in the past — well outside the ±60 s replay window.
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-EXPIRED");
    let resp = call(app, signed_request_with_ts(&body, now_ts() - 300)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_future_timestamp_returns_401() {
    // 5 minutes in the future — outside the symmetric replay window.
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-FUTURE");
    let resp = call(app, signed_request_with_ts(&body, now_ts() + 300)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_bad_signature_returns_401() {
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-BAD-SIG");
    let bytes = serde_json::to_vec(&body).unwrap();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/webhooks/whatsapp")
        .header("content-type", "application/json")
        .header("x-timestamp", now_ts().to_string())
        // Constant-length hex that is definitely not the real signature.
        .header(
            "x-signature",
            "sha256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        )
        .body(Body::from(bytes))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_oversized_body_returns_401() {
    // Body just over the 1 MiB hard cap. `to_bytes` aborts before the
    // signature check even runs, so the request collapses to 401. The
    // 401 (not 413) is intentional — the cap is part of the auth gate.
    let app = webhook_app().await;
    let oversized = "x".repeat(1024 * 1024 + 8);
    let body = serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2348031234567",
        "messageId": "WAMSG-OVERSIZE",
        "ocrText": oversized,
        "receivedAt": "2026-03-10T10:00:00+00:00"
    });
    let ts = now_ts();
    let bytes = serde_json::to_vec(&body).unwrap();
    let sig = sign_for_testing(WEBHOOK_SECRET, ts, &bytes);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/webhooks/whatsapp")
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", format!("sha256={sig}"))
        .body(Body::from(bytes))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_malformed_json_returns_401() {
    // Garbage body, signed correctly. The HMAC verifies, but
    // `serde_json::from_slice` fails — the extractor collapses that to
    // 401 too, since exposing "valid sig but bad JSON" gives an attacker
    // a probe oracle for valid secret guesses.
    let app = webhook_app().await;
    let ts = now_ts();
    let bytes: Vec<u8> = b"{not-json".to_vec();
    let sig = sign_for_testing(WEBHOOK_SECRET, ts, &bytes);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/webhooks/whatsapp")
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", format!("sha256={sig}"))
        .body(Body::from(bytes))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Matcher branches ──────────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_unknown_chat_id_returns_not_linked() {
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": "9999999999999@g.us",
        "senderPhone": "2348031234567",
        "messageId": "WAMSG-NO-LINK",
        "ocrText": "",
        "receivedAt": "2026-03-10T10:00:00+00:00"
    });
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["outcome"], "not_linked");
}

#[tokio::test]
async fn webhook_duplicate_message_id_is_idempotent() {
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-DUP");

    let first = call(app.clone(), signed_request(&body)).await;
    assert_eq!(first.status(), StatusCode::OK);
    let f: serde_json::Value = json_body(first).await;
    assert_eq!(f["outcome"], "ingested");

    let second = call(app, signed_request(&body)).await;
    assert_eq!(second.status(), StatusCode::OK);
    let s: serde_json::Value = json_body(second).await;
    assert_eq!(s["outcome"], "duplicate");
    assert!(s["receiptId"].is_null(), "duplicate must not echo a receipt id");
}

#[tokio::test]
async fn webhook_sender_phone_matches_member() {
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-MATCH-MEMBER");
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["outcome"], "ingested");
    assert_eq!(
        v["memberMatched"], true,
        "member matching must surface when the phone hits a fixture member"
    );
}

#[tokio::test]
async fn webhook_sender_phone_no_match_still_ingests() {
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2340000000000",
        "messageId": "WAMSG-NO-MATCH",
        "ocrText": "NGN 10,000.00",
        "parsed": {},
        "receivedAt": "2026-03-10T10:00:00+00:00"
    });
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["outcome"], "ingested");
    assert_eq!(
        v["memberMatched"], false,
        "unknown sender phone must ingest with memberMatched=false"
    );
}

#[tokio::test]
async fn webhook_persists_receipt_row_visible_to_admin_list() {
    // End-to-end persistence check: a successful webhook ingest must show
    // up in `GET /api/receipts`. Confirms the receipt row materialises
    // through the same listing the FE admin queue consumes.
    //
    // `GET /api/receipts` is a public read endpoint, so it deliberately
    // strips bot-supplied (`rawImageUrl`) and admin-supplied
    // (`rejectionReason`) fields — we assert the row appears and carries
    // the public identifiers, and that the sensitive fields are absent.
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-PERSIST");

    let resp = call(app.clone(), signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let webhook_resp: serde_json::Value = json_body(resp).await;
    let receipt_id = webhook_resp["receiptId"]
        .as_str()
        .expect("ingested response must carry receiptId")
        .to_string();

    let list = call(
        app,
        Request::builder()
            .method(Method::GET)
            .uri("/api/receipts?limit=200")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(list.status(), StatusCode::OK);
    let receipts: Vec<serde_json::Value> = json_body(list).await;
    let row = receipts
        .iter()
        .find(|r| r["id"] == receipt_id)
        .expect("ingested receipt must appear in /api/receipts");
    assert_eq!(row["whatsappMessageId"], "WAMSG-PERSIST");
    assert!(
        row.get("rawImageUrl").is_none(),
        "public /api/receipts must not expose bot-supplied rawImageUrl"
    );
    assert!(
        row.get("rejectionReason").is_none(),
        "public /api/receipts must not expose admin-supplied rejectionReason"
    );
}
