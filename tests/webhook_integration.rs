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
    use poolpay::api::models::{now_iso, GroupLinkContent};
    let now = now_iso();
    let content = GroupLinkContent {
        chat_id: LINKED_CHAT_ID.into(),
        group_id: "1".into(),
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
    };
    let _: Option<poolpay::api::models::DbGroupLink> = db
        .create("group_link")
        .content(content)
        .await
        .expect("seed group_link");
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
    let resp = call(
        app,
        signed_request(&payload_matching_member("WAMSG-VALID-1")),
    )
    .await;
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
    assert!(
        s["receiptId"].is_null(),
        "duplicate must not echo a receipt id"
    );
}

#[tokio::test]
async fn webhook_concurrent_duplicate_deliveries_persist_single_row() {
    // TOCTOU regression guard. The sequential-duplicate test above exercises
    // the fast-path pre-check (`find_receipt_by_message_id`); this one fires
    // two identical webhook deliveries in parallel so both reads observe "no
    // row" before either insert lands. Without the DB-side UNIQUE index on
    // `receipt.whatsapp_message_id`, both inserts succeed and the admin
    // queue ends up with two pending rows for the same message. With the
    // index in place, exactly one insert wins, the other collapses to the
    // `Duplicate` outcome, and both clients still see a 200.
    let app = webhook_app().await;
    let body = payload_matching_member("WAMSG-CONCURRENT");
    let req1 = signed_request(&body);
    let req2 = signed_request(&body);

    let (resp1, resp2) = tokio::join!(call(app.clone(), req1), call(app.clone(), req2),);

    assert_eq!(
        resp1.status(),
        StatusCode::OK,
        "first request must return 200"
    );
    assert_eq!(
        resp2.status(),
        StatusCode::OK,
        "second request must return 200"
    );

    let body1: serde_json::Value = json_body(resp1).await;
    let body2: serde_json::Value = json_body(resp2).await;

    // Exactly one side ingests; the other collapses to the duplicate outcome.
    // Ordering is non-deterministic under `join!`, so accept either pairing.
    let outcomes = [
        body1["outcome"].as_str().unwrap_or(""),
        body2["outcome"].as_str().unwrap_or(""),
    ];
    let ingested = outcomes.iter().filter(|o| **o == "ingested").count();
    let duplicate = outcomes.iter().filter(|o| **o == "duplicate").count();
    assert_eq!(
        ingested, 1,
        "exactly one concurrent webhook delivery must ingest (outcomes={outcomes:?})"
    );
    assert_eq!(
        duplicate, 1,
        "the other concurrent delivery must collapse to duplicate (outcomes={outcomes:?})"
    );

    // The duplicate side must match the existing duplicate response shape —
    // no echoed receipt id, mirroring `webhook_duplicate_message_id_is_idempotent`.
    let duplicate_body = if body1["outcome"] == "duplicate" {
        &body1
    } else {
        &body2
    };
    assert!(
        duplicate_body["receiptId"].is_null(),
        "concurrent duplicate response must not echo a receiptId (body={duplicate_body})"
    );

    // And exactly one row must persist for the message id — the whole point
    // of the unique index is that the second insert never lands.
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
    let persisted: Vec<_> = receipts
        .iter()
        .filter(|r| r["whatsappMessageId"] == "WAMSG-CONCURRENT")
        .collect();
    assert_eq!(
        persisted.len(),
        1,
        "exactly one receipt row must persist for the duplicate message id (found {})",
        persisted.len()
    );
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

// ── `rawImageUrl` boundary validation ─────────────────────────────────────────

#[tokio::test]
async fn webhook_https_raw_image_url_ingests() {
    // Baseline: an absolute https URL passes the boundary check. Confirms
    // the new gate doesn't regress the existing happy path that ships a
    // screenshot URL alongside the payload.
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2348031234567",
        "messageId": "WAMSG-URL-HTTPS-OK",
        "ocrText": "",
        "receivedAt": "2026-03-10T10:00:00+00:00",
        "rawImageUrl": "https://example.com/receipt.jpg"
    });
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["outcome"], "ingested");
}

#[tokio::test]
async fn webhook_javascript_raw_image_url_returns_401() {
    // A `javascript:` URI would render as an executable link when an admin
    // clicks it in the FE review modal. The boundary check must reject and
    // collapse to the same opaque 401 used by the other payload gates.
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2348031234567",
        "messageId": "WAMSG-URL-JS",
        "ocrText": "",
        "receivedAt": "2026-03-10T10:00:00+00:00",
        "rawImageUrl": "javascript:alert(1)"
    });
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_relative_raw_image_url_returns_401() {
    // A relative path bypasses scheme checks at render time and resolves
    // against whatever origin happens to host the FE — admin-side XSS / data
    // exfiltration vector. Reject at the boundary.
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2348031234567",
        "messageId": "WAMSG-URL-RELATIVE",
        "ocrText": "",
        "receivedAt": "2026-03-10T10:00:00+00:00",
        "rawImageUrl": "/foo.png"
    });
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_missing_raw_image_url_still_ingests() {
    // Regression guard: `rawImageUrl` is optional. A bot post that omits
    // the field must continue to ingest cleanly — the validation only
    // applies when the field is `Some`.
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": LINKED_CHAT_ID,
        "senderPhone": "2348031234567",
        "messageId": "WAMSG-URL-NONE",
        "ocrText": "",
        "receivedAt": "2026-03-10T10:00:00+00:00"
    });
    let resp = call(app, signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["outcome"], "ingested");
}

#[tokio::test]
async fn webhook_trims_whitespace_padded_fields_and_routes() {
    // A bot post that ships `chatId` / `senderPhone` / `messageId` /
    // `rawImageUrl` with surrounding whitespace must still route to the
    // linked group, match the member by phone, and persist the canonical
    // (trimmed) values. Without boundary normalisation, the padded
    // `chatId` would miss the exact-match `group_link` lookup and the
    // ingest would collapse to `not_linked` even though the underlying
    // chat is wired up — exactly the kind of silent miss that hides for
    // weeks in prod.
    let app = webhook_app().await;
    let body = serde_json::json!({
        "chatId": format!("  {LINKED_CHAT_ID}  "),
        "senderPhone": "  2348031234567  ",
        "messageId": "  WAMSG-TRIMMED  ",
        "ocrText": "NGN 10,000.00\nFrom: Tunde Bakare",
        "parsed": {
            "sender": "Tunde Bakare",
            "bank": "GTBank",
            "amount": "10,000"
        },
        "receivedAt": "2026-03-10T10:00:00+00:00",
        "rawImageUrl": "  https://example.com/receipt.jpg  "
    });

    let resp = call(app.clone(), signed_request(&body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let webhook_resp: serde_json::Value = json_body(resp).await;
    assert_eq!(
        webhook_resp["outcome"], "ingested",
        "padded chatId must still route to the linked group (trim before lookup)"
    );
    assert_eq!(
        webhook_resp["memberMatched"], true,
        "padded senderPhone must still match the fixture member (trim before phone match)"
    );
    let receipt_id = webhook_resp["receiptId"]
        .as_str()
        .expect("ingested response must carry receiptId")
        .to_string();

    // Confirm the row persisted with canonical (trimmed) identifier
    // values. `/api/receipts` exposes `chatId`, `senderPhone`, and
    // `whatsappMessageId` to anonymous callers; `rawImageUrl` is admin-
    // gated and exercised in unit coverage of the trim path itself.
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
    assert_eq!(
        row["whatsappMessageId"], "WAMSG-TRIMMED",
        "persisted whatsappMessageId must be trimmed"
    );
    assert_eq!(
        row["chatId"], LINKED_CHAT_ID,
        "persisted chatId must be trimmed"
    );
    assert_eq!(
        row["senderPhone"], "2348031234567",
        "persisted senderPhone must be trimmed"
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
