/// Integration tests for the Axum REST API.
///
/// Each test spins up a fresh in-memory SurrealDB instance seeded with fixture
/// data, so tests are fully isolated and do not touch the filesystem.
///
/// Fixture counts (defined in db.rs):
///   - 6 members
///   - 3 cycles
///   - 15 payments (3 in cycle 3, 6 in cycle 1, 6 in cycle 2)
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use receipt_engine::{api, db};
use tower::ServiceExt;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Build a fresh app backed by an isolated in-memory DB.
async fn test_app() -> Router {
    let conn = db::init_memory().await.expect("failed to init test DB");
    api::router(conn)
}

/// Dispatch a single request through the router and return the response.
/// `oneshot` consumes the router; clone before calling if you need it again.
async fn call(app: Router, req: Request<Body>) -> Response {
    app.oneshot(req).await.unwrap()
}

/// Deserialize a response body as JSON.
async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body is not valid JSON")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn post_json(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn delete_req(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::DELETE)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

fn post_empty(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

// ── GET /api/members ──────────────────────────────────────────────────────────

#[tokio::test]
async fn get_members_returns_200() {
    let resp = call(test_app().await, get("/api/members")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_members_returns_six_members() {
    let resp = call(test_app().await, get("/api/members")).await;
    let members: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(members.len(), 6);
}

#[tokio::test]
async fn get_members_response_shape() {
    let resp = call(test_app().await, get("/api/members")).await;
    let members: Vec<serde_json::Value> = json_body(resp).await;
    let first = &members[0];
    assert!(first.get("id").is_some(), "missing id");
    assert!(first.get("name").is_some(), "missing name");
    assert!(first.get("phone").is_some(), "missing phone");
    assert!(first.get("position").is_some(), "missing position");
    assert!(first.get("status").is_some(), "missing status");
}

#[tokio::test]
async fn get_members_status_is_lowercase_string() {
    let resp = call(test_app().await, get("/api/members")).await;
    let members: Vec<serde_json::Value> = json_body(resp).await;
    for member in &members {
        let status = member["status"].as_str().expect("status must be a string");
        assert!(
            status == "active" || status == "inactive",
            "unexpected status value: {status}"
        );
    }
}

// ── GET /api/cycles ───────────────────────────────────────────────────────────

#[tokio::test]
async fn get_cycles_returns_200() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_cycles_returns_three_cycles() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(cycles.len(), 3);
}

#[tokio::test]
async fn get_cycles_response_shape() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    let c = &cycles[0];
    assert!(c.get("id").is_some(), "missing id");
    assert!(c.get("cycleNumber").is_some(), "missing cycleNumber");
    assert!(c.get("startDate").is_some(), "missing startDate");
    assert!(c.get("endDate").is_some(), "missing endDate");
    assert!(c.get("contributionPerMember").is_some(), "missing contributionPerMember");
    assert!(c.get("totalAmount").is_some(), "missing totalAmount");
    assert!(c.get("recipientMemberId").is_some(), "missing recipientMemberId");
    assert!(c.get("status").is_some(), "missing status");
}

#[tokio::test]
async fn get_cycles_has_one_active_cycle() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    let active = cycles.iter().filter(|c| c["status"] == "active").count();
    assert_eq!(active, 1, "expected exactly one active cycle");
}

#[tokio::test]
async fn get_cycles_status_values_are_valid() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    for cycle in &cycles {
        let status = cycle["status"].as_str().expect("status must be a string");
        assert!(
            status == "active" || status == "closed",
            "unexpected status value: {status}"
        );
    }
}

// ── GET /api/payments ─────────────────────────────────────────────────────────

#[tokio::test]
async fn get_payments_returns_200() {
    let resp = call(test_app().await, get("/api/payments")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_payments_returns_fifteen_total() {
    let resp = call(test_app().await, get("/api/payments")).await;
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 15);
}

#[tokio::test]
async fn get_payments_response_shape() {
    let resp = call(test_app().await, get("/api/payments")).await;
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    let p = &payments[0];
    assert!(p.get("id").is_some(), "missing id");
    assert!(p.get("memberId").is_some(), "missing memberId");
    assert!(p.get("cycleId").is_some(), "missing cycleId");
    assert!(p.get("amount").is_some(), "missing amount");
    assert!(p.get("currency").is_some(), "missing currency");
    assert!(p.get("paymentDate").is_some(), "missing paymentDate");
}

#[tokio::test]
async fn get_payments_filter_by_cycle_id_returns_subset() {
    let resp = call(test_app().await, get("/api/payments?cycleId=3")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 3, "cycle 3 should have 3 fixture payments");
    for p in &payments {
        assert_eq!(p["cycleId"], 3, "all returned payments must belong to cycle 3");
    }
}

#[tokio::test]
async fn get_payments_filter_cycle_1_returns_six() {
    let resp = call(test_app().await, get("/api/payments?cycleId=1")).await;
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 6, "cycle 1 should have 6 fixture payments");
}

#[tokio::test]
async fn get_payments_filter_unknown_cycle_returns_empty() {
    let resp = call(test_app().await, get("/api/payments?cycleId=999")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert!(payments.is_empty(), "unknown cycle should return empty array");
}

// ── POST /api/payments ────────────────────────────────────────────────────────

#[tokio::test]
async fn create_payment_returns_201() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4,
                "cycleId": 3,
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn create_payment_response_shape() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4,
                "cycleId": 3,
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    let payment: serde_json::Value = json_body(resp).await;
    assert!(payment.get("id").is_some(), "missing id");
    assert_eq!(payment["memberId"], 4);
    assert_eq!(payment["cycleId"], 3);
    assert_eq!(payment["amount"], 1_000_000);
    assert_eq!(payment["currency"], "NGN");
    assert_eq!(payment["paymentDate"], "2026-03-10");
}

#[tokio::test]
async fn create_payment_persists_to_db() {
    let app = test_app().await;

    call(
        app.clone(),
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4,
                "cycleId": 3,
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;

    // Cycle 3 should now have 4 payments (3 fixture + 1 new).
    let resp = call(app, get("/api/payments?cycleId=3")).await;
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 4, "cycle 3 should now have 4 payments");
}

#[tokio::test]
async fn create_payment_zero_amount_returns_400() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4, "cycleId": 3,
                "amount": 0, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_negative_amount_returns_400() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4, "cycleId": 3,
                "amount": -500, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_invalid_currency_returns_400() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4, "cycleId": 3,
                "amount": 1_000_000, "currency": "USD", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_invalid_date_format_returns_400() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4, "cycleId": 3,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "10-03-2026"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_empty_date_returns_400() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4, "cycleId": 3,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": ""
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_invalid_member_id_returns_400() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 0, "cycleId": 3,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_nonexistent_member_returns_404() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 999, "cycleId": 3,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_payment_nonexistent_cycle_returns_404() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 1, "cycleId": 999,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── DELETE /api/payments/:memberId/:cycleId ───────────────────────────────────

#[tokio::test]
async fn delete_payment_returns_204() {
    // Member 1 paid in cycle 3 (fixture payment id=1).
    let resp = call(test_app().await, delete_req("/api/payments/1/3")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_payment_removes_record_from_db() {
    let app = test_app().await;

    // Confirm baseline: cycle 3 has 3 fixture payments.
    let before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments?cycleId=3")).await).await;
    assert_eq!(before.len(), 3);

    // Delete member 1's payment in cycle 3.
    call(app.clone(), delete_req("/api/payments/1/3")).await;

    // One fewer payment remains.
    let after: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments?cycleId=3")).await).await;
    assert_eq!(after.len(), 2);
}

#[tokio::test]
async fn delete_payment_unknown_member_returns_404() {
    let resp = call(test_app().await, delete_req("/api/payments/999/3")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_payment_unknown_cycle_returns_404() {
    let resp = call(test_app().await, delete_req("/api/payments/1/999")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_payment_404_body_has_error_field() {
    let resp = call(test_app().await, delete_req("/api/payments/999/3")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = json_body(resp).await;
    assert!(
        body.get("error").is_some(),
        "404 response must have an 'error' field"
    );
}

// ── POST /api/test/reset ──────────────────────────────────────────────────────

#[tokio::test]
async fn reset_endpoint_returns_200() {
    let resp = call(test_app().await, post_empty("/api/test/reset")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn reset_restores_payments_to_fixture_count() {
    let app = test_app().await;

    // Add an extra payment.
    call(
        app.clone(),
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 4, "cycleId": 3,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;

    // Reset to fixture state.
    call(app.clone(), post_empty("/api/test/reset")).await;

    // Back to 15.
    let payments: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments")).await).await;
    assert_eq!(payments.len(), 15, "reset should restore 15 fixture payments");
}

#[tokio::test]
async fn reset_restores_members() {
    let app = test_app().await;
    call(app.clone(), post_empty("/api/test/reset")).await;
    let members: Vec<serde_json::Value> =
        json_body(call(app, get("/api/members")).await).await;
    assert_eq!(members.len(), 6);
}

#[tokio::test]
async fn reset_restores_cycles() {
    let app = test_app().await;
    call(app.clone(), post_empty("/api/test/reset")).await;
    let cycles: Vec<serde_json::Value> =
        json_body(call(app, get("/api/cycles")).await).await;
    assert_eq!(cycles.len(), 3);
}

// ── Error response contract ───────────────────────────────────────────────────

#[tokio::test]
async fn bad_request_error_has_json_error_field() {
    let resp = call(
        test_app().await,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": 0, "cycleId": 3,
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body: serde_json::Value = json_body(resp).await;
    assert!(body.get("error").is_some(), "400 must have an 'error' field");
    assert!(body["error"].is_string(), "'error' must be a string");
}

#[tokio::test]
async fn not_found_error_has_json_error_field() {
    let resp = call(test_app().await, delete_req("/api/payments/999/999")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = json_body(resp).await;
    assert!(body.get("error").is_some(), "404 must have an 'error' field");
}
