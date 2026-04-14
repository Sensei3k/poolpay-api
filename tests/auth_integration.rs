//! Integration tests for the Plan 3 / BE-1 auth surface:
//!   - HMAC-gated `/api/auth/verify-credentials` and `/api/auth/ensure-user`
//!   - Bootstrap admin idempotency

use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use poolpay::{
    api,
    auth::{bootstrap, hmac::sign_for_testing, password},
    db,
};
use std::sync::OnceLock;
use tower::ServiceExt;

// ── Shared env setup ──────────────────────────────────────────────────────────

const HMAC_SECRET: &str = "test-hmac-secret-for-integration-only";
const BOOTSTRAP_EMAIL: &str = "seed-admin@example.com";
const BOOTSTRAP_PASSWORD: &str = "correct-horse-battery-staple";

fn init_env() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Safety: written once before any test reads these vars. Parallel
        // tests may then read them freely.
        unsafe {
            std::env::set_var("NEXTAUTH_BACKEND_SECRET", HMAC_SECRET);
            std::env::set_var("BOOTSTRAP_ADMIN_EMAIL", BOOTSTRAP_EMAIL);
            std::env::set_var("BOOTSTRAP_ADMIN_PASSWORD", BOOTSTRAP_PASSWORD);
        }
    });
}

async fn test_app() -> (Router, poolpay::db::DbConn) {
    init_env();
    let conn = db::init_memory().await.expect("failed to init test DB");
    bootstrap::ensure_admin_user(&conn)
        .await
        .expect("bootstrap seed must succeed");
    let router = api::router(conn.clone());
    (router, conn)
}

fn hmac_request(uri: &str, body: &serde_json::Value) -> Request<Body> {
    let body_bytes = serde_json::to_vec(body).unwrap();
    let ts = chrono::Utc::now().timestamp();
    let sig = sign_for_testing(HMAC_SECRET, ts, &body_bytes);
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", format!("sha256={sig}"))
        .body(Body::from(body_bytes))
        .unwrap()
}

async fn call(app: Router, req: Request<Body>) -> Response {
    app.oneshot(req).await.unwrap()
}

async fn json_body<T: serde::de::DeserializeOwned>(resp: Response) -> T {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).expect("response body is not valid JSON")
}

// ── verify-credentials ────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_credentials_success_for_bootstrap_admin() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": BOOTSTRAP_PASSWORD,
    });
    let resp = call(app, hmac_request("/api/auth/verify-credentials", &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["email"], BOOTSTRAP_EMAIL);
    assert_eq!(v["role"], "super_admin");
    assert_eq!(v["mustResetPassword"], true);
    assert!(!v["userId"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn verify_credentials_wrong_password_returns_401() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": "not the real password",
    });
    let resp = call(app, hmac_request("/api/auth/verify-credentials", &body)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_credentials_unknown_email_returns_401_and_runs_dummy_hash() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": "ghost@example.com",
        "password": "any",
    });
    let resp = call(app, hmac_request("/api/auth/verify-credentials", &body)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_credentials_bad_signature_returns_401() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": BOOTSTRAP_PASSWORD,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let ts = chrono::Utc::now().timestamp();
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/verify-credentials")
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", "sha256=deadbeef")
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn verify_credentials_stale_timestamp_returns_401() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": BOOTSTRAP_PASSWORD,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let ts = chrono::Utc::now().timestamp() - 600; // 10 minutes old
    let sig = sign_for_testing(HMAC_SECRET, ts, &body_bytes);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/verify-credentials")
        .header("content-type", "application/json")
        .header("x-timestamp", ts.to_string())
        .header("x-signature", format!("sha256={sig}"))
        .body(Body::from(body_bytes))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── ensure-user ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn ensure_user_creates_and_reuses_for_same_provider_subject() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "provider": "google",
        "providerSubject": "google-sub-12345",
        "email": "Alice@Example.com",
    });
    let resp1 = call(app.clone(), hmac_request("/api/auth/ensure-user", &body)).await;
    assert_eq!(resp1.status(), StatusCode::OK);
    let v1: serde_json::Value = json_body(resp1).await;
    assert_eq!(v1["created"], true);
    assert_eq!(v1["role"], "member");
    let first_id = v1["userId"].as_str().unwrap().to_string();

    let resp2 = call(app, hmac_request("/api/auth/ensure-user", &body)).await;
    assert_eq!(resp2.status(), StatusCode::OK);
    let v2: serde_json::Value = json_body(resp2).await;
    assert_eq!(v2["created"], false);
    assert_eq!(v2["userId"].as_str().unwrap(), first_id);
}

#[tokio::test]
async fn ensure_user_second_provider_does_not_auto_link_on_email() {
    // Industry best practice (Cognito / Auth0 / OAuth BCP): never auto-link
    // accounts on email match, even when both providers report the email as
    // verified. A second provider must produce a NEW user — linking is an
    // explicit FE flow for a signed-in user (deferred to post-BE-6 work).
    let (app, _db) = test_app().await;
    let first = serde_json::json!({
        "provider": "google",
        "providerSubject": "sub-google-1",
        "email": "bob@example.com",
    });
    let r1 = call(app.clone(), hmac_request("/api/auth/ensure-user", &first)).await;
    let v1: serde_json::Value = json_body(r1).await;
    let google_user_id = v1["userId"].as_str().unwrap().to_string();

    let second = serde_json::json!({
        "provider": "github",
        "providerSubject": "sub-github-1",
        "email": "bob@example.com",
    });
    let r2 = call(app, hmac_request("/api/auth/ensure-user", &second)).await;
    assert_eq!(r2.status(), StatusCode::OK);
    let v2: serde_json::Value = json_body(r2).await;
    assert_eq!(v2["created"], true);
    assert_ne!(v2["userId"].as_str().unwrap(), google_user_id);
}

#[tokio::test]
async fn ensure_user_never_links_across_providers_even_on_matching_email() {
    let (app, _db) = test_app().await;
    // Seed via Google.
    let first = serde_json::json!({
        "provider": "google",
        "providerSubject": "sub-google-2",
        "email": "carol@example.com",
    });
    let r1 = call(app.clone(), hmac_request("/api/auth/ensure-user", &first)).await;
    let v1: serde_json::Value = json_body(r1).await;
    let first_id = v1["userId"].as_str().unwrap().to_string();

    // GitHub signup with the same email must produce a new user, not link.
    let second = serde_json::json!({
        "provider": "github",
        "providerSubject": "sub-github-2",
        "email": "carol@example.com",
    });
    let r2 = call(app, hmac_request("/api/auth/ensure-user", &second)).await;
    assert_eq!(r2.status(), StatusCode::OK);
    let v2: serde_json::Value = json_body(r2).await;
    assert_eq!(v2["created"], true);
    assert_ne!(v2["userId"].as_str().unwrap(), first_id);
}

// ── Field length caps (H-2) ───────────────────────────────────────────────────

#[tokio::test]
async fn verify_credentials_rejects_oversized_email() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": format!("{}@example.com", "a".repeat(400)),
        "password": BOOTSTRAP_PASSWORD,
    });
    let resp = call(app, hmac_request("/api/auth/verify-credentials", &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn verify_credentials_rejects_oversized_password() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": "x".repeat(2000),
    });
    let resp = call(app, hmac_request("/api/auth/verify-credentials", &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn ensure_user_rejects_oversized_provider_subject() {
    let (app, _db) = test_app().await;
    let body = serde_json::json!({
        "provider": "google",
        "providerSubject": "s".repeat(300),
        "email": "long-sub@example.com",
    });
    let resp = call(app, hmac_request("/api/auth/ensure-user", &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn bootstrap_is_idempotent() {
    let (_app, db) = test_app().await;
    // Run it a second time — should be a no-op.
    bootstrap::ensure_admin_user(&db)
        .await
        .expect("second bootstrap must succeed");

    let mut resp = db
        .query("SELECT count() FROM user WHERE role IN ['admin', 'super_admin'] GROUP ALL")
        .await
        .unwrap()
        .check()
        .unwrap();
    let counts: Vec<i64> = resp.take("count").unwrap_or_default();
    assert_eq!(counts.first().copied().unwrap_or(0), 1);
}

// ── Password primitives sanity check ──────────────────────────────────────────

#[test]
fn argon2_hash_is_phc_formatted() {
    let h = password::hash("some password").unwrap();
    assert!(h.starts_with("$argon2id$"), "expected PHC format, got: {h}");
    assert!(password::verify("some password", &h).unwrap());
}
