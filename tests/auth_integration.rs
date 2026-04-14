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
use axum::{
    extract::{Path, State},
    http::StatusCode as AxumStatus,
    routing::get,
    Extension as AxumExtension,
};
use poolpay::{
    api,
    auth::{
        bootstrap,
        extractors::{require_group_scope, AuthenticatedUser, SuperAdminUser},
        hmac::sign_for_testing,
        jwt::{JwtConfig, SharedVerifier, StaticKeyVerifier},
        password,
        rate_limit::{RateLimitConfig, TEST_PEER_IP_HEADER},
        refresh,
    },
    db,
};
use std::sync::{Arc, OnceLock};
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
    let (r, d, _v) = build_app_full(lax_rate_cfg()).await;
    (r, d)
}

async fn build_app(rate_cfg: RateLimitConfig) -> (Router, poolpay::db::DbConn) {
    let (r, d, _v) = build_app_full(rate_cfg).await;
    (r, d)
}

async fn build_app_full(
    rate_cfg: RateLimitConfig,
) -> (Router, poolpay::db::DbConn, SharedVerifier) {
    init_env();
    let conn = db::init_memory().await.expect("failed to init test DB");
    bootstrap::ensure_admin_user(&conn)
        .await
        .expect("bootstrap seed must succeed");
    let verifier = test_verifier();
    let router = api::router_with_config(conn.clone(), rate_cfg, verifier.clone());
    (router, conn, verifier)
}

fn test_verifier() -> SharedVerifier {
    Arc::new(
        StaticKeyVerifier::from_env(JwtConfig {
            audience: "poolpay-api".into(),
            issuer: "poolpay-nextauth".into(),
            access_ttl_secs: 900,
            leeway_secs: 60,
        })
        .expect("test verifier"),
    )
}

/// Non-restrictive config used by every non-rate-limit test. Large buckets so
/// the existing tests cannot trip a 429 by accident.
fn lax_rate_cfg() -> RateLimitConfig {
    RateLimitConfig {
        per_ip_per_minute: 60,
        per_ip_burst: 1000,
        credential_failure_limit: 1000,
        credential_failure_window_secs: 900,
        trust_proxy_headers: false,
        test_mode: true,
    }
}

fn hmac_request_with_ip(uri: &str, body: &serde_json::Value, peer_ip: &str) -> Request<Body> {
    let mut req = hmac_request(uri, body);
    req.headers_mut().insert(
        TEST_PEER_IP_HEADER,
        peer_ip.parse().expect("valid header value"),
    );
    req
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

// ── Rate limiting (Plan 3 / BE-2) ─────────────────────────────────────────────

fn strict_credential_cfg() -> RateLimitConfig {
    // Composite limiter: 5 failures per 900s. Per-IP stays generous so it
    // doesn't overshadow the composite limit in these tests.
    RateLimitConfig {
        per_ip_per_minute: 60,
        per_ip_burst: 1000,
        credential_failure_limit: 5,
        credential_failure_window_secs: 900,
        trust_proxy_headers: false,
        test_mode: true,
    }
}

fn strict_per_ip_cfg() -> RateLimitConfig {
    // Per-IP limiter with a tiny burst so tests can exhaust it in-process.
    // `per_ip_per_minute=1` → one replenish per minute; burst=2 means the
    // third consecutive hit gets 429 without any risk of a token refilling
    // mid-test on slow CI.
    RateLimitConfig {
        per_ip_per_minute: 1,
        per_ip_burst: 2,
        credential_failure_limit: 1000,
        credential_failure_window_secs: 900,
        trust_proxy_headers: false,
        test_mode: true,
    }
}

#[tokio::test]
async fn credential_failure_limit_returns_429_after_limit() {
    let (app, _db) = build_app(strict_credential_cfg()).await;
    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": "wrong",
    });

    for _ in 0..5 {
        let resp = call(
            app.clone(),
            hmac_request_with_ip("/api/auth/verify-credentials", &body, "10.0.0.1"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // 6th failure from the same (ip, email) exhausts the bucket → 429.
    let resp = call(
        app,
        hmac_request_with_ip("/api/auth/verify-credentials", &body, "10.0.0.1"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        resp.headers().contains_key("retry-after"),
        "429 must carry a Retry-After header"
    );
}

#[tokio::test]
async fn credential_failure_limit_isolates_by_email() {
    let (app, _db) = build_app(strict_credential_cfg()).await;

    // Exhaust the bucket for ghost-a@.
    let body_a = serde_json::json!({ "email": "ghost-a@example.com", "password": "x" });
    for _ in 0..5 {
        let resp = call(
            app.clone(),
            hmac_request_with_ip("/api/auth/verify-credentials", &body_a, "10.0.0.2"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Same IP, different email → still 401, not 429.
    let body_b = serde_json::json!({ "email": "ghost-b@example.com", "password": "x" });
    let resp = call(
        app,
        hmac_request_with_ip("/api/auth/verify-credentials", &body_b, "10.0.0.2"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_failure_limit_isolates_by_ip() {
    let (app, _db) = build_app(strict_credential_cfg()).await;
    let body = serde_json::json!({ "email": "ghost@example.com", "password": "x" });

    for _ in 0..5 {
        let resp = call(
            app.clone(),
            hmac_request_with_ip("/api/auth/verify-credentials", &body, "10.0.0.3"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Different IP, same email → still 401, not 429.
    let resp = call(
        app,
        hmac_request_with_ip("/api/auth/verify-credentials", &body, "10.0.0.99"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn credential_failure_limit_is_not_consumed_by_success() {
    let (app, _db) = build_app(strict_credential_cfg()).await;

    // Burn 4 failures against the real admin account.
    let bad = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": "wrong",
    });
    for _ in 0..4 {
        let resp = call(
            app.clone(),
            hmac_request_with_ip("/api/auth/verify-credentials", &bad, "10.0.0.4"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // A correct password must not consume the remaining slot.
    let good = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": BOOTSTRAP_PASSWORD,
    });
    let ok = call(
        app.clone(),
        hmac_request_with_ip("/api/auth/verify-credentials", &good, "10.0.0.4"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);

    // Hence one more failure is still allowed (5th failure total, still 401).
    let resp5 = call(
        app.clone(),
        hmac_request_with_ip("/api/auth/verify-credentials", &bad, "10.0.0.4"),
    )
    .await;
    assert_eq!(resp5.status(), StatusCode::UNAUTHORIZED);

    // The 6th failure finally exhausts the bucket.
    let resp6 = call(
        app,
        hmac_request_with_ip("/api/auth/verify-credentials", &bad, "10.0.0.4"),
    )
    .await;
    assert_eq!(resp6.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn per_ip_limit_returns_429_after_burst() {
    let (app, _db) = build_app(strict_per_ip_cfg()).await;
    let body = serde_json::json!({
        "provider": "google",
        "providerSubject": "sub-rate-1",
        "email": "rate@example.com",
    });

    // First two requests fit the burst.
    for _ in 0..2 {
        let resp = call(
            app.clone(),
            hmac_request_with_ip("/api/auth/ensure-user", &body, "10.0.1.1"),
        )
        .await;
        // Either 200 (first) or 200 (second idempotent); never 429 yet.
        assert!(
            resp.status() == StatusCode::OK,
            "first burst hits must succeed, got {}",
            resp.status()
        );
    }

    // Third consecutive hit from the same IP exceeds the burst → 429. Tower
    // governor replies 429 before the handler runs, so HMAC validity is
    // irrelevant.
    let resp = call(
        app,
        hmac_request_with_ip("/api/auth/ensure-user", &body, "10.0.1.1"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn per_ip_limit_isolates_by_ip() {
    let (app, _db) = build_app(strict_per_ip_cfg()).await;
    let body = serde_json::json!({
        "provider": "google",
        "providerSubject": "sub-rate-2",
        "email": "rate2@example.com",
    });

    // Exhaust the bucket from one IP.
    for _ in 0..2 {
        let _ = call(
            app.clone(),
            hmac_request_with_ip("/api/auth/ensure-user", &body, "10.0.2.1"),
        )
        .await;
    }
    let blocked = call(
        app.clone(),
        hmac_request_with_ip("/api/auth/ensure-user", &body, "10.0.2.1"),
    )
    .await;
    assert_eq!(blocked.status(), StatusCode::TOO_MANY_REQUESTS);

    // A fresh IP must not inherit the neighbour's empty bucket.
    let other = serde_json::json!({
        "provider": "google",
        "providerSubject": "sub-rate-2",
        "email": "rate2@example.com",
    });
    let ok = call(
        app,
        hmac_request_with_ip("/api/auth/ensure-user", &other, "10.0.2.99"),
    )
    .await;
    assert_eq!(ok.status(), StatusCode::OK);
}

// ── Refresh rotation + logout (Plan 3 / BE-3) ────────────────────────────────

/// Provision a member user via the public ensure-user endpoint so we get a
/// real `user_id` string without reaching into `pub(crate)` helpers.
async fn seed_member(app: &Router, subject: &str, email: &str) -> String {
    let body = serde_json::json!({
        "provider": "google",
        "providerSubject": subject,
        "email": email,
    });
    let resp = call(app.clone(), hmac_request("/api/auth/ensure-user", &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    v["userId"].as_str().unwrap().to_string()
}

fn refresh_req(token: &str) -> Request<Body> {
    let body = serde_json::json!({ "refreshToken": token });
    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/refresh")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn logout_req(token: &str) -> Request<Body> {
    let body = serde_json::json!({ "refreshToken": token });
    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/logout")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

#[tokio::test]
async fn refresh_rotates_and_invalidates_the_old_token() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-refresh-1", "refresh1@example.com").await;

    let issued = refresh::issue(&db, &user_id).await.expect("issue");
    let original = issued.plaintext;

    let resp = call(app.clone(), refresh_req(&original)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    let new_refresh = v["refreshToken"].as_str().unwrap().to_string();
    assert!(!v["accessToken"].as_str().unwrap().is_empty());
    assert_ne!(new_refresh, original, "rotation must mint a new token");

    // Presenting the original token again is the reuse signal: it's already
    // revoked, so the endpoint returns 401 and the rotation chain is killed.
    let replay = call(app.clone(), refresh_req(&original)).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    // The freshly rotated token should also now be dead — family was revoked
    // as part of reuse detection on the replay.
    let after_reuse = call(app, refresh_req(&new_refresh)).await;
    assert_eq!(after_reuse.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_reuse_bumps_token_version() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-refresh-2", "refresh2@example.com").await;

    let version_before = user_token_version(&db, &user_id).await;

    let issued = refresh::issue(&db, &user_id).await.expect("issue");
    let original = issued.plaintext;

    // First rotate succeeds.
    let ok = call(app.clone(), refresh_req(&original)).await;
    assert_eq!(ok.status(), StatusCode::OK);

    // Replay the now-revoked token: server must bump token_version and 401.
    let replay = call(app, refresh_req(&original)).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    let version_after = user_token_version(&db, &user_id).await;
    assert!(
        version_after > version_before,
        "token_version must advance on reuse detection: before={version_before} after={version_after}"
    );
}

#[tokio::test]
async fn refresh_unknown_token_returns_401() {
    let (app, _db) = test_app().await;
    let resp = call(app, refresh_req("not-a-real-token")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn logout_revokes_family_and_always_returns_204() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-logout-1", "logout1@example.com").await;

    let issued = refresh::issue(&db, &user_id).await.expect("issue");

    // Happy path: logout returns 204.
    let out = call(app.clone(), logout_req(&issued.plaintext)).await;
    assert_eq!(out.status(), StatusCode::NO_CONTENT);

    // The refresh token is now dead — /refresh must 401.
    let after = call(app.clone(), refresh_req(&issued.plaintext)).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);

    // Unknown token → still 204 (no oracle).
    let unknown = call(app, logout_req("nonsense")).await;
    assert_eq!(unknown.status(), StatusCode::NO_CONTENT);
}

// ── Extractors (Plan 3 / BE-3) ────────────────────────────────────────────────

/// Tiny inline router that exercises the extractors so we can verify their
/// guard logic without waiting for BE-5 to flip real handlers over.
fn extractor_app(db: poolpay::db::DbConn, verifier: SharedVerifier) -> Router {
    async fn who_am_i(user: AuthenticatedUser) -> axum::Json<serde_json::Value> {
        axum::Json(serde_json::json!({
            "userId": user.user_id,
            "role": user.role,
            "tokenVersion": user.token_version,
        }))
    }
    async fn super_only(_: SuperAdminUser) -> AxumStatus {
        AxumStatus::NO_CONTENT
    }
    async fn scoped(
        user: AuthenticatedUser,
        State(db): State<poolpay::db::DbConn>,
        Path(gid): Path<String>,
    ) -> Result<AxumStatus, poolpay::api::models::AppError> {
        require_group_scope(&user, &gid, &db).await?;
        Ok(AxumStatus::NO_CONTENT)
    }

    Router::new()
        .route("/me", get(who_am_i))
        .route("/super", get(super_only))
        .route("/scope/{gid}", get(scoped))
        .layer(AxumExtension(verifier))
        .with_state(db)
}

fn bearer_get(uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn user_token_version(db: &poolpay::db::DbConn, user_id: &str) -> i64 {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT token_version FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp.take("token_version").unwrap_or_default();
    rows.first().copied().unwrap_or(-1)
}

async fn set_user_role(db: &poolpay::db::DbConn, user_id: &str, role: &str) {
    use surrealdb::types::RecordId;
    db.query("UPDATE $id SET role = $r")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .bind(("r", role.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
}

async fn set_user_status(db: &poolpay::db::DbConn, user_id: &str, status: &str) {
    use surrealdb::types::RecordId;
    db.query("UPDATE $id SET status = $s")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .bind(("s", status.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
}

async fn bootstrap_admin_id(db: &poolpay::db::DbConn) -> String {
    let mut resp = db
        .query("SELECT VALUE meta::id(id) FROM user WHERE email_normalised = $e LIMIT 1")
        .bind(("e", BOOTSTRAP_EMAIL.to_lowercase()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<String> = resp.take(0).unwrap_or_default();
    rows.into_iter().next().expect("bootstrap admin row must exist")
}

#[tokio::test]
async fn extractor_accepts_valid_token_for_active_user() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-ext-1", "ext1@example.com").await;
    let token = verifier.mint_access(&user_id, "member", 0).expect("mint");

    let app = extractor_app(db, verifier);
    let resp = call(app, bearer_get("/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["userId"].as_str().unwrap(), user_id);
    assert_eq!(v["role"], "member");
}

#[tokio::test]
async fn extractor_rejects_stale_token_version() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-ext-2", "ext2@example.com").await;

    // Mint a token with a version that does not match the user's current 0.
    let stale = verifier.mint_access(&user_id, "member", 42).expect("mint");

    let app = extractor_app(db, verifier);
    let resp = call(app, bearer_get("/me", &stale)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extractor_rejects_disabled_user() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-ext-3", "ext3@example.com").await;
    let token = verifier.mint_access(&user_id, "member", 0).expect("mint");

    set_user_status(&db, &user_id, "disabled").await;

    let app = extractor_app(db, verifier);
    let resp = call(app, bearer_get("/me", &token)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn extractor_rejects_missing_bearer() {
    let (_app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let app = extractor_app(db, verifier);

    let no_header = Request::builder()
        .method(Method::GET)
        .uri("/me")
        .body(Body::empty())
        .unwrap();
    let resp = call(app, no_header).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn super_admin_extractor_accepts_super_admin_and_rejects_others() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;

    let admin_id = bootstrap_admin_id(&db).await;
    let admin_token = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint super");

    let member_id = seed_member(&app, "sub-super-1", "super1@example.com").await;
    let member_token = verifier.mint_access(&member_id, "member", 0).expect("mint");

    let test_app = extractor_app(db, verifier);

    let ok = call(test_app.clone(), bearer_get("/super", &admin_token)).await;
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);

    let denied = call(test_app, bearer_get("/super", &member_token)).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn group_scope_super_admin_bypasses() {
    let (_app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let token = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let test_app = extractor_app(db, verifier);
    // No `group_admin` row exists — super_admin still passes.
    let resp = call(test_app, bearer_get("/scope/any-group-id", &token)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn group_scope_admin_requires_group_admin_row() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;

    let user_id = seed_member(&app, "sub-scope-1", "scope1@example.com").await;
    set_user_role(&db, &user_id, "admin").await;
    let token = verifier.mint_access(&user_id, "admin", 0).expect("mint");

    let test_app = extractor_app(db.clone(), verifier);

    // No row yet → 403.
    let denied = call(test_app.clone(), bearer_get("/scope/group-7", &token)).await;
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    // Add the join row — now the same token passes for that specific group.
    db.create::<Option<poolpay::api::models::DbGroupAdmin>>("group_admin")
        .content(poolpay::api::models::GroupAdminContent {
            user_id: user_id.clone(),
            group_id: "group-7".into(),
            created_at: poolpay::api::models::now_iso(),
            created_by: "test".into(),
        })
        .await
        .expect("insert group_admin")
        .expect("row returned");

    let ok = call(test_app.clone(), bearer_get("/scope/group-7", &token)).await;
    assert_eq!(ok.status(), StatusCode::NO_CONTENT);

    // Different group still denied.
    let other = call(test_app, bearer_get("/scope/group-8", &token)).await;
    assert_eq!(other.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn group_scope_member_is_always_forbidden() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-scope-2", "scope2@example.com").await;
    let token = verifier.mint_access(&user_id, "member", 0).expect("mint");

    let test_app = extractor_app(db, verifier);
    let resp = call(test_app, bearer_get("/scope/group-9", &token)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Password primitives sanity check ──────────────────────────────────────────

#[test]
fn argon2_hash_is_phc_formatted() {
    let h = password::hash("some password").unwrap();
    assert!(h.starts_with("$argon2id$"), "expected PHC format, got: {h}");
    assert!(password::verify("some password", &h).unwrap());
}
