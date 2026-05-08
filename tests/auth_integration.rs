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
use std::sync::{Arc, Mutex, OnceLock};
use tower::ServiceExt;

// ── Shared env setup ──────────────────────────────────────────────────────────

const HMAC_SECRET: &str = "test-hmac-secret-for-integration-only";
const BOOTSTRAP_EMAIL: &str = "seed-admin@example.com";
const BOOTSTRAP_PASSWORD: &str = "correct-horse-battery-staple";

/// Single global lock serializing every `std::env::set_var`/`remove_var`
/// call in this integration binary. Each test helper has its own `OnceLock`
/// so it only mutates the env once, but those first-time initializers can
/// still execute concurrently across helpers under parallel tests — which
/// violates `set_var`'s safety precondition. Taking this mutex before any
/// mutation makes the writer window mutually exclusive across helpers.
fn env_lock() -> &'static Mutex<()> {
    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    ENV_LOCK.get_or_init(|| Mutex::new(()))
}

fn init_env() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _guard = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        // Safety: serialized by `env_lock()` above; written once before any
        // test reads these vars. Parallel tests may then read them freely.
        unsafe {
            std::env::set_var("NEXTAUTH_BACKEND_SECRET", HMAC_SECRET);
            std::env::set_var("BOOTSTRAP_ADMIN_EMAIL", BOOTSTRAP_EMAIL);
            std::env::set_var("BOOTSTRAP_ADMIN_PASSWORD", BOOTSTRAP_PASSWORD);
            // Pin APP_ENV so `StaticKeyVerifier::from_env` takes the ephemeral
            // branch even when the host shell has `APP_ENV=production` or a
            // real `JWT_KEYS` set. Keeps the suite hermetic.
            std::env::set_var("APP_ENV", "test");
            std::env::remove_var("JWT_KEYS");
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
    // `StaticKeyVerifier::from_env` generates a fresh RSA-2048 keypair when
    // `JWT_KEYS` is unset, which is expensive enough to dominate test runtime
    // if we rebuild it per call. Build once per process and clone the `Arc`.
    static VERIFIER: OnceLock<SharedVerifier> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            Arc::new(
                StaticKeyVerifier::from_env(JwtConfig {
                    audience: "poolpay-api".into(),
                    issuer: "poolpay-nextauth".into(),
                    access_ttl_secs: 900,
                    leeway_secs: 60,
                })
                .expect("test verifier"),
            )
        })
        .clone()
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
async fn concurrent_refresh_rotation_detects_race_as_reuse() {
    // Two callers present the same refresh token at the same time. The
    // atomic conditional revoke guarantees exactly one wins; the other
    // trips reuse detection and kills the family. If both walked away
    // with live tokens in the same family we would have a working
    // token-theft bypass — this test pins that behaviour down.
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-race-1", "race1@example.com").await;
    let issued = refresh::issue(&db, &user_id).await.expect("issue");

    let a = tokio::spawn({
        let app = app.clone();
        let tok = issued.plaintext.clone();
        async move { call(app, refresh_req(&tok)).await }
    });
    let b = tokio::spawn({
        let app = app.clone();
        let tok = issued.plaintext.clone();
        async move { call(app, refresh_req(&tok)).await }
    });
    let (resp_a, resp_b) = (a.await.unwrap(), b.await.unwrap());

    let mut statuses = [resp_a.status(), resp_b.status()];
    statuses.sort_by_key(|s| s.as_u16());
    assert_eq!(
        statuses,
        [StatusCode::OK, StatusCode::UNAUTHORIZED],
        "exactly one of the racing rotates must win; the other is reuse",
    );

    // The losing call must have killed the family: the winner's freshly
    // rotated token is also dead now, just like the non-racing reuse path.
    let version_after = user_token_version(&db, &user_id).await;
    assert!(
        version_after > 0,
        "reuse detection on the racing call must bump token_version: got {version_after}"
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

// ── Issue endpoint (Plan 3 / BE-7) ────────────────────────────────────────────

fn issue_req(user_id: &str) -> Request<Body> {
    let body = serde_json::json!({ "userId": user_id });
    hmac_request("/api/auth/issue", &body)
}

async fn count_auth_events(
    db: &poolpay::db::DbConn,
    user_id: &str,
    event_type: &str,
) -> i64 {
    let mut resp = db
        .query(
            "SELECT count() FROM auth_event \
             WHERE user_id = $uid AND event_type = $t GROUP ALL",
        )
        .bind(("uid", user_id.to_string()))
        .bind(("t", event_type.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp
        .take("count")
        .expect("auth_event count query returned unexpected shape");
    rows.first().copied().unwrap_or(0)
}

async fn count_failure_events_by_actor(
    db: &poolpay::db::DbConn,
    actor_id: &str,
    event_type: &str,
    reason: &str,
) -> i64 {
    let mut resp = db
        .query(
            "SELECT count() FROM auth_event \
             WHERE actor_id = $aid AND event_type = $t \
               AND success = false AND reason = $r GROUP ALL",
        )
        .bind(("aid", actor_id.to_string()))
        .bind(("t", event_type.to_string()))
        .bind(("r", reason.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp
        .take("count")
        .expect("auth_event count query returned unexpected shape");
    rows.first().copied().unwrap_or(0)
}

#[tokio::test]
async fn issue_returns_tokens_that_round_trip_through_refresh() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-issue-1", "issue1@example.com").await;

    let resp = call(app.clone(), issue_req(&user_id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    let access = v["accessToken"].as_str().unwrap().to_string();
    let refresh_tok = v["refreshToken"].as_str().unwrap().to_string();
    let expires_at = v["expiresAt"].as_str().unwrap().to_string();
    assert!(!access.is_empty());
    assert!(!refresh_tok.is_empty());
    // ISO-8601 with timezone — chrono can parse it.
    assert!(chrono::DateTime::parse_from_rfc3339(&expires_at).is_ok());

    // Round-trip proves the refresh row was persisted correctly.
    let rotate = call(app, refresh_req(&refresh_tok)).await;
    assert_eq!(rotate.status(), StatusCode::OK);

    let issued_count = count_auth_events(&db, &user_id, "token_issued").await;
    assert_eq!(issued_count, 1, "exactly one token_issued row on success");
}

#[tokio::test]
async fn issue_access_token_carries_users_token_version() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-issue-tv", "issuetv@example.com").await;

    // Bump the user's token_version so the default 0 isn't incidentally correct.
    use surrealdb::types::RecordId;
    db.query("UPDATE $id SET token_version = 9")
        .bind(("id", RecordId::new("user", user_id.clone())))
        .await
        .unwrap()
        .check()
        .unwrap();

    let resp = call(app, issue_req(&user_id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    let access = v["accessToken"].as_str().unwrap();

    let claims = verifier.verify_access(access).expect("verify");
    assert_eq!(claims.token_version, 9);
    assert_eq!(claims.sub, user_id);
    assert_eq!(claims.role, "member");
}

#[tokio::test]
async fn issue_access_token_carries_role_for_super_admin() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;

    let resp = call(app, issue_req(&admin_id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    let claims = verifier
        .verify_access(v["accessToken"].as_str().unwrap())
        .expect("verify");
    assert_eq!(claims.role, "super_admin");
}

#[tokio::test]
async fn issue_access_token_carries_role_for_admin() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-issue-admin", "issueadmin@example.com").await;
    set_user_role(&db, &user_id, "admin").await;

    let resp = call(app, issue_req(&user_id)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    let claims = verifier
        .verify_access(v["accessToken"].as_str().unwrap())
        .expect("verify");
    assert_eq!(claims.role, "admin");
}

#[tokio::test]
async fn issue_unknown_user_returns_401_and_writes_failure_event() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;

    let resp = call(app, issue_req("nonexistent-user-id")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Unknown user: failure audit row is written with user_id = NONE, so we
    // cannot filter by user_id — scan for the event_type directly.
    let mut resp = db
        .query(
            "SELECT count() FROM auth_event \
             WHERE event_type = 'token_issue_failure' \
               AND reason = 'unknown_user' GROUP ALL",
        )
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp
        .take("count")
        .expect("auth_event count query returned unexpected shape");
    assert_eq!(rows.first().copied().unwrap_or(0), 1);
}

#[tokio::test]
async fn issue_disabled_user_returns_401_and_writes_failure_event() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-issue-dis", "issuedis@example.com").await;
    set_user_status(&db, &user_id, "disabled").await;

    let resp = call(app, issue_req(&user_id)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let failures =
        count_auth_events(&db, &user_id, "token_issue_failure").await;
    assert_eq!(failures, 1);
    // And no success row was written.
    let successes = count_auth_events(&db, &user_id, "token_issued").await;
    assert_eq!(successes, 0);
}

#[tokio::test]
async fn issue_soft_deleted_user_returns_401() {
    let (app, db, _v) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-issue-del", "issuedel@example.com").await;

    use surrealdb::types::RecordId;
    db.query("UPDATE $id SET deleted_at = $n")
        .bind(("id", RecordId::new("user", user_id.clone())))
        .bind(("n", poolpay::api::models::now_iso()))
        .await
        .unwrap()
        .check()
        .unwrap();

    let resp = call(app, issue_req(&user_id)).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let failures =
        count_auth_events(&db, &user_id, "token_issue_failure").await;
    assert_eq!(failures, 1);
    let successes = count_auth_events(&db, &user_id, "token_issued").await;
    assert_eq!(successes, 0);
}

#[tokio::test]
async fn issue_without_hmac_headers_returns_401() {
    let (app, _db, _v) = build_app_full(lax_rate_cfg()).await;
    let body = serde_json::json!({ "userId": "anything" });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/issue")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn issue_empty_user_id_returns_400() {
    let (app, _db, _v) = build_app_full(lax_rate_cfg()).await;
    let resp = call(app, issue_req("")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn issue_oversized_user_id_returns_400() {
    let (app, _db, _v) = build_app_full(lax_rate_cfg()).await;
    let huge = "x".repeat(200);
    let resp = call(app, issue_req(&huge)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
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

// ── Change-password (Plan 3 / BE-8 PR 2) ─────────────────────────────────────

fn change_password_req(token: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/auth/change-password")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

async fn user_password_hash(db: &poolpay::db::DbConn, user_id: &str) -> Option<String> {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT password_hash FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<Option<String>> = resp.take("password_hash").unwrap_or_default();
    rows.into_iter().next().flatten()
}

async fn user_must_reset_password(db: &poolpay::db::DbConn, user_id: &str) -> bool {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT must_reset_password FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<bool> = resp.take("must_reset_password").unwrap_or_default();
    rows.into_iter().next().unwrap_or(false)
}

async fn credentials_identity_exists(db: &poolpay::db::DbConn, email_normalised: &str) -> bool {
    let mut resp = db
        .query(
            "SELECT count() FROM user_identity \
             WHERE provider = 'credentials' AND provider_subject = $e GROUP ALL",
        )
        .bind(("e", email_normalised.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp.take("count").unwrap_or_default();
    rows.first().copied().unwrap_or(0) > 0
}

#[tokio::test]
async fn change_password_rotates_hash_bumps_token_version_and_clears_must_reset() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let version_before = user_token_version(&db, &admin_id).await;
    let hash_before = user_password_hash(&db, &admin_id)
        .await
        .expect("bootstrap admin must have a hash");
    assert!(user_must_reset_password(&db, &admin_id).await);

    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": "brand-new-secret-passphrase",
    });
    let resp = call(app.clone(), change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let version_after = user_token_version(&db, &admin_id).await;
    assert!(
        version_after > version_before,
        "change_password must bump token_version: before={version_before} after={version_after}"
    );

    let hash_after = user_password_hash(&db, &admin_id)
        .await
        .expect("hash must still be set after change");
    assert_ne!(hash_after, hash_before, "password hash must rotate");

    assert!(
        !user_must_reset_password(&db, &admin_id).await,
        "must_reset_password should clear on successful change"
    );

    // Old bearer now rejects — token_version bump invalidates in-flight access.
    let replay = call(app.clone(), change_password_req(&access, &body)).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);

    // New password verifies via the public credentials endpoint.
    let verify_body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "password": "brand-new-secret-passphrase",
    });
    let verify_resp = call(app, hmac_request("/api/auth/verify-credentials", &verify_body)).await;
    assert_eq!(verify_resp.status(), StatusCode::OK);
}

/// Wrong `currentPassword` used to collapse onto `401`, which forced the FE
/// to infer it from a post-refresh retry against a still-valid session.
/// Since issue #39 it returns `400 + { code: "bad_current", message }` so the
/// FE can read the failure mode directly; `401` stays reserved for genuine
/// token failures. Audit + no-mutation invariants unchanged.
#[tokio::test]
async fn change_password_wrong_current_returns_400_bad_current_and_does_not_mutate() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let hash_before = user_password_hash(&db, &admin_id).await;
    let version_before = user_token_version(&db, &admin_id).await;
    let failures_before =
        count_auth_events(&db, &admin_id, "password_change_failure").await;

    let body = serde_json::json!({
        "currentPassword": "this-is-not-the-real-password",
        "newPassword": "some-new-password",
    });
    let resp = call(app, change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["code"], "bad_current");
    assert_eq!(body["message"], "Current password is incorrect.");
    assert!(
        body.get("error").is_none(),
        "coded errors must not also carry the legacy `error` field"
    );

    assert_eq!(user_password_hash(&db, &admin_id).await, hash_before);
    assert_eq!(user_token_version(&db, &admin_id).await, version_before);
    assert_eq!(
        count_auth_events(&db, &admin_id, "password_change_failure").await,
        failures_before + 1,
        "bad-current-password must still write a `password_change_failure` audit row"
    );
}

/// Genuine token failures (malformed bearer, bad signature) must still
/// return `401` — the FE relies on this split post-#39 to tell a real auth
/// failure from a wrong-password one.
#[tokio::test]
async fn change_password_with_malformed_bearer_returns_401() {
    let (app, _db, _verifier) = build_app_full(lax_rate_cfg()).await;
    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": "some-new-password",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/change-password")
        .header("authorization", "Bearer not-a-real-jwt")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_missing_current_when_hash_exists_returns_400() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let body = serde_json::json!({ "newPassword": "some-new-password" });
    let resp = call(app, change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_password_rejects_empty_new_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": "",
    });
    let resp = call(app, change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_password_rejects_whitespace_only_new_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": "      ",
    });
    let resp = call(app, change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_password_rejects_oversized_new_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let huge = "a".repeat(1025);
    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": huge,
    });
    let resp = call(app, change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn change_password_sets_hash_for_social_upgrade_without_current_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-change-social", "social1@example.com").await;
    let access = verifier.mint_access(&user_id, "member", 0).expect("mint");

    assert!(user_password_hash(&db, &user_id).await.is_none());
    assert!(
        !credentials_identity_exists(&db, "social1@example.com").await,
        "social user must not have a credentials identity before upgrade"
    );

    let body = serde_json::json!({ "newPassword": "first-time-password-set" });
    let resp = call(app.clone(), change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert!(user_password_hash(&db, &user_id).await.is_some());
    assert!(
        credentials_identity_exists(&db, "social1@example.com").await,
        "set path must insert a credentials user_identity row"
    );

    // Verify-credentials now works with the new password + the user's email.
    let verify_body = serde_json::json!({
        "email": "social1@example.com",
        "password": "first-time-password-set",
    });
    let verify_resp = call(app, hmac_request("/api/auth/verify-credentials", &verify_body)).await;
    assert_eq!(verify_resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn change_password_revokes_refresh_tokens_on_change() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    // Issue a refresh token before the password change.
    let issued = refresh::issue(&db, &admin_id).await.expect("issue");

    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": "rotation-secret-passphrase",
    });
    let resp = call(app.clone(), change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Pre-existing refresh token must now be dead.
    let after = call(app, refresh_req(&issued.plaintext)).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_does_not_revoke_refresh_tokens_on_set_path() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let user_id = seed_member(&app, "sub-change-set", "set1@example.com").await;
    let access = verifier.mint_access(&user_id, "member", 0).expect("mint");

    let issued = refresh::issue(&db, &user_id).await.expect("issue");

    let body = serde_json::json!({ "newPassword": "set-path-password" });
    let resp = call(app.clone(), change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Set path is a social upgrade, not a re-auth trigger — refresh stays live.
    let after = call(app, refresh_req(&issued.plaintext)).await;
    assert_eq!(after.status(), StatusCode::OK);
}

#[tokio::test]
async fn change_password_without_bearer_returns_401() {
    let (app, _db, _v) = build_app_full(lax_rate_cfg()).await;
    let body = serde_json::json!({ "newPassword": "whatever" });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/auth/change-password")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn change_password_writes_password_changed_auth_event() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let admin_id = bootstrap_admin_id(&db).await;
    let access = verifier
        .mint_access(&admin_id, "super_admin", 0)
        .expect("mint");

    let before = count_auth_events(&db, &admin_id, "password_changed").await;
    let body = serde_json::json!({
        "currentPassword": BOOTSTRAP_PASSWORD,
        "newPassword": "audit-trail-passphrase",
    });
    let resp = call(app, change_password_req(&access, &body)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let after = count_auth_events(&db, &admin_id, "password_changed").await;
    assert_eq!(after, before + 1, "expected exactly one password_changed event");
}

/// `user.email_normalised` is intentionally non-unique, so two social users
/// can share an email. Only one of them may own the
/// (`provider='credentials'`, `provider_subject=email_normalised`) identity —
/// the second user attempting to set a password must be refused with 409,
/// and critically must not end up with a `password_hash` that lets them pass
/// `/api/auth/verify-credentials` even though the credentials identity is
/// resolved to a *different* account.
#[tokio::test]
async fn change_password_set_path_refuses_when_another_user_owns_credentials_identity() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;

    let shared_email = "shared-credentials@example.com";
    let user_a = seed_member(&app, "sub-shared-a", shared_email).await;
    let user_b = seed_member(&app, "sub-shared-b", shared_email).await;
    assert_ne!(user_a, user_b, "distinct providerSubjects must produce distinct users");

    // User A sets a password first — this inserts the single credentials
    // identity row for `shared_email`.
    let access_a = verifier.mint_access(&user_a, "member", 0).expect("mint");
    let body_a = serde_json::json!({ "newPassword": "owner-password" });
    let resp_a = call(app.clone(), change_password_req(&access_a, &body_a)).await;
    assert_eq!(resp_a.status(), StatusCode::NO_CONTENT);

    // User B now tries to set a password for the same email — the credentials
    // identity already exists and belongs to someone else.
    let access_b = verifier.mint_access(&user_b, "member", 0).expect("mint");
    let body_b = serde_json::json!({ "newPassword": "interloper-password" });
    let resp_b = call(app.clone(), change_password_req(&access_b, &body_b)).await;
    assert_eq!(resp_b.status(), StatusCode::CONFLICT);

    // User B must NOT have a password hash — otherwise future refactors could
    // silently let B authenticate through credentials even though the
    // identity resolves to A.
    assert!(
        user_password_hash(&db, &user_b).await.is_none(),
        "conflicting set attempt must not write a password_hash for the losing user"
    );

    // The owning user's password must still work via verify-credentials —
    // the identity row was not rewired.
    let verify_body = serde_json::json!({
        "email": shared_email,
        "password": "owner-password",
    });
    let verify_resp = call(app, hmac_request("/api/auth/verify-credentials", &verify_body)).await;
    assert_eq!(verify_resp.status(), StatusCode::OK);
}

// ── Admin user CRUD (Plan 3 / BE-8 PR 3) ─────────────────────────────────────

fn admin_users_post_req(token: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/api/admin/users")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn admin_users_patch_req(id: &str, token: &str, body: &serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(Method::PATCH)
        .uri(format!("/api/admin/users/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

fn admin_users_delete_req(id: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/admin/users/{id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn user_version(db: &poolpay::db::DbConn, user_id: &str) -> i64 {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT version FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp.take("version").unwrap_or_default();
    rows.first().copied().unwrap_or(-1)
}

async fn user_role(db: &poolpay::db::DbConn, user_id: &str) -> String {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT role FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<String> = resp.take("role").unwrap_or_default();
    rows.into_iter().next().unwrap_or_default()
}

async fn user_status(db: &poolpay::db::DbConn, user_id: &str) -> String {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT status FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<String> = resp.take("status").unwrap_or_default();
    rows.into_iter().next().unwrap_or_default()
}

async fn user_deleted_at(db: &poolpay::db::DbConn, user_id: &str) -> Option<String> {
    use surrealdb::types::RecordId;
    let mut resp = db
        .query("SELECT deleted_at FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<Option<String>> = resp.take("deleted_at").unwrap_or_default();
    rows.into_iter().next().flatten()
}

// --- POST /api/admin/users ---

#[tokio::test]
async fn create_admin_user_happy_path_returns_201_and_allows_signin() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "new-admin@example.com",
        "initialPassword": "initial-secret-passphrase",
        "role": "admin",
    });
    let resp = call(app.clone(), admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["email"], "new-admin@example.com");
    assert_eq!(v["role"], "admin");
    assert_eq!(v["status"], "active");
    assert_eq!(v["mustResetPassword"], true);
    assert!(
        v.get("tokenVersion").is_none(),
        "token_version is a server-side invalidation counter and must not leak to clients"
    );
    assert_eq!(v["version"], 1);
    let new_id = v["userId"].as_str().unwrap().to_string();
    assert!(!new_id.is_empty());

    // Audit row written.
    let events = count_auth_events(&db, &new_id, "user_created").await;
    assert_eq!(events, 1);

    // Credentials identity was created — verify-credentials with the seed
    // password now returns 200 and flags mustResetPassword.
    let verify_body = serde_json::json!({
        "email": "new-admin@example.com",
        "password": "initial-secret-passphrase",
    });
    let verify_resp = call(app, hmac_request("/api/auth/verify-credentials", &verify_body)).await;
    assert_eq!(verify_resp.status(), StatusCode::OK);
    let vv: serde_json::Value = json_body(verify_resp).await;
    assert_eq!(vv["mustResetPassword"], true);
    assert_eq!(vv["role"], "admin");
}

#[tokio::test]
async fn create_admin_user_allows_second_super_admin() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "second-super@example.com",
        "initialPassword": "another-seed-password",
        "role": "super_admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["role"], "super_admin");
}

#[tokio::test]
async fn create_admin_user_rejects_member_role() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "not-an-admin@example.com",
        "initialPassword": "seed-password",
        "role": "member",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_admin_user_rejects_empty_email() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "   ",
        "initialPassword": "seed-password",
        "role": "admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_admin_user_rejects_oversized_email() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": format!("{}@example.com", "a".repeat(400)),
        "initialPassword": "seed-password",
        "role": "admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_admin_user_rejects_empty_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "blank-pwd@example.com",
        "initialPassword": "",
        "role": "admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_admin_user_rejects_whitespace_only_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "ws-pwd@example.com",
        "initialPassword": "      ",
        "role": "admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_admin_user_rejects_oversized_password() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "huge-pwd@example.com",
        "initialPassword": "x".repeat(2000),
        "role": "admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_admin_user_duplicate_email_returns_409() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": "dupe@example.com",
        "initialPassword": "seed-password",
        "role": "admin",
    });
    let first = call(app.clone(), admin_users_post_req(&super_token, &body)).await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);

    // Failure is audited with actor_id = super_admin so ops can alert on
    // probing patterns (many failed provisions from one operator).
    let failures =
        count_failure_events_by_actor(&db, &super_id, "user_created", "duplicate_email").await;
    assert_eq!(failures, 1);
}

#[tokio::test]
async fn create_admin_user_collides_on_existing_bootstrap_email() {
    // The bootstrap admin already owns a `credentials`/email_normalised
    // identity row, so re-creating the same email must 409 even though the
    // request is the operator's first CRUD call.
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({
        "email": BOOTSTRAP_EMAIL,
        "initialPassword": "seed-password",
        "role": "admin",
    });
    let resp = call(app, admin_users_post_req(&super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_admin_user_rejects_non_super_admin_with_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let member_id = seed_member(&app, "sub-post-forbidden", "postforbid@example.com").await;
    let member_token = verifier.mint_access(&member_id, "member", 0).expect("mint");

    let body = serde_json::json!({
        "email": "should-not-exist@example.com",
        "initialPassword": "seed-password",
        "role": "admin",
    });

    // Exercise the member path before the DB role is promoted — the extractor
    // derives the role from the DB row, so flipping it first would turn this
    // into a second admin-caller assertion.
    let member_resp = call(app.clone(), admin_users_post_req(&member_token, &body)).await;
    assert_eq!(member_resp.status(), StatusCode::FORBIDDEN);

    set_user_role(&db, &member_id, "admin").await;
    let admin_token = verifier.mint_access(&member_id, "admin", 0).expect("mint");

    let admin_resp = call(app, admin_users_post_req(&admin_token, &body)).await;
    assert_eq!(admin_resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_admin_user_without_bearer_returns_401() {
    let (app, _db, _v) = build_app_full(lax_rate_cfg()).await;
    let body = serde_json::json!({
        "email": "nobody@example.com",
        "initialPassword": "seed-password",
        "role": "admin",
    });
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/admin/users")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// --- PATCH /api/admin/users/:id ---

/// Provision an admin-tier user via the POST endpoint so the PATCH/DELETE
/// tests exercise the real create path rather than a hand-crafted row.
async fn seed_admin_user(
    app: &Router,
    super_token: &str,
    email: &str,
    role: &str,
) -> (String, i64) {
    let body = serde_json::json!({
        "email": email,
        "initialPassword": "initial-password",
        "role": role,
    });
    let resp = call(app.clone(), admin_users_post_req(super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::CREATED, "seed_admin_user failed");
    let v: serde_json::Value = json_body(resp).await;
    (
        v["userId"].as_str().unwrap().to_string(),
        v["version"].as_i64().unwrap(),
    )
}

#[tokio::test]
async fn update_admin_user_role_change_bumps_token_version_and_writes_audit() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "patch-role@example.com", "admin").await;

    let tv_before = user_token_version(&db, &target_id).await;

    let body = serde_json::json!({ "role": "super_admin", "version": version });
    let resp = call(app, admin_users_patch_req(&target_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["role"], "super_admin");
    assert_eq!(v["version"], version + 1);

    let tv_after = user_token_version(&db, &target_id).await;
    assert!(
        tv_after > tv_before,
        "role change must bump token_version: before={tv_before} after={tv_after}"
    );

    // Stored role reflects the patch.
    assert_eq!(user_role(&db, &target_id).await, "super_admin");

    // Audit row written.
    let events = count_auth_events(&db, &target_id, "role_changed").await;
    assert_eq!(events, 1);
}

#[tokio::test]
async fn update_admin_user_role_change_rejects_in_flight_access_token() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "stale-token@example.com", "admin").await;
    // Token minted against the target's current token_version (0) — this is
    // the JWT-invalidation cursor, distinct from `user.version` (optimistic
    // concurrency). The role-change below bumps `token_version` so this
    // access token stops verifying.
    let target_token = verifier.mint_access(&target_id, "admin", 0).expect("mint");

    // Promote target to super_admin — bumps token_version.
    let body = serde_json::json!({ "role": "super_admin", "version": version });
    let resp = call(app.clone(), admin_users_patch_req(&target_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The target's pre-promotion access token must now fail the version
    // check on any authenticated endpoint — use change-password which is
    // gated by AuthenticatedUser.
    let cp = serde_json::json!({
        "currentPassword": "initial-password",
        "newPassword": "rotation-secret-passphrase",
    });
    let replay = call(app, change_password_req(&target_token, &cp)).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn update_admin_user_status_disable_revokes_refresh_tokens_and_audits() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "disable@example.com", "admin").await;

    // Pre-issue a refresh token for the target.
    let issued = refresh::issue(&db, &target_id).await.expect("issue");
    let tv_before = user_token_version(&db, &target_id).await;

    let body = serde_json::json!({ "status": "disabled", "version": version });
    let resp = call(app.clone(), admin_users_patch_req(&target_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(user_status(&db, &target_id).await, "disabled");
    let tv_after = user_token_version(&db, &target_id).await;
    assert!(tv_after > tv_before, "disable must bump token_version");

    // Refresh token is now dead.
    let after = call(app, refresh_req(&issued.plaintext)).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);

    // Audit row.
    let events = count_auth_events(&db, &target_id, "user_disabled").await;
    assert_eq!(events, 1);
}

#[tokio::test]
async fn update_admin_user_reenable_emits_user_enabled_audit_event() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "reenable@example.com", "admin").await;

    // Disable first — produces a user_disabled event and bumps version to version+1.
    let disable = serde_json::json!({ "status": "disabled", "version": version });
    let resp = call(app.clone(), admin_users_patch_req(&target_id, &super_token, &disable)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(user_status(&db, &target_id).await, "disabled");

    // Re-enable with the bumped version.
    let reenable = serde_json::json!({ "status": "active", "version": version + 1 });
    let resp = call(app, admin_users_patch_req(&target_id, &super_token, &reenable)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(user_status(&db, &target_id).await, "active");

    // Symmetric audit — one disable, one enable.
    let disabled_events = count_auth_events(&db, &target_id, "user_disabled").await;
    assert_eq!(disabled_events, 1);
    let enabled_events = count_auth_events(&db, &target_id, "user_enabled").await;
    assert_eq!(enabled_events, 1);
}

#[tokio::test]
async fn update_admin_user_noop_patch_bumps_version_but_not_token_version() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "noop@example.com", "admin").await;
    let tv_before = user_token_version(&db, &target_id).await;

    // Send the same role + current version — nothing changes.
    let body = serde_json::json!({ "role": "admin", "version": version });
    let resp = call(app, admin_users_patch_req(&target_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(user_version(&db, &target_id).await, version + 1);
    assert_eq!(
        user_token_version(&db, &target_id).await,
        tv_before,
        "no-op patch must not bump token_version"
    );
    let events = count_auth_events(&db, &target_id, "role_changed").await;
    assert_eq!(events, 0, "no role_changed event for a no-op role patch");
}

#[tokio::test]
async fn update_admin_user_version_mismatch_returns_409() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "stale-version@example.com", "admin").await;

    let body = serde_json::json!({ "role": "super_admin", "version": version + 99 });
    let resp = call(app, admin_users_patch_req(&target_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_admin_user_unknown_id_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let body = serde_json::json!({ "role": "admin", "version": 1 });
    let resp = call(app, admin_users_patch_req("nonexistent-id", &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_admin_user_rejects_unsupported_role_and_status() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "badvals@example.com", "admin").await;

    let bad_role = serde_json::json!({ "role": "owner", "version": version });
    let r1 = call(app.clone(), admin_users_patch_req(&target_id, &super_token, &bad_role)).await;
    assert_eq!(r1.status(), StatusCode::BAD_REQUEST);

    let bad_status = serde_json::json!({ "status": "pending", "version": version });
    let r2 = call(app, admin_users_patch_req(&target_id, &super_token, &bad_status)).await;
    assert_eq!(r2.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn update_admin_user_self_mutation_returns_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let version = user_version(&db, &super_id).await;
    let body = serde_json::json!({ "role": "admin", "version": version });
    let resp = call(app, admin_users_patch_req(&super_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_admin_user_rejects_non_super_admin_with_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "patch-forbid@example.com", "admin").await;
    let target_token = verifier.mint_access(&target_id, "admin", 0).expect("mint");

    let body = serde_json::json!({ "role": "super_admin", "version": version });
    let resp = call(app, admin_users_patch_req(&target_id, &target_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn update_admin_user_allows_demotion_to_member() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, version) =
        seed_admin_user(&app, &super_token, "demote@example.com", "admin").await;

    let body = serde_json::json!({ "role": "member", "version": version });
    let resp = call(app, admin_users_patch_req(&target_id, &super_token, &body)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(user_role(&db, &target_id).await, "member");
}

// --- DELETE /api/admin/users/:id ---

#[tokio::test]
async fn delete_admin_user_soft_deletes_and_bumps_token_version() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "soft-del@example.com", "admin").await;

    let issued = refresh::issue(&db, &target_id).await.expect("issue");
    let tv_before = user_token_version(&db, &target_id).await;

    let resp = call(app.clone(), admin_users_delete_req(&target_id, &super_token)).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert!(
        user_deleted_at(&db, &target_id).await.is_some(),
        "delete must stamp deleted_at"
    );
    let tv_after = user_token_version(&db, &target_id).await;
    assert!(tv_after > tv_before, "delete must bump token_version");

    // Refresh token is revoked.
    let after = call(app, refresh_req(&issued.plaintext)).await;
    assert_eq!(after.status(), StatusCode::UNAUTHORIZED);

    // Audit row with `soft_deleted` reason.
    let mut resp = db
        .query(
            "SELECT count() FROM auth_event \
             WHERE user_id = $uid AND event_type = 'user_disabled' \
               AND reason = 'soft_deleted' GROUP ALL",
        )
        .bind(("uid", target_id.clone()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp.take("count").unwrap_or_default();
    assert_eq!(rows.first().copied().unwrap_or(0), 1);
}

#[tokio::test]
async fn delete_admin_user_self_delete_returns_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let resp = call(app, admin_users_delete_req(&super_id, &super_token)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Still present, still active. `user_deleted_at` returning `None` alone
    // cannot distinguish "deleted_at unset" from "row missing", so also
    // assert the status column still resolves to `active` — that query
    // would return empty (and `user_status` `""`) if the row were gone.
    assert!(user_deleted_at(&db, &super_id).await.is_none());
    assert_eq!(user_status(&db, &super_id).await, "active");
}

#[tokio::test]
async fn delete_admin_user_unknown_id_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let resp = call(app, admin_users_delete_req("nonexistent-id", &super_token)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_admin_user_already_deleted_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "double-del@example.com", "admin").await;

    let first = call(app.clone(), admin_users_delete_req(&target_id, &super_token)).await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    let second = call(app, admin_users_delete_req(&target_id, &super_token)).await;
    assert_eq!(second.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_admin_user_rejects_non_super_admin_with_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "del-forbid@example.com", "admin").await;
    let target_token = verifier.mint_access(&target_id, "admin", 0).expect("mint");

    let resp = call(app, admin_users_delete_req(&target_id, &target_token)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Group-admin grants (Plan 3 / BE-8 PR 4) ──────────────────────────────────

fn group_admin_post_req(user_id: &str, group_id: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(format!("/api/admin/users/{user_id}/groups/{group_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

async fn seed_test_group(db: &poolpay::db::DbConn, id: &str) {
    let now = poolpay::api::models::now_iso();
    db.upsert::<Option<poolpay::api::models::DbGroup>>(("group", id.to_string()))
        .content(poolpay::api::models::GroupContent {
            name: format!("Test group {id}"),
            status: "active".into(),
            description: None,
            created_at: now.clone(),
            updated_at: now,
            deleted_at: None,
            version: 1,
        })
        .await
        .expect("seed group")
        .expect("group row returned");
}

async fn count_group_admin_rows(
    db: &poolpay::db::DbConn,
    user_id: &str,
    group_id: &str,
) -> i64 {
    let mut resp = db
        .query(
            "SELECT count() FROM group_admin \
             WHERE user_id = $uid AND group_id = $gid GROUP ALL",
        )
        .bind(("uid", user_id.to_string()))
        .bind(("gid", group_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let rows: Vec<i64> = resp.take("count").unwrap_or_default();
    rows.first().copied().unwrap_or(0)
}

#[tokio::test]
async fn grant_group_admin_happy_path_returns_201_and_inserts_row() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "grant-hp@example.com", "admin").await;
    seed_test_group(&db, "grant-hp-group").await;

    let resp = call(
        app,
        group_admin_post_req(&target_id, "grant-hp-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    let v: serde_json::Value = json_body(resp).await;
    assert_eq!(v["userId"], target_id);
    assert_eq!(v["groupId"], "grant-hp-group");
    assert_eq!(v["createdBy"], super_id);
    assert!(v["createdAt"].as_str().is_some());

    assert_eq!(
        count_group_admin_rows(&db, &target_id, "grant-hp-group").await,
        1
    );
    assert_eq!(
        count_auth_events(&db, &target_id, "group_admin_granted").await,
        1
    );
}

#[tokio::test]
async fn grant_group_admin_without_bearer_returns_401() {
    let (app, db, _verifier) = build_app_full(lax_rate_cfg()).await;
    seed_test_group(&db, "grant-no-bearer").await;

    let resp = call(
        app,
        Request::builder()
            .method(Method::POST)
            .uri("/api/admin/users/any-user/groups/grant-no-bearer")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn grant_group_admin_rejects_non_super_admin_with_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "grant-forbid@example.com", "admin").await;
    let admin_token = verifier.mint_access(&target_id, "admin", 0).expect("mint");
    seed_test_group(&db, "grant-forbid-group").await;

    let resp = call(
        app,
        group_admin_post_req(&target_id, "grant-forbid-group", &admin_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn grant_group_admin_on_unknown_user_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");
    seed_test_group(&db, "grant-unknown-user-group").await;

    let resp = call(
        app,
        group_admin_post_req("ghost-user", "grant-unknown-user-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn grant_group_admin_on_disabled_user_returns_409() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "grant-disabled@example.com", "admin").await;
    set_user_status(&db, &target_id, "disabled").await;
    seed_test_group(&db, "grant-disabled-group").await;

    let resp = call(
        app,
        group_admin_post_req(&target_id, "grant-disabled-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(
        count_group_admin_rows(&db, &target_id, "grant-disabled-group").await,
        0
    );
}

#[tokio::test]
async fn grant_group_admin_on_super_admin_target_returns_409() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) = seed_admin_user(
        &app,
        &super_token,
        "grant-super@example.com",
        "super_admin",
    )
    .await;
    seed_test_group(&db, "grant-super-group").await;

    let resp = call(
        app,
        group_admin_post_req(&target_id, "grant-super-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn grant_group_admin_on_member_target_returns_409() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let member_id = seed_member(&app, "sub-grant-member", "grant-member@example.com").await;
    seed_test_group(&db, "grant-member-group").await;

    let resp = call(
        app,
        group_admin_post_req(&member_id, "grant-member-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn grant_group_admin_on_unknown_group_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "grant-ghost-group@example.com", "admin").await;

    let resp = call(
        app,
        group_admin_post_req(&target_id, "ghost-group-id", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn grant_group_admin_duplicate_returns_409() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "grant-dup@example.com", "admin").await;
    seed_test_group(&db, "grant-dup-group").await;

    let first = call(
        app.clone(),
        group_admin_post_req(&target_id, "grant-dup-group", &super_token),
    )
    .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = call(
        app,
        group_admin_post_req(&target_id, "grant-dup-group", &super_token),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);

    assert_eq!(
        count_group_admin_rows(&db, &target_id, "grant-dup-group").await,
        1
    );
}

fn group_admin_delete_req(user_id: &str, group_id: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(Method::DELETE)
        .uri(format!("/api/admin/users/{user_id}/groups/{group_id}"))
        .header("authorization", format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn revoke_group_admin_happy_path_returns_204_and_removes_row() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "revoke-hp@example.com", "admin").await;
    seed_test_group(&db, "revoke-hp-group").await;

    let grant = call(
        app.clone(),
        group_admin_post_req(&target_id, "revoke-hp-group", &super_token),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::CREATED);

    let resp = call(
        app,
        group_admin_delete_req(&target_id, "revoke-hp-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    assert_eq!(
        count_group_admin_rows(&db, &target_id, "revoke-hp-group").await,
        0
    );
    assert_eq!(
        count_auth_events(&db, &target_id, "group_admin_revoked").await,
        1
    );
}

#[tokio::test]
async fn revoke_group_admin_bumps_target_token_version() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "revoke-tv@example.com", "admin").await;
    seed_test_group(&db, "revoke-tv-group").await;

    let grant = call(
        app.clone(),
        group_admin_post_req(&target_id, "revoke-tv-group", &super_token),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::CREATED);

    let tv_before = user_token_version(&db, &target_id).await;

    let resp = call(
        app,
        group_admin_delete_req(&target_id, "revoke-tv-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let tv_after = user_token_version(&db, &target_id).await;
    assert!(
        tv_after > tv_before,
        "revoke must bump target's token_version: before={tv_before} after={tv_after}"
    );
}

/// The bump only matters if an in-flight token minted *before* the
/// revoke actually gets rejected on the next verify. This is a
/// regression test for the end-to-end guarantee, not just the DB
/// counter delta: mint a target access token at `tokenVersion=0`,
/// grant + revoke, then hit a bearer-gated route with the same
/// stale token and expect 401 (not 403 — the whole session is
/// invalidated, not just the group scope).
#[tokio::test]
async fn revoke_group_admin_invalidates_pre_revoke_access_token() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "kick-after-revoke@example.com", "admin").await;
    seed_test_group(&db, "kick-group").await;
    let grant = call(
        app.clone(),
        group_admin_post_req(&target_id, "kick-group", &super_token),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::CREATED);

    // Mint the target's access token *before* revoke with the
    // current DB token_version (0 — grant does not bump).
    let target_token = verifier.mint_access(&target_id, "admin", 0).expect("mint");

    // Sanity check: the fresh token passes for the granted group
    // through the AuthenticatedUser + require_group_scope pipeline
    // on a router that only mounts the extractor route.
    let test_app = extractor_app(db.clone(), verifier);
    let before = call(test_app.clone(), bearer_get("/scope/kick-group", &target_token)).await;
    assert_eq!(before.status(), StatusCode::NO_CONTENT);

    let revoke = call(
        app,
        group_admin_delete_req(&target_id, "kick-group", &super_token),
    )
    .await;
    assert_eq!(revoke.status(), StatusCode::NO_CONTENT);

    // The pre-revoke token must now 401 — `AuthenticatedUser`
    // re-reads token_version from the DB on every call and
    // rejects the mismatch before group-scope evaluation runs.
    let after = call(test_app, bearer_get("/scope/kick-group", &target_token)).await;
    assert_eq!(
        after.status(),
        StatusCode::UNAUTHORIZED,
        "pre-revoke token must be rejected once token_version is bumped"
    );
}

#[tokio::test]
async fn revoke_group_admin_without_bearer_returns_401() {
    let (app, db, _verifier) = build_app_full(lax_rate_cfg()).await;
    seed_test_group(&db, "revoke-no-bearer").await;

    let resp = call(
        app,
        Request::builder()
            .method(Method::DELETE)
            .uri("/api/admin/users/any/groups/revoke-no-bearer")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoke_group_admin_rejects_non_super_admin_with_403() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "revoke-forbid@example.com", "admin").await;
    let admin_token = verifier.mint_access(&target_id, "admin", 0).expect("mint");
    seed_test_group(&db, "revoke-forbid-group").await;
    let grant = call(
        app.clone(),
        group_admin_post_req(&target_id, "revoke-forbid-group", &super_token),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::CREATED);

    let resp = call(
        app,
        group_admin_delete_req(&target_id, "revoke-forbid-group", &admin_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Grant must still exist — the 403 exited before the delete query.
    assert_eq!(
        count_group_admin_rows(&db, &target_id, "revoke-forbid-group").await,
        1
    );
}

#[tokio::test]
async fn revoke_group_admin_unknown_grant_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "revoke-unknown@example.com", "admin").await;

    let resp = call(
        app,
        group_admin_delete_req(&target_id, "never-granted-group", &super_token),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn revoke_group_admin_replay_after_success_returns_404() {
    let (app, db, verifier) = build_app_full(lax_rate_cfg()).await;
    let super_id = bootstrap_admin_id(&db).await;
    let super_token = verifier.mint_access(&super_id, "super_admin", 0).expect("mint");

    let (target_id, _) =
        seed_admin_user(&app, &super_token, "revoke-replay@example.com", "admin").await;
    seed_test_group(&db, "revoke-replay-group").await;
    let grant = call(
        app.clone(),
        group_admin_post_req(&target_id, "revoke-replay-group", &super_token),
    )
    .await;
    assert_eq!(grant.status(), StatusCode::CREATED);

    let first = call(
        app.clone(),
        group_admin_delete_req(&target_id, "revoke-replay-group", &super_token),
    )
    .await;
    assert_eq!(first.status(), StatusCode::NO_CONTENT);

    let second = call(
        app,
        group_admin_delete_req(&target_id, "revoke-replay-group", &super_token),
    )
    .await;
    assert_eq!(second.status(), StatusCode::NOT_FOUND);
}

// ── Dev-only dummy admin fixtures ─────────────────────────────────────────────
//
// Tests drive the seed path via the boolean-flag helper instead of toggling
// `SEED_ON_EMPTY` at runtime. Flipping a process-wide env var inside a
// parallel test binary races with any concurrent `std::env::var` read in
// other tests or async tasks — `set_var`'s safety precondition only holds
// when there are no concurrent readers, which we can't guarantee in an
// async test harness. The flag-taking helper sidesteps the hazard entirely.

async fn count_rows(db: &poolpay::db::DbConn, query: &str) -> i64 {
    let mut resp = db.query(query).await.unwrap().check().unwrap();
    let rows: Vec<i64> = resp.take("count").unwrap_or_default();
    rows.first().copied().unwrap_or(0)
}

#[tokio::test]
async fn seed_dummy_admins_creates_all_fixtures_with_expected_roles_and_grants() {
    let (_app, db) = test_app().await;
    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("seed_dummy_admins");

    // admin1, admin2, admin4 — regular `admin` role.
    let admin_role_rows = count_rows(
        &db,
        "SELECT count() FROM user \
         WHERE email_normalised IN [\
             'admin1@poolpay.test', 'admin2@poolpay.test', 'admin4@poolpay.test'\
         ] \
         AND role = 'admin' AND status = 'active' AND must_reset_password = false \
         GROUP ALL",
    )
    .await;
    assert_eq!(
        admin_role_rows, 3,
        "admin1/admin2/admin4 must be created as active admin-role users"
    );

    // admin3 — super_admin role, to exercise super-admin-on-super-admin flows
    // without touching the bootstrap account.
    let super_admin_rows = count_rows(
        &db,
        "SELECT count() FROM user \
         WHERE email_normalised = 'admin3@poolpay.test' \
         AND role = 'super_admin' AND status = 'active' AND must_reset_password = false \
         GROUP ALL",
    )
    .await;
    assert_eq!(
        super_admin_rows, 1,
        "admin3 must be created as an active super_admin"
    );

    // Only admin1 receives a FIXTURE_GROUP_ID grant.
    let admin1_grants = count_rows(
        &db,
        "SELECT count() FROM group_admin \
         WHERE group_id = '1' AND user_id IN (\
             SELECT VALUE meta::id(id) FROM user WHERE email_normalised = 'admin1@poolpay.test'\
         ) GROUP ALL",
    )
    .await;
    assert_eq!(admin1_grants, 1, "admin1 must receive exactly one fixture grant on group 1");

    for email in ["admin2@poolpay.test", "admin3@poolpay.test", "admin4@poolpay.test"] {
        let grants = count_rows(
            &db,
            &format!(
                "SELECT count() FROM group_admin \
                 WHERE user_id IN (\
                     SELECT VALUE meta::id(id) FROM user WHERE email_normalised = '{email}'\
                 ) GROUP ALL"
            ),
        )
        .await;
        assert_eq!(grants, 0, "{email} must not receive any fixture grants");
    }
}

#[tokio::test]
async fn seed_dummy_admins_is_idempotent_across_restarts() {
    let (_app, db) = test_app().await;
    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("first seed");
    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("second seed (simulated restart)");

    let admins = count_rows(
        &db,
        "SELECT count() FROM user \
         WHERE email_normalised IN [\
             'admin1@poolpay.test', 'admin2@poolpay.test', \
             'admin3@poolpay.test', 'admin4@poolpay.test'\
         ] \
         GROUP ALL",
    )
    .await;
    assert_eq!(admins, 4, "restart must not duplicate fixture admin rows");

    let grants = count_rows(
        &db,
        "SELECT count() FROM group_admin WHERE group_id = '1' GROUP ALL",
    )
    .await;
    assert_eq!(grants, 1, "restart must not duplicate fixture grants");
}

#[tokio::test]
async fn seed_dummy_admins_is_noop_without_flag() {
    let (_app, db) = test_app().await;
    // Verify the guard short-circuits rather than relying on idempotency
    // alone, so a production boot without the flag is provably silent.
    bootstrap::seed_dummy_admins_with_flag(&db, false)
        .await
        .expect("seed_dummy_admins noop");

    let admins = count_rows(
        &db,
        "SELECT count() FROM user \
         WHERE email_normalised IN [\
             'admin1@poolpay.test', 'admin2@poolpay.test', \
             'admin3@poolpay.test', 'admin4@poolpay.test'\
         ] \
         GROUP ALL",
    )
    .await;
    assert_eq!(admins, 0, "fixture admins must not be seeded without SEED_ON_EMPTY=true");
}

#[tokio::test]
async fn seed_dummy_admins_restores_missing_admin1_grant_on_restart() {
    // Idempotency contract: if admin1 already exists but the `group_admin`
    // grant was manually deleted (partial cleanup, ops intervention), a
    // subsequent seed must restore the grant rather than silently skip it.
    let (_app, db) = test_app().await;
    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("first seed");

    // Wipe admin1's grant without touching the user row, simulating a manual
    // cleanup that left the fixture admin intact but stripped the grant.
    db.query("DELETE group_admin WHERE group_id = '1'")
        .await
        .unwrap()
        .check()
        .unwrap();
    let grants_after_wipe = count_rows(
        &db,
        "SELECT count() FROM group_admin WHERE group_id = '1' GROUP ALL",
    )
    .await;
    assert_eq!(grants_after_wipe, 0, "precondition: grant wiped");

    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("second seed restores grant");

    let grants = count_rows(
        &db,
        "SELECT count() FROM group_admin WHERE group_id = '1' GROUP ALL",
    )
    .await;
    assert_eq!(grants, 1, "restart must restore admin1's fixture grant");
}

#[tokio::test]
async fn seed_dummy_admins_skips_grant_when_fixture_user_is_disabled() {
    // If the fixture admin1 was disabled via the admin UI (soft-deleted or
    // status=disabled) after the first seed, a subsequent seed must NOT
    // award a fresh `group_admin` grant to that disabled user — the fixture
    // is no longer in a usable state, and silently granting would mask the
    // fact that admin1 has been taken offline.
    let (_app, db) = test_app().await;
    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("first seed");

    // Soft-delete admin1 and wipe the fixture grant to mirror a "disabled
    // admin + stripped grant" state on the second boot.
    db.query(
        "UPDATE user \
         SET status = 'disabled', deleted_at = '2026-04-22T00:00:00Z' \
         WHERE email_normalised = 'admin1@poolpay.test'",
    )
    .await
    .unwrap()
    .check()
    .unwrap();
    db.query("DELETE group_admin WHERE group_id = '1'")
        .await
        .unwrap()
        .check()
        .unwrap();

    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("second seed tolerates disabled fixture admin");

    let grants = count_rows(
        &db,
        "SELECT count() FROM group_admin WHERE group_id = '1' GROUP ALL",
    )
    .await;
    assert_eq!(
        grants, 0,
        "disabled fixture admin must not receive a restored grant"
    );
}

#[tokio::test]
async fn seed_dummy_admins_reconciles_role_drift_on_restart() {
    // If a fixture admin was re-roled via the admin UI after first seed
    // (e.g. admin3 demoted from super_admin to admin), the next restart
    // must restore the role declared in DUMMY_ADMINS so the fixture matrix
    // stays the source of truth. Also bumps token_version so any cached
    // access token the drifted user held is invalidated.
    let (_app, db) = test_app().await;
    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("first seed");

    // Drift admin3 from super_admin -> admin, simulating a manual demotion
    // via PATCH /api/admin/users/:id.
    let admin3_tv_before: Vec<i64> = db
        .query(
            "SELECT VALUE token_version FROM user \
             WHERE email_normalised = 'admin3@poolpay.test'",
        )
        .await
        .unwrap()
        .check()
        .unwrap()
        .take(0)
        .unwrap();
    let tv_before = *admin3_tv_before.first().expect("admin3 token_version");
    db.query(
        "UPDATE user SET role = 'admin' \
         WHERE email_normalised = 'admin3@poolpay.test'",
    )
    .await
    .unwrap()
    .check()
    .unwrap();

    bootstrap::seed_dummy_admins_with_flag(&db, true)
        .await
        .expect("second seed reconciles role");

    let super_admin_rows = count_rows(
        &db,
        "SELECT count() FROM user \
         WHERE email_normalised = 'admin3@poolpay.test' \
         AND role = 'super_admin' AND status = 'active' \
         GROUP ALL",
    )
    .await;
    assert_eq!(
        super_admin_rows, 1,
        "admin3 must be reconciled back to super_admin after drift"
    );

    let admin3_tv_after: Vec<i64> = db
        .query(
            "SELECT VALUE token_version FROM user \
             WHERE email_normalised = 'admin3@poolpay.test'",
        )
        .await
        .unwrap()
        .check()
        .unwrap()
        .take(0)
        .unwrap();
    let tv_after = *admin3_tv_after.first().expect("admin3 token_version");
    assert!(
        tv_after > tv_before,
        "role reconciliation must bump token_version (before={tv_before}, after={tv_after})"
    );
}
