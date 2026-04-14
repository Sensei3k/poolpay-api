/// Integration tests for the Axum REST API.
///
/// Each test spins up a fresh in-memory SurrealDB instance seeded with fixture
/// data, so tests are fully isolated and do not touch the filesystem.
///
/// Fixture counts (defined in db.rs):
///   - 1 group
///   - 6 members (all in group 1)
///   - 9 cycles (all in group 1)
///   - 49 payments
use axum::{
    body::Body,
    http::{Method, Request, StatusCode},
    response::Response,
    Router,
};
use http_body_util::BodyExt;
use poolpay::{api, db};
use tower::ServiceExt;

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Single global lock serializing every `std::env::set_var`/`remove_var`
/// call in this integration binary. Per-helper `OnceLock`s stop each helper
/// from mutating the env more than once, but distinct helpers' first-time
/// initializers can still race under parallel tests — which violates
/// `set_var`'s safety precondition. Taking this mutex before any mutation
/// makes the writer window mutually exclusive across helpers.
fn env_lock() -> &'static std::sync::Mutex<()> {
    static ENV_LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    ENV_LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

/// Build a fresh app backed by an isolated in-memory DB.
async fn test_app() -> Router {
    // The /api/test/reset endpoint is only mounted when APP_ENV is "test" or
    // "development" (fail-closed). Set it once for the whole suite.
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let _guard = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        // Safety: serialized by `env_lock()`; called once before any test
        // reads APP_ENV.
        unsafe { std::env::set_var("APP_ENV", "test") };
    });
    let conn = db::init_memory().await.expect("failed to init test DB");
    api::router(conn)
}

/// Build a fresh app with three pre-seeded admin users:
/// `TEST_SUPER_ADMIN_SUB` as `super_admin`, `TEST_ADMIN_SUB` as a
/// role-only `admin` with no group grants, and `TEST_SCOPED_ADMIN_SUB`
/// as an `admin` with a matching `group_admin` row for the fixture group.
///
/// The seeded users back every admin test in the suite: `SuperAdminUser`
/// re-reads `user.role` from the DB on every request, and
/// `GroupScopedAdmin::ensure` re-reads the `group_admin` join row, so the
/// JWT alone is not enough — each claim needs a real user (and, for
/// scoped flows, a real grant) to succeed or fail predictably.
///
/// `OnceLock` keeps `set_var` to a single mutation per process; `env_lock()`
/// serialises that mutation against every other env writer in this binary.
async fn test_app_with_auth() -> Router {
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let _guard = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        // Safety: serialized by `env_lock()`; called once before any test
        // that reads APP_ENV runs. APP_ENV must be set before the first
        // `api::router()` call so the JWT verifier can generate ephemeral
        // RSA keys (prod fail-closed gate).
        unsafe { std::env::set_var("APP_ENV", "test") };
    });
    let conn = db::init_memory().await.expect("failed to init test DB");
    seed_test_admin_users(&conn).await;
    api::router(conn)
}

const TEST_SUPER_ADMIN_SUB: &str = "test-super-admin";
const TEST_ADMIN_SUB: &str = "test-admin";
const TEST_SCOPED_ADMIN_SUB: &str = "test-scoped-admin";
/// Fixture group the scoped admin is granted access to — matches the
/// single group id produced by `db::init_memory()`.
const TEST_SCOPED_ADMIN_GROUP: &str = "1";

/// Insert three pre-baked admin user rows so JWT-gated handlers find a
/// matching `user` record on the `claims.sub → user` lookup, plus a
/// `group_admin` row granting `TEST_SCOPED_ADMIN_SUB` access to the
/// fixture group.
///
/// * `TEST_SUPER_ADMIN_SUB` — bypasses `GroupScopedAdmin` via role.
/// * `TEST_SCOPED_ADMIN_SUB` — scoped `admin` with a matching
///   `group_admin` row for `TEST_SCOPED_ADMIN_GROUP`; exercises the
///   positive branch of `require_group_scope`.
/// * `TEST_ADMIN_SUB` — `admin` with no `group_admin` rows; the
///   canonical 403 fixture for both `SuperAdminUser` and
///   `GroupScopedAdmin` handlers.
async fn seed_test_admin_users(db: &poolpay::db::DbConn) {
    use poolpay::api::models::{DbUser, UserContent, now_iso};

    for (sub, role) in [
        (TEST_SUPER_ADMIN_SUB, "super_admin"),
        (TEST_ADMIN_SUB, "admin"),
        (TEST_SCOPED_ADMIN_SUB, "admin"),
    ] {
        let now = now_iso();
        let content = UserContent {
            email: format!("{sub}@test.local"),
            email_normalised: format!("{sub}@test.local"),
            password_hash: None,
            role: role.into(),
            status: "active".into(),
            token_version: 0,
            must_reset_password: false,
            created_at: now.clone(),
            updated_at: now,
            deleted_at: None,
        };
        let _: Option<DbUser> = db
            .upsert(("user", sub))
            .content(content)
            .await
            .expect("seed admin user");
    }

    // Grant the scoped admin access to the fixture group. Inserted via raw
    // query because `group_admin` has no helper Content type in the test
    // harness and the schema asserts `UNIQUE(user_id, group_id)`.
    let now = poolpay::api::models::now_iso();
    db.query(
        "CREATE group_admin SET \
             user_id = $uid, group_id = $gid, \
             created_at = $now, created_by = $creator",
    )
    .bind(("uid", TEST_SCOPED_ADMIN_SUB.to_string()))
    .bind(("gid", TEST_SCOPED_ADMIN_GROUP.to_string()))
    .bind(("now", now))
    .bind(("creator", TEST_SUPER_ADMIN_SUB.to_string()))
    .await
    .expect("seed group_admin row")
    .check()
    .expect("group_admin insert check");
}

async fn call(app: Router, req: Request<Body>) -> Response {
    app.oneshot(req).await.unwrap()
}

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

/// Mint an admin access token signed by the same verifier the app uses.
/// Caller passes both `sub` (must match a seeded `user` row) and `role`
/// (`super_admin` or `admin`) so a single test can sign tokens for
/// distinct user fixtures — needed for the `SuperAdminUser` 403 case,
/// which has to present a JWT for a real `admin`-role user.
///
/// `SuperAdminUser` re-reads the role from the DB row (not the JWT
/// claim), so the role argument here only populates the claim for
/// signing; it is not currently used for authorisation or consistency
/// checks against the DB user.
fn mint_admin_jwt(sub: &str, role: &str) -> String {
    assert!(
        matches!(role, "super_admin" | "admin"),
        "mint_admin_jwt only mints admin-tier roles; got {role}"
    );
    // `shared_verifier()` fails closed if `APP_ENV` is not `test` /
    // `development` and `JWT_KEYS` is absent. Mirror the env init here
    // so callers can use the helper without going through `test_app()`.
    static INIT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INIT.get_or_init(|| {
        let _guard = env_lock().lock().unwrap_or_else(|p| p.into_inner());
        // Safety: serialized by `env_lock()` with every other env mutator
        // in this binary; called once before any caller reads APP_ENV
        // through the verifier; other suite helpers set the same value.
        unsafe { std::env::set_var("APP_ENV", "test") };
    });
    poolpay::api::shared_verifier()
        .mint_access(sub, role, 0)
        .expect("shared verifier must mint")
}

fn super_admin_bearer() -> String {
    format!("Bearer {}", mint_admin_jwt(TEST_SUPER_ADMIN_SUB, "super_admin"))
}

fn admin_bearer() -> String {
    format!("Bearer {}", mint_admin_jwt(TEST_ADMIN_SUB, "admin"))
}

/// Bearer for an `admin`-role user with a matching `group_admin` row
/// for `TEST_SCOPED_ADMIN_GROUP`. Used to verify that scoped admins —
/// not just super-admins — can reach `GroupScopedAdmin` handlers.
fn scoped_admin_bearer() -> String {
    format!("Bearer {}", mint_admin_jwt(TEST_SCOPED_ADMIN_SUB, "admin"))
}

fn post_json_jwt(uri: &str, body: serde_json::Value) -> Request<Body> {
    post_json_jwt_with(uri, body, &super_admin_bearer())
}

fn post_json_jwt_with(uri: &str, body: serde_json::Value, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", bearer)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn patch_json_jwt(uri: &str, body: serde_json::Value) -> Request<Body> {
    patch_json_jwt_with(uri, body, &super_admin_bearer())
}

fn patch_json_jwt_with(uri: &str, body: serde_json::Value, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(Method::PATCH)
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", bearer)
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn delete_req_jwt(uri: &str) -> Request<Body> {
    delete_req_jwt_with(uri, &super_admin_bearer())
}

fn delete_req_jwt_with(uri: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(Method::DELETE)
        .uri(uri)
        .header("authorization", bearer)
        .body(Body::empty())
        .unwrap()
}

fn post_empty_jwt(uri: &str) -> Request<Body> {
    post_empty_jwt_with(uri, &super_admin_bearer())
}

fn post_empty_jwt_with(uri: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("authorization", bearer)
        .body(Body::empty())
        .unwrap()
}

fn get_jwt(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", super_admin_bearer())
        .body(Body::empty())
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

// ── Auth extractor tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn admin_no_auth_header_returns_401() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json("/api/admin/groups", serde_json::json!({"name": "Test"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_wrong_token_returns_401() {
    let app = test_app_with_auth().await;
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/admin/groups")
        .header("content-type", "application/json")
        .header("authorization", "Bearer wrong-token")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({"name": "Test"})).unwrap(),
        ))
        .unwrap();
    let resp = call(app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_group_super_admin_jwt_proceeds() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "New Group"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

/// BE-5a guard: groups endpoints are `SuperAdminUser`-gated, so a valid
/// JWT for a real `admin`-role user must be rejected with 403. Pairs
/// with `create_group_super_admin_jwt_proceeds` above (the 200/super-admin
/// half) and the legacy `admin_*_returns_401` cases (the no-token /
/// garbage-token half).
#[tokio::test]
async fn create_group_admin_role_jwt_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with("/api/admin/groups", serde_json::json!({"name": "x"}), &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── GET /api/groups ──────────────────────────────────────────────────────────

#[tokio::test]
async fn get_groups_returns_200() {
    let resp = call(test_app().await, get("/api/groups")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_groups_returns_seeded_group() {
    let resp = call(test_app().await, get("/api/groups")).await;
    let groups: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "PoolPay Group Alpha");
}

#[tokio::test]
async fn get_groups_response_shape() {
    let resp = call(test_app().await, get("/api/groups")).await;
    let groups: Vec<serde_json::Value> = json_body(resp).await;
    let g = &groups[0];
    assert!(g.get("id").is_some(), "missing id");
    assert!(g.get("name").is_some(), "missing name");
    assert!(g.get("status").is_some(), "missing status");
    assert!(g.get("createdAt").is_some(), "missing createdAt");
    assert!(g.get("updatedAt").is_some(), "missing updatedAt");
    assert!(g.get("version").is_some(), "missing version");
}

// ── POST /api/admin/groups ───────────────────────────────────────────────────

#[tokio::test]
async fn create_group_returns_201_with_body() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "Beta Circle"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let group: serde_json::Value = json_body(resp).await;
    assert_eq!(group["name"], "Beta Circle");
    assert_eq!(group["status"], "active");
    assert_eq!(group["version"], 1);
}

#[tokio::test]
async fn create_group_name_too_long_returns_400() {
    let app = test_app_with_auth().await;
    let long_name = "a".repeat(101);
    let resp = call(
        app,
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": long_name})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_group_empty_name_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "  "})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── PATCH /api/admin/groups/{id} ─────────────────────────────────────────────

#[tokio::test]
async fn update_group_name_only() {
    let app = test_app_with_auth().await;
    let resp = call(
        app.clone(),
        patch_json_jwt(
            "/api/admin/groups/1",
            serde_json::json!({"name": "Renamed Circle", "version": 1}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let group: serde_json::Value = json_body(resp).await;
    assert_eq!(group["name"], "Renamed Circle");
    assert_eq!(group["version"], 2);
}

#[tokio::test]
async fn update_group_version_mismatch_returns_409() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt(
            "/api/admin/groups/1",
            serde_json::json!({"name": "X", "version": 999}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ── DELETE /api/admin/groups/{id} ────────────────────────────────────────────

#[tokio::test]
async fn delete_group_with_members_returns_409() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/admin/groups/1")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ── GET /api/members ─────────────────────────────────────────────────────────

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
    assert!(first.get("groupId").is_some(), "missing groupId");
    assert!(first.get("createdAt").is_some(), "missing createdAt");
    assert!(first.get("updatedAt").is_some(), "missing updatedAt");
    assert!(first.get("version").is_some(), "missing version");
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

#[tokio::test]
async fn get_members_filter_by_group_id() {
    let resp = call(test_app().await, get("/api/members?groupId=1")).await;
    let members: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(members.len(), 6);
    for m in &members {
        assert_eq!(m["groupId"], "1");
    }
}

#[tokio::test]
async fn get_members_filter_unknown_group_returns_empty() {
    let resp = call(test_app().await, get("/api/members?groupId=999")).await;
    let members: Vec<serde_json::Value> = json_body(resp).await;
    assert!(members.is_empty());
}

// ── POST /api/admin/groups/{gid}/members ─────────────────────────────────────

#[tokio::test]
async fn create_member_returns_201() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/groups/1/members",
            serde_json::json!({
                "name": "New Member",
                "phone": "2340000000000",
                "position": 7
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let member: serde_json::Value = json_body(resp).await;
    assert_eq!(member["name"], "New Member");
    assert_eq!(member["groupId"], "1");
    assert_eq!(member["status"], "active");
}

#[tokio::test]
async fn create_member_duplicate_phone_same_group_returns_409() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/groups/1/members",
            serde_json::json!({
                "name": "Duplicate Phone",
                "phone": "2348101234567",
                "position": 7
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_member_same_phone_different_group_allowed() {
    let app = test_app_with_auth().await;

    // Create a second group first.
    let resp = call(
        app.clone(),
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "Second Group"})),
    )
    .await;
    let new_group: serde_json::Value = json_body(resp).await;
    let group_id = new_group["id"].as_str().unwrap();

    // Same phone as member 1 in group 1 — should succeed in different group.
    let resp = call(
        app,
        post_json_jwt(
            &format!("/api/admin/groups/{group_id}/members"),
            serde_json::json!({
                "name": "Cross-Group Member",
                "phone": "2348101234567",
                "position": 1
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn create_member_nonexistent_group_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/groups/999/members",
            serde_json::json!({
                "name": "Orphan",
                "phone": "2340000000000",
                "position": 1
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── PATCH /api/admin/members/{id} ────────────────────────────────────────────

#[tokio::test]
async fn update_member_name_only_preserves_other_fields() {
    let app = test_app_with_auth().await;

    // Read current state of member 1.
    let before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/members")).await).await;
    let member1 = before.iter().find(|m| m["id"] == "1").unwrap();
    let original_phone = member1["phone"].as_str().unwrap().to_string();
    let original_position = member1["position"].as_i64().unwrap();

    let resp = call(
        app,
        patch_json_jwt(
            "/api/admin/members/1",
            serde_json::json!({"name": "Updated Name", "version": 1}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let updated: serde_json::Value = json_body(resp).await;
    assert_eq!(updated["name"], "Updated Name");
    assert_eq!(updated["phone"], original_phone);
    assert_eq!(updated["position"], original_position);
    assert_eq!(updated["version"], 2);
}

#[tokio::test]
async fn update_member_version_mismatch_returns_409() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt(
            "/api/admin/members/1",
            serde_json::json!({"name": "X", "version": 999}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn update_member_phone_to_duplicate_returns_409() {
    let app = test_app_with_auth().await;
    // Member 2's phone is "2347031234567". Try changing member 1's phone to it.
    let resp = call(
        app,
        patch_json_jwt(
            "/api/admin/members/1",
            serde_json::json!({"phone": "2347031234567", "version": 1}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ── DELETE /api/admin/members/{id} ───────────────────────────────────────────

#[tokio::test]
async fn delete_member_active_cycle_recipient_returns_409() {
    // Member 3 is the recipient of cycle 3 (the active cycle).
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/admin/members/3")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_member_not_recipient_returns_204() {
    // Member 6 is not the recipient of the active cycle.
    let app = test_app_with_auth().await;
    let resp = call(app.clone(), delete_req_jwt("/api/admin/members/6")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify soft delete — member no longer in default list.
    let members: Vec<serde_json::Value> =
        json_body(call(app, get("/api/members")).await).await;
    assert_eq!(members.len(), 5);
}

#[tokio::test]
async fn delete_already_deleted_member_returns_204() {
    let app = test_app_with_auth().await;

    // Delete member 6.
    let resp = call(app.clone(), delete_req_jwt("/api/admin/members/6")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Try to delete again — should still find the record via select but it
    // will appear deleted. The handler fetches by ID without soft-delete
    // filtering, so it will find it. This tests the current behaviour.
    let resp = call(app, delete_req_jwt("/api/admin/members/6")).await;
    // The handler succeeds (re-sets deleted_at) — this is acceptable.
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ── GET /api/cycles ──────────────────────────────────────────────────────────

#[tokio::test]
async fn get_cycles_returns_200() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_cycles_returns_nine_cycles() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(cycles.len(), 9);
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
    assert!(c.get("groupId").is_some(), "missing groupId");
    assert!(c.get("createdAt").is_some(), "missing createdAt");
    assert!(c.get("updatedAt").is_some(), "missing updatedAt");
    assert!(c.get("version").is_some(), "missing version");
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
            status == "pending" || status == "active" || status == "closed",
            "unexpected status value: {status}"
        );
    }
}

#[tokio::test]
async fn get_cycles_filter_by_group_id() {
    let resp = call(test_app().await, get("/api/cycles?groupId=1")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(cycles.len(), 9);
}

#[tokio::test]
async fn get_cycles_filter_unknown_group_returns_empty() {
    let resp = call(test_app().await, get("/api/cycles?groupId=999")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    assert!(cycles.is_empty());
}

// ── POST /api/admin/groups/{gid}/cycles ──────────────────────────────────────

#[tokio::test]
async fn create_cycle_returns_201_with_computed_total() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/groups/1/cycles",
            serde_json::json!({
                "cycleNumber": 10,
                "startDate": "2026-04-01",
                "endDate": "2026-04-30",
                "contributionPerMember": 1_000_000,
                "recipientMemberId": "4"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let cycle: serde_json::Value = json_body(resp).await;
    assert_eq!(cycle["cycleNumber"], 10);
    assert_eq!(cycle["status"], "pending");
    assert_eq!(cycle["groupId"], "1");
    // 6 active members × 1,000,000 = 6,000,000
    assert_eq!(cycle["totalAmount"], 6_000_000);
}

#[tokio::test]
async fn create_cycle_recipient_wrong_group_returns_400() {
    let app = test_app_with_auth().await;

    // Create a second group.
    let resp = call(
        app.clone(),
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "Other Group"})),
    )
    .await;
    let other_group: serde_json::Value = json_body(resp).await;
    let other_gid = other_group["id"].as_str().unwrap();

    // Create a member in the other group.
    let resp = call(
        app.clone(),
        post_json_jwt(
            &format!("/api/admin/groups/{other_gid}/members"),
            serde_json::json!({
                "name": "Other Member",
                "phone": "2340000000001",
                "position": 1
            }),
        ),
    )
    .await;
    let other_member: serde_json::Value = json_body(resp).await;
    let other_mid = other_member["id"].as_str().unwrap();

    // Try to create cycle in group 1 with recipient from other group.
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/groups/1/cycles",
            serde_json::json!({
                "cycleNumber": 10,
                "startDate": "2026-04-01",
                "endDate": "2026-04-30",
                "contributionPerMember": 1_000_000,
                "recipientMemberId": other_mid
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── PATCH /api/admin/cycles/{id} ─────────────────────────────────────────────

#[tokio::test]
async fn update_cycle_contribution_recomputes_total() {
    let app = test_app_with_auth().await;

    // Cycle 3 (id=3) is the active cycle with contribution 1,000,000.
    let resp = call(
        app,
        patch_json_jwt(
            "/api/admin/cycles/3",
            serde_json::json!({
                "contributionPerMember": 2_000_000,
                "version": 1
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cycle: serde_json::Value = json_body(resp).await;
    assert_eq!(cycle["contributionPerMember"], 2_000_000);
    // 6 active members × 2,000,000 = 12,000,000
    assert_eq!(cycle["totalAmount"], 12_000_000);
    assert_eq!(cycle["version"], 2);
}

// ── DELETE /api/admin/cycles/{id} ────────────────────────────────────────────

#[tokio::test]
async fn delete_cycle_with_payments_returns_409() {
    let app = test_app_with_auth().await;
    // Cycle 3 has 3 fixture payments.
    let resp = call(app, delete_req_jwt("/api/admin/cycles/3")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn delete_cycle_without_payments_returns_204() {
    let app = test_app_with_auth().await;

    // Create a new cycle with no payments.
    let resp = call(
        app.clone(),
        post_json_jwt(
            "/api/admin/groups/1/cycles",
            serde_json::json!({
                "cycleNumber": 99,
                "startDate": "2026-05-01",
                "endDate": "2026-05-31",
                "contributionPerMember": 1_000_000,
                "recipientMemberId": "1"
            }),
        ),
    )
    .await;
    let cycle: serde_json::Value = json_body(resp).await;
    let cycle_id = cycle["id"].as_str().unwrap();

    let resp = call(
        app,
        delete_req_jwt(&format!("/api/admin/cycles/{cycle_id}")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn create_cycle_start_after_end_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/groups/1/cycles",
            serde_json::json!({
                "cycleNumber": 99,
                "startDate": "2026-12-01",
                "endDate": "2026-01-01",
                "contributionPerMember": 1_000_000,
                "recipientMemberId": "1"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── GET /api/payments ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_payments_returns_200() {
    let resp = call(test_app().await, get("/api/payments")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_payments_returns_forty_nine_total() {
    let resp = call(test_app().await, get("/api/payments")).await;
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 49);
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
    assert!(p.get("createdAt").is_some(), "missing createdAt");
    assert!(p.get("updatedAt").is_some(), "missing updatedAt");
}

#[tokio::test]
async fn get_payments_filter_by_cycle_id_returns_subset() {
    let resp = call(test_app().await, get("/api/payments?cycleId=3")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 3, "cycle 3 should have 3 fixture payments");
    for p in &payments {
        assert_eq!(p["cycleId"], "3", "all returned payments must belong to cycle 3");
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

// ── POST /api/payments ──────────────────────────────────────────────────────

#[tokio::test]
async fn create_payment_requires_auth() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn create_payment_returns_201() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4",
                "cycleId": "3",
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
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4",
                "cycleId": "3",
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    let payment: serde_json::Value = json_body(resp).await;
    assert!(payment.get("id").is_some(), "missing id");
    assert_eq!(payment["memberId"], "4");
    assert_eq!(payment["cycleId"], "3");
    assert_eq!(payment["amount"], 1_000_000);
    assert_eq!(payment["currency"], "NGN");
    assert_eq!(payment["paymentDate"], "2026-03-10");
}

#[tokio::test]
async fn create_payment_persists_to_db() {
    let app = test_app_with_auth().await;

    call(
        app.clone(),
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4",
                "cycleId": "3",
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;

    let resp = call(app, get("/api/payments?cycleId=3")).await;
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 4, "cycle 3 should now have 4 payments");
}

#[tokio::test]
async fn create_payment_zero_amount_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": 0, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_negative_amount_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": -500, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_invalid_currency_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": 1_000_000, "currency": "USD", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_invalid_date_format_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "10-03-2026"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_empty_date_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": ""
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_invalid_member_id_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_payment_nonexistent_member_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "999", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_payment_nonexistent_cycle_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "1", "cycleId": "999",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_payment_same_group_returns_201() {
    let app = test_app_with_auth().await;

    // Member 1 and cycle 3 are both in group 1 — payment should be accepted.
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "1", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ── DELETE /api/payments/:memberId/:cycleId ─────────────────────────────────

#[tokio::test]
async fn delete_payment_requires_auth() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req("/api/payments/1/3")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_payment_returns_204() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/payments/1/3")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_payment_soft_deletes_record() {
    let app = test_app_with_auth().await;

    let before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments?cycleId=3")).await).await;
    assert_eq!(before.len(), 3);

    call(app.clone(), delete_req_jwt("/api/payments/1/3")).await;

    // Soft-deleted payment should no longer appear in the default list.
    let after: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments?cycleId=3")).await).await;
    assert_eq!(after.len(), 2);
}

#[tokio::test]
async fn delete_payment_unknown_member_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/payments/999/3")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_payment_unknown_cycle_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/payments/1/999")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_payment_404_body_has_error_field() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/payments/999/3")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = json_body(resp).await;
    assert!(
        body.get("error").is_some(),
        "404 response must have an 'error' field"
    );
}

// ── POST /api/test/reset ────────────────────────────────────────────────────

#[tokio::test]
async fn reset_endpoint_returns_200() {
    let resp = call(test_app().await, post_empty("/api/test/reset")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn reset_restores_payments_to_fixture_count() {
    let app = test_app_with_auth().await;

    call(
        app.clone(),
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "4", "cycleId": "3",
                "amount": 1_000_000, "currency": "NGN", "paymentDate": "2026-03-10"
            }),
        ),
    )
    .await;

    call(app.clone(), post_empty("/api/test/reset")).await;

    let payments: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments")).await).await;
    assert_eq!(payments.len(), 49, "reset should restore 49 fixture payments");
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
    assert_eq!(cycles.len(), 9);
}

#[tokio::test]
async fn reset_restores_groups() {
    let app = test_app().await;
    call(app.clone(), post_empty("/api/test/reset")).await;
    let groups: Vec<serde_json::Value> =
        json_body(call(app, get("/api/groups")).await).await;
    assert_eq!(groups.len(), 1);
}

// ── Error response contract ─────────────────────────────────────────────────

#[tokio::test]
async fn bad_request_error_has_json_error_field() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/payments",
            serde_json::json!({
                "memberId": "", "cycleId": "3",
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
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/payments/999/999")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = json_body(resp).await;
    assert!(body.get("error").is_some(), "404 must have an 'error' field");
}

#[tokio::test]
async fn unauthorized_error_has_json_error_field() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json("/api/admin/groups", serde_json::json!({"name": "X"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = json_body(resp).await;
    assert!(body.get("error").is_some(), "401 must have an 'error' field");
}

#[tokio::test]
async fn conflict_error_has_json_error_field() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/admin/groups/1")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = json_body(resp).await;
    assert!(body.get("error").is_some(), "409 must have an 'error' field");
}

// ── WhatsApp links (admin CRUD) ─────────────────────────────────────────────

#[tokio::test]
async fn create_whatsapp_link_no_auth_returns_401() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000001@g.us", "groupId": "1"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_whatsapp_links_no_auth_returns_401() {
    let app = test_app_with_auth().await;
    let resp = call(app, get("/api/admin/whatsapp-links")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_whatsapp_link_no_auth_returns_401() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req("/api/admin/whatsapp-links/xyz")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// BE-5f guard: WhatsApp link endpoints are `SuperAdminUser`-gated, so a
/// JWT for a real `admin`-role user (no `super_admin` privilege) must
/// be rejected with 403. Mirrors `create_group_admin_role_jwt_returns_403`.
#[tokio::test]
async fn create_whatsapp_link_admin_role_jwt_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000099999@g.us", "groupId": "1"}),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_whatsapp_link_returns_201_with_body() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000001@g.us", "groupId": "1"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let link: serde_json::Value = json_body(resp).await;
    assert!(link.get("id").is_some(), "missing id");
    assert_eq!(link["chatId"], "2349000000001@g.us");
    assert_eq!(link["groupId"], "1");
    assert!(link.get("createdAt").is_some(), "missing createdAt");
    assert!(link.get("updatedAt").is_some(), "missing updatedAt");
}

#[tokio::test]
async fn create_whatsapp_link_missing_group_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000001@g.us", "groupId": "999"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_whatsapp_link_deleted_group_returns_404() {
    let app = test_app_with_auth().await;

    // Create a group, then soft-delete it.
    let resp = call(
        app.clone(),
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "Doomed"})),
    )
    .await;
    let group: serde_json::Value = json_body(resp).await;
    let gid = group["id"].as_str().unwrap().to_string();
    let del = call(
        app.clone(),
        delete_req_jwt(&format!("/api/admin/groups/{gid}")),
    )
    .await;
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000002@g.us", "groupId": gid}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_whatsapp_link_duplicate_chat_id_returns_409() {
    let app = test_app_with_auth().await;
    let body = serde_json::json!({"chatId": "2349000000003@g.us", "groupId": "1"});

    let first = call(app.clone(), post_json_jwt("/api/admin/whatsapp-links", body.clone())).await;
    assert_eq!(first.status(), StatusCode::CREATED);

    let second = call(app, post_json_jwt("/api/admin/whatsapp-links", body)).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn create_whatsapp_link_empty_chat_id_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "   ", "groupId": "1"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn create_whatsapp_link_empty_group_id_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000004@g.us", "groupId": ""}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_whatsapp_links_returns_200_empty_on_fresh_db() {
    let app = test_app_with_auth().await;
    let resp = call(app, get_jwt("/api/admin/whatsapp-links")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let links: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(links.len(), 0);
}

#[tokio::test]
async fn get_whatsapp_links_excludes_soft_deleted() {
    let app = test_app_with_auth().await;

    let created = call(
        app.clone(),
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000005@g.us", "groupId": "1"}),
        ),
    )
    .await;
    let link: serde_json::Value = json_body(created).await;
    let id = link["id"].as_str().unwrap().to_string();

    let before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get_jwt("/api/admin/whatsapp-links")).await).await;
    assert_eq!(before.len(), 1);

    let del = call(
        app.clone(),
        delete_req_jwt(&format!("/api/admin/whatsapp-links/{id}")),
    )
    .await;
    assert_eq!(del.status(), StatusCode::NO_CONTENT);

    let after: Vec<serde_json::Value> =
        json_body(call(app, get_jwt("/api/admin/whatsapp-links")).await).await;
    assert_eq!(after.len(), 0, "soft-deleted links must be excluded");
}

#[tokio::test]
async fn delete_whatsapp_link_returns_204() {
    let app = test_app_with_auth().await;
    let created = call(
        app.clone(),
        post_json_jwt(
            "/api/admin/whatsapp-links",
            serde_json::json!({"chatId": "2349000000006@g.us", "groupId": "1"}),
        ),
    )
    .await;
    let link: serde_json::Value = json_body(created).await;
    let id = link["id"].as_str().unwrap().to_string();

    let resp = call(
        app,
        delete_req_jwt(&format!("/api/admin/whatsapp-links/{id}")),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn delete_whatsapp_link_nonexistent_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        delete_req_jwt("/api/admin/whatsapp-links/does-not-exist"),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_whatsapp_link_allows_relinking_same_chat_id() {
    let app = test_app_with_auth().await;
    let body = serde_json::json!({"chatId": "2349000000007@g.us", "groupId": "1"});

    let first = call(
        app.clone(),
        post_json_jwt("/api/admin/whatsapp-links", body.clone()),
    )
    .await;
    let link: serde_json::Value = json_body(first).await;
    let id = link["id"].as_str().unwrap().to_string();

    call(
        app.clone(),
        delete_req_jwt(&format!("/api/admin/whatsapp-links/{id}")),
    )
    .await;

    // Recreate the same chat_id — should succeed because previous row is soft-deleted.
    let second = call(app, post_json_jwt("/api/admin/whatsapp-links", body)).await;
    assert_eq!(second.status(), StatusCode::CREATED);
}

// ── GET /api/receipts ────────────────────────────────────────────────────────

#[tokio::test]
async fn get_receipts_returns_200() {
    let resp = call(test_app().await, get("/api/receipts")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_receipts_no_auth_header_is_public() {
    // No Authorization header — endpoint must still succeed (public read).
    let resp = call(test_app().await, get("/api/receipts")).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_receipts_returns_seeded_fixtures() {
    let resp = call(test_app().await, get("/api/receipts")).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(
        !receipts.is_empty(),
        "expected at least one seeded receipt fixture"
    );
}

#[tokio::test]
async fn get_receipts_response_shape() {
    let resp = call(test_app().await, get("/api/receipts")).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    let r = &receipts[0];
    for field in [
        "id",
        "whatsappMessageId",
        "groupId",
        "chatId",
        "senderPhone",
        "status",
        "receivedAt",
        "createdAt",
        "updatedAt",
    ] {
        assert!(r.get(field).is_some(), "missing field: {field}");
    }
}

#[tokio::test]
async fn get_receipts_filter_by_group_id() {
    let app = test_app().await;
    let resp = call(app, get("/api/receipts?groupId=1")).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(receipts.iter().all(|r| r["groupId"] == "1"));
}

#[tokio::test]
async fn get_receipts_filter_by_group_id_unknown_returns_empty() {
    let app = test_app().await;
    let resp = call(app, get("/api/receipts?groupId=does-not-exist")).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(receipts.len(), 0);
}

#[tokio::test]
async fn get_receipts_filter_by_status_pending() {
    let app = test_app().await;
    let resp = call(app, get("/api/receipts?status=pending")).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(receipts.iter().all(|r| r["status"] == "pending"));
}

#[tokio::test]
async fn get_receipts_invalid_status_returns_400() {
    let app = test_app().await;
    let resp = call(app, get("/api/receipts?status=weird")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_receipts_excludes_soft_deleted() {
    // At least one fixture receipt has deleted_at set — ensure it's filtered out.
    let app = test_app().await;
    let resp = call(app, get("/api/receipts")).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(
        receipts.iter().all(|r| r.get("deletedAt").is_none()
            || r["deletedAt"].is_null()),
        "soft-deleted receipts must not be returned"
    );
}

#[tokio::test]
async fn reset_restores_receipts_to_fixture_count() {
    let app = test_app().await;
    let before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/receipts")).await).await;
    let baseline = before.len();
    call(app.clone(), post_empty("/api/test/reset")).await;
    let after: Vec<serde_json::Value> =
        json_body(call(app, get("/api/receipts")).await).await;
    assert_eq!(after.len(), baseline);
}

// ── POST /api/admin/receipts/{id}/confirm ────────────────────────────────────

#[tokio::test]
async fn confirm_receipt_requires_auth() {
    let app = test_app_with_auth().await;
    let resp = call(app, post_empty("/api/admin/receipts/1/confirm")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn confirm_receipt_unknown_id_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(app, post_empty_jwt("/api/admin/receipts/does-not-exist/confirm")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn confirm_receipt_soft_deleted_returns_404() {
    // Fixture receipt id 2 is soft-deleted.
    let app = test_app_with_auth().await;
    let resp = call(app, post_empty_jwt("/api/admin/receipts/2/confirm")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn confirm_receipt_marks_status_and_creates_payment() {
    let app = test_app_with_auth().await;

    let payments_before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments")).await).await;
    let baseline = payments_before.len();

    let resp = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated: serde_json::Value = json_body(resp).await;
    assert_eq!(updated["status"], "confirmed");
    assert_eq!(updated["id"], "1");

    let payments_after: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments")).await).await;
    assert_eq!(payments_after.len(), baseline + 1);

    let new_payment = payments_after
        .iter()
        .find(|p| p["reference"] == "3EB0C123ABCD4567EF89")
        .expect("expected new payment referencing the receipt's whatsapp message id");
    assert_eq!(new_payment["memberId"], "4");
    assert_eq!(new_payment["cycleId"], "3");
    assert_eq!(new_payment["amount"], 1_000_000);
    assert_eq!(new_payment["currency"], "NGN");
    assert!(new_payment["confirmedAt"].is_string());
}

#[tokio::test]
async fn confirm_receipt_twice_returns_409() {
    let app = test_app_with_auth().await;
    let first = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = call(app, post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn confirm_receipt_with_existing_payment_for_member_cycle_returns_409() {
    // Pre-create a payment for the same member+cycle referenced by receipt 1,
    // then confirm the receipt and verify the duplicate-payment guard returns
    // HTTP 409 Conflict.
    let app = test_app_with_auth().await;
    let create = post_json_jwt(
        "/api/payments",
        serde_json::json!({
            "memberId": "4",
            "cycleId": "3",
            "amount": 1_000_000,
            "currency": "NGN",
            "paymentDate": "2026-03-02"
        }),
    );
    let create_resp = call(app.clone(), create).await;
    assert_eq!(create_resp.status(), StatusCode::CREATED);

    let resp = call(app, post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

// ── POST /api/admin/receipts/{id}/reject ─────────────────────────────────────

#[tokio::test]
async fn reject_receipt_requires_auth() {
    let app = test_app_with_auth().await;
    let resp = call(app, post_empty("/api/admin/receipts/1/reject")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn reject_receipt_unknown_id_returns_404() {
    let app = test_app_with_auth().await;
    let resp = call(app, post_empty_jwt("/api/admin/receipts/nope/reject")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn reject_receipt_marks_status_and_creates_no_payment() {
    let app = test_app_with_auth().await;
    let payments_before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments")).await).await;
    let baseline = payments_before.len();

    let resp = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/reject")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let updated: serde_json::Value = json_body(resp).await;
    assert_eq!(updated["status"], "rejected");

    let payments_after: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments")).await).await;
    assert_eq!(payments_after.len(), baseline);
}

#[tokio::test]
async fn reject_receipt_already_rejected_returns_409() {
    // Fixture receipt id 2 is rejected and soft-deleted, so reject hits 404.
    // Use receipt 1: reject once, then try again.
    let app = test_app_with_auth().await;
    let first = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/reject")).await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = call(app, post_empty_jwt("/api/admin/receipts/1/reject")).await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn confirm_after_reject_returns_409() {
    let app = test_app_with_auth().await;
    let r = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/reject")).await;
    assert_eq!(r.status(), StatusCode::OK);
    let c = call(app, post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(c.status(), StatusCode::CONFLICT);
}

// ── GroupScopedAdmin guard (BE-5b–e) ─────────────────────────────────────────
//
// These cases pin both branches of `require_group_scope` for every
// group-scoped resource. `admin_bearer()` is an `admin`-role user with
// no `group_admin` rows — it must be rejected with 403 on any handler
// behind `GroupScopedAdmin`. `scoped_admin_bearer()` is an `admin` with
// a `group_admin{user_id, group_id=1}` row and must succeed on the same
// endpoints. Super-admin happy paths are already covered above via
// `super_admin_bearer()` through the normal resource tests.

#[tokio::test]
async fn create_member_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/admin/groups/1/members",
            serde_json::json!({
                "name": "Gatekept",
                "phone": "+2348099990001",
                "position": 7,
            }),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_member_scoped_admin_proceeds() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/admin/groups/1/members",
            serde_json::json!({
                "name": "Scoped Success",
                "phone": "+2348099990002",
                "position": 7,
            }),
            &scoped_admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn update_member_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt_with(
            "/api/admin/members/1",
            serde_json::json!({"name": "x", "version": 1}),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_member_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        delete_req_jwt_with("/api/admin/members/3", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_cycle_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/admin/groups/1/cycles",
            serde_json::json!({
                "cycleNumber": 99,
                "startDate": "2027-01-01",
                "endDate": "2027-01-31",
                "contributionPerMember": 1_000,
                "recipientMemberId": "4",
            }),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_cycle_scoped_admin_proceeds() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/admin/groups/1/cycles",
            serde_json::json!({
                "cycleNumber": 99,
                "startDate": "2027-01-01",
                "endDate": "2027-01-31",
                "contributionPerMember": 1_000,
                "recipientMemberId": "4",
            }),
            &scoped_admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn update_cycle_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt_with(
            "/api/admin/cycles/1",
            serde_json::json!({"version": 1, "status": "closed"}),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_cycle_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        delete_req_jwt_with("/api/admin/cycles/3", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_payment_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/payments",
            serde_json::json!({
                "memberId": "4",
                "cycleId": "3",
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10",
            }),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_payment_scoped_admin_proceeds() {
    let app = test_app_with_auth().await;
    // Member 4 has no payment in fixture cycle 3 yet; member 4 belongs to group 1.
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/payments",
            serde_json::json!({
                "memberId": "4",
                "cycleId": "3",
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10",
            }),
            &scoped_admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn delete_payment_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        delete_req_jwt_with("/api/payments/1/3", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn confirm_receipt_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_empty_jwt_with("/api/admin/receipts/1/confirm", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reject_receipt_admin_without_group_admin_returns_403() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_empty_jwt_with("/api/admin/receipts/1/reject", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn reject_receipt_scoped_admin_proceeds() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_empty_jwt_with("/api/admin/receipts/1/reject", &scoped_admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Opaque-denial for unknown ids (cross-tenant existence probing) ───────────
//
// A non-scoped `admin` must not be able to distinguish "this id doesn't
// exist" from "this id exists in a group you can't touch" — both collapse
// to 403. Super-admins still see 404 for truly missing ids (covered by
// the existing `*_unknown_*_returns_404` tests that run under
// `super_admin_bearer()`).

#[tokio::test]
async fn update_member_unknown_id_denies_non_scoped_admin_opaquely() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt_with(
            "/api/admin/members/does-not-exist",
            serde_json::json!({"name": "x", "version": 1}),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_cycle_unknown_id_denies_non_scoped_admin_opaquely() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        delete_req_jwt_with("/api/admin/cycles/does-not-exist", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn confirm_receipt_unknown_id_denies_non_scoped_admin_opaquely() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_empty_jwt_with("/api/admin/receipts/does-not-exist/confirm", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn create_payment_unknown_member_denies_non_scoped_admin_opaquely() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        post_json_jwt_with(
            "/api/payments",
            serde_json::json!({
                "memberId": "does-not-exist",
                "cycleId": "3",
                "amount": 1_000_000,
                "currency": "NGN",
                "paymentDate": "2026-03-10",
            }),
            &admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn delete_payment_unknown_cycle_denies_non_scoped_admin_opaquely() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        delete_req_jwt_with("/api/payments/1/does-not-exist", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
