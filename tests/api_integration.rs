/// Integration tests for the Axum REST API.
///
/// Each test spins up a fresh in-memory SurrealDB instance seeded with fixture
/// data, so tests are fully isolated and do not touch the filesystem.
///
/// Fixture counts (defined in db.rs):
///   - 1 group
///   - 6 members (all in group 1)
///   - 12 cycles (all in group 1): cycles 1–8 closed, cycle 9 active,
///     cycles 10–12 pending (upcoming Apr–Jun 2026)
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
    test_app_with_auth_and_db().await.0
}

/// Same setup as `test_app_with_auth`, but also returns the shared `DbConn`
/// so tests can inspect rows the public API hides (e.g. soft-deleted
/// payments that get filtered out of `/api/payments`).
async fn test_app_with_auth_and_db() -> (Router, db::DbConn) {
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
    let router = api::router(conn.clone());
    (router, conn)
}

const TEST_SUPER_ADMIN_SUB: &str = "test-super-admin";
const TEST_ADMIN_SUB: &str = "test-admin";
const TEST_SCOPED_ADMIN_SUB: &str = "test-scoped-admin";
/// `member`-role fixture user — used to assert that member tokens are
/// admitted to `GET /api/receipts` (the route is gated by
/// `AuthenticatedUser`) but receive the stripped projection that omits
/// bot-supplied content and sender PII. Admin-review fields are
/// admin-only.
const TEST_MEMBER_SUB: &str = "test-member";
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
    use poolpay::api::models::{now_iso, DbUser, UserContent};

    for (sub, role) in [
        (TEST_SUPER_ADMIN_SUB, "super_admin"),
        (TEST_ADMIN_SUB, "admin"),
        (TEST_SCOPED_ADMIN_SUB, "admin"),
        (TEST_MEMBER_SUB, "member"),
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
            version: 1,
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

/// Mint an access token for the given role, signed by the same verifier
/// the app uses. Caller passes both `sub` (must match a seeded `user`
/// row) and `role` (`super_admin`, `admin`, or `member`) so a single
/// test can sign tokens for distinct user fixtures — needed for cases
/// like the `SuperAdminUser` 403, which has to present a JWT for a real
/// `admin`-role user, and for member-only assertions that confirm
/// admin-gated fields are stripped from non-admin callers.
///
/// Role-agnostic by design: the `SuperAdminUser` extractor re-reads the
/// role from the DB row (not the JWT claim), so the role argument here
/// only populates the claim for signing; it is not currently used for
/// authorisation or consistency checks against the DB user.
fn mint_user_jwt(sub: &str, role: &str) -> String {
    assert!(
        matches!(role, "super_admin" | "admin" | "member"),
        "mint_user_jwt only mints known user roles; got {role}"
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
    format!(
        "Bearer {}",
        mint_user_jwt(TEST_SUPER_ADMIN_SUB, "super_admin")
    )
}

fn admin_bearer() -> String {
    format!("Bearer {}", mint_user_jwt(TEST_ADMIN_SUB, "admin"))
}

/// Bearer for an `admin`-role user with a matching `group_admin` row
/// for `TEST_SCOPED_ADMIN_GROUP`. Used to verify that scoped admins —
/// not just super-admins — can reach `GroupScopedAdmin` handlers.
fn scoped_admin_bearer() -> String {
    format!("Bearer {}", mint_user_jwt(TEST_SCOPED_ADMIN_SUB, "admin"))
}

/// Bearer for a `member`-role user. Used to verify that handlers which
/// release admin-only fields to admin callers (e.g. `GET /api/receipts`)
/// still strip those fields for member callers — a valid token is not
/// the same as admin authority.
fn member_bearer() -> String {
    format!("Bearer {}", mint_user_jwt(TEST_MEMBER_SUB, "member"))
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
    get_jwt_with(uri, &super_admin_bearer())
}

fn get_jwt_with(uri: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("authorization", bearer)
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
        post_json_jwt(
            "/api/admin/groups",
            serde_json::json!({"name": "New Group"}),
        ),
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
        post_json_jwt_with(
            "/api/admin/groups",
            serde_json::json!({"name": "x"}),
            &admin_bearer(),
        ),
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
        post_json_jwt(
            "/api/admin/groups",
            serde_json::json!({"name": "Beta Circle"}),
        ),
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
        post_json_jwt(
            "/api/admin/groups",
            serde_json::json!({"name": "Second Group"}),
        ),
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
    let members: Vec<serde_json::Value> = json_body(call(app, get("/api/members")).await).await;
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
async fn get_cycles_returns_all_fixture_cycles() {
    let resp = call(test_app().await, get("/api/cycles")).await;
    let cycles: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(cycles.len(), 12);
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
    assert!(
        c.get("contributionPerMember").is_some(),
        "missing contributionPerMember"
    );
    assert!(c.get("totalAmount").is_some(), "missing totalAmount");
    assert!(
        c.get("recipientMemberId").is_some(),
        "missing recipientMemberId"
    );
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
    assert_eq!(cycles.len(), 12);
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
        post_json_jwt(
            "/api/admin/groups",
            serde_json::json!({"name": "Other Group"}),
        ),
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
        assert_eq!(
            p["cycleId"], "3",
            "all returned payments must belong to cycle 3"
        );
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
    assert!(
        payments.is_empty(),
        "unknown cycle should return empty array"
    );
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
async fn delete_payment_populates_deleted_by() {
    // The public list filters soft-deleted rows out, so reach into the DB
    // directly to confirm the audit column was populated from the caller's
    // JWT subject.
    use poolpay::api::models::DbPayment;

    let (app, conn) = test_app_with_auth_and_db().await;
    let resp = call(app, delete_req_jwt("/api/payments/1/3")).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let rows: Vec<DbPayment> = conn
        .query("SELECT * FROM payment WHERE member_id = $mid AND cycle_id = $cid")
        .bind(("mid", "1".to_string()))
        .bind(("cid", "3".to_string()))
        .await
        .expect("select payment")
        .take(0)
        .expect("decode payments");
    let deleted = rows
        .into_iter()
        .find(|p| p.deleted_at.is_some())
        .expect("soft-deleted payment row should exist");
    assert_eq!(deleted.deleted_by.as_deref(), Some(TEST_SUPER_ADMIN_SUB));
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

    let payments: Vec<serde_json::Value> = json_body(call(app, get("/api/payments")).await).await;
    assert_eq!(
        payments.len(),
        49,
        "reset should restore 49 fixture payments"
    );
}

#[tokio::test]
async fn reset_restores_members() {
    let app = test_app().await;
    call(app.clone(), post_empty("/api/test/reset")).await;
    let members: Vec<serde_json::Value> = json_body(call(app, get("/api/members")).await).await;
    assert_eq!(members.len(), 6);
}

#[tokio::test]
async fn reset_restores_cycles() {
    let app = test_app().await;
    call(app.clone(), post_empty("/api/test/reset")).await;
    let cycles: Vec<serde_json::Value> = json_body(call(app, get("/api/cycles")).await).await;
    assert_eq!(cycles.len(), 12);
}

#[tokio::test]
async fn reset_restores_groups() {
    let app = test_app().await;
    call(app.clone(), post_empty("/api/test/reset")).await;
    let groups: Vec<serde_json::Value> = json_body(call(app, get("/api/groups")).await).await;
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
    assert!(
        body.get("error").is_some(),
        "400 must have an 'error' field"
    );
    assert!(body["error"].is_string(), "'error' must be a string");
}

#[tokio::test]
async fn not_found_error_has_json_error_field() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/payments/999/999")).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: serde_json::Value = json_body(resp).await;
    assert!(
        body.get("error").is_some(),
        "404 must have an 'error' field"
    );
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
    assert!(
        body.get("error").is_some(),
        "401 must have an 'error' field"
    );
}

#[tokio::test]
async fn conflict_error_has_json_error_field() {
    let app = test_app_with_auth().await;
    let resp = call(app, delete_req_jwt("/api/admin/groups/1")).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    let body: serde_json::Value = json_body(resp).await;
    assert!(
        body.get("error").is_some(),
        "409 must have an 'error' field"
    );
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

    let first = call(
        app.clone(),
        post_json_jwt("/api/admin/whatsapp-links", body.clone()),
    )
    .await;
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
    let resp = call(
        test_app_with_auth().await,
        get_jwt_with("/api/receipts", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn get_receipts_no_auth_header_returns_401() {
    // No Authorization header — endpoint must reject. The listing route is
    // gated behind `AuthenticatedUser` because the payload contains
    // bot-supplied content and sender PII that a compromised bot can
    // poison; anonymous read access turns a bot compromise into a public
    // phishing / XSS surface.
    let resp = call(test_app_with_auth().await, get("/api/receipts")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_receipts_returns_seeded_fixtures() {
    let resp = call(
        test_app_with_auth().await,
        get_jwt_with("/api/receipts", &admin_bearer()),
    )
    .await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(
        !receipts.is_empty(),
        "expected at least one seeded receipt fixture"
    );
}

#[tokio::test]
async fn get_receipts_response_shape() {
    let resp = call(
        test_app_with_auth().await,
        get_jwt_with("/api/receipts", &admin_bearer()),
    )
    .await;
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
    let app = test_app_with_auth().await;
    let resp = call(app, get_jwt_with("/api/receipts?groupId=1", &admin_bearer())).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(receipts.iter().all(|r| r["groupId"] == "1"));
}

#[tokio::test]
async fn get_receipts_filter_by_group_id_unknown_returns_empty() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        get_jwt_with("/api/receipts?groupId=does-not-exist", &admin_bearer()),
    )
    .await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(receipts.len(), 0);
}

#[tokio::test]
async fn get_receipts_filter_by_status_pending() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        get_jwt_with("/api/receipts?status=pending", &admin_bearer()),
    )
    .await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(receipts.iter().all(|r| r["status"] == "pending"));
}

#[tokio::test]
async fn get_receipts_invalid_status_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        get_jwt_with("/api/receipts?status=weird", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_receipts_excludes_soft_deleted() {
    // At least one fixture receipt has deleted_at set — ensure it's filtered out.
    let app = test_app_with_auth().await;
    let resp = call(app, get_jwt_with("/api/receipts", &admin_bearer())).await;
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert!(
        receipts
            .iter()
            .all(|r| r.get("deletedAt").is_none() || r["deletedAt"].is_null()),
        "soft-deleted receipts must not be returned"
    );
}

#[tokio::test]
async fn reset_restores_receipts_to_fixture_count() {
    let app = test_app_with_auth().await;
    let before: Vec<serde_json::Value> = json_body(
        call(
            app.clone(),
            get_jwt_with("/api/receipts", &admin_bearer()),
        )
        .await,
    )
    .await;
    let baseline = before.len();
    call(app.clone(), post_empty("/api/test/reset")).await;
    let after: Vec<serde_json::Value> = json_body(
        call(app, get_jwt_with("/api/receipts", &admin_bearer())).await,
    )
    .await;
    assert_eq!(after.len(), baseline);
}

/// Seed the bot-supplied content fields and admin note on receipt id `1`
/// so the projection tests can prove which callers see them and which do
/// not. The fixture leaves these fields blank or `None`; the serializer
/// skips `None`, so without a real value present we cannot distinguish
/// "field stripped" from "field never set" — write known values here and
/// assert against them.
async fn seed_strippable_fields_on_receipt_one(db: &poolpay::db::DbConn) {
    use surrealdb::types::RecordId;
    db.query(
        "UPDATE $id SET \
             raw_image_url = $url, \
             rejection_reason = $reason, \
             ocr_text = $ocr, \
             sender_label = $sender, \
             bank_label = $bank",
    )
    .bind(("id", RecordId::new("receipt", "1".to_string())))
    .bind(("url", "https://example.invalid/screenshot.png".to_string()))
    .bind(("reason", "needs manual review".to_string()))
    .bind(("ocr", "NGN 1,000,000.00\nFrom: Tunde Bakare".to_string()))
    .bind(("sender", "Tunde Bakare".to_string()))
    .bind(("bank", "GTBank".to_string()))
    .await
    .expect("seed strippable fields")
    .check()
    .expect("strippable field update must succeed");
}

/// Fields that must NEVER appear in a non-admin projection of the listing.
/// Bot-supplied content (`rawImageUrl`, `ocrText`, `senderLabel`,
/// `bankLabel`) is attacker-controllable through a compromised WhatsApp
/// bot; `senderPhone` is PII; `rejectionReason` is an admin note. Surfacing
/// any of these to non-admin callers turns a bot compromise or a stolen
/// member token into a public phishing / data-exfil surface.
const NON_ADMIN_STRIPPED_FIELDS: &[&str] = &[
    "rawImageUrl",
    "rejectionReason",
    "ocrText",
    "senderPhone",
    "senderLabel",
    "bankLabel",
];

#[tokio::test]
async fn get_receipts_anonymous_returns_401() {
    // Anonymous callers cannot reach the listing at all — the route is
    // gated behind `AuthenticatedUser`. Token presence is not authority,
    // but token absence is an outright refusal.
    let app = test_app_with_auth().await;
    let resp = call(app, get("/api/receipts")).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_receipts_member_token_strips_sensitive_fields() {
    // A valid token is not the same as admin authority — `member`-role
    // callers receive a stripped projection that omits bot-supplied
    // content and sender PII even when the underlying row has them
    // populated.
    let (app, db) = test_app_with_auth_and_db().await;
    seed_strippable_fields_on_receipt_one(&db).await;

    let resp = call(app, get_jwt_with("/api/receipts", &member_bearer())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    let r = receipts
        .iter()
        .find(|r| r["id"] == "1")
        .expect("receipt 1 must be in the listing");
    for field in NON_ADMIN_STRIPPED_FIELDS {
        assert!(
            r.get(field).is_none(),
            "member-token callers must not see {field}: {r}"
        );
    }
}

#[tokio::test]
async fn get_receipts_admin_token_includes_sensitive_fields() {
    // Admin-tier callers (`admin` or `super_admin`) are the only callers
    // who get the full payload — they need the bot-supplied content to
    // triage the pending queue and `rejectionReason` for audit context.
    let (app, db) = test_app_with_auth_and_db().await;
    seed_strippable_fields_on_receipt_one(&db).await;

    let resp = call(app, get_jwt_with("/api/receipts", &admin_bearer())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    let r = receipts
        .iter()
        .find(|r| r["id"] == "1")
        .expect("receipt 1 must be in the listing");
    assert_eq!(r["rawImageUrl"], "https://example.invalid/screenshot.png");
    assert_eq!(r["rejectionReason"], "needs manual review");
    assert_eq!(r["ocrText"], "NGN 1,000,000.00\nFrom: Tunde Bakare");
    assert_eq!(r["senderLabel"], "Tunde Bakare");
    assert_eq!(r["bankLabel"], "GTBank");
    // `senderPhone` is sourced from the row itself (always present in the
    // DB, not from the test seed), so just assert it surfaces as a string.
    assert!(
        r["senderPhone"].is_string(),
        "admin callers must see senderPhone: {r}"
    );
}

#[tokio::test]
async fn get_receipts_super_admin_token_includes_sensitive_fields() {
    // `super_admin` is strictly more privileged than `admin`; if `admin`
    // sees the full payload, super-admin must as well.
    let (app, db) = test_app_with_auth_and_db().await;
    seed_strippable_fields_on_receipt_one(&db).await;

    let resp = call(app, get_jwt_with("/api/receipts", &super_admin_bearer())).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    let r = receipts
        .iter()
        .find(|r| r["id"] == "1")
        .expect("receipt 1 must be in the listing");
    assert_eq!(r["rawImageUrl"], "https://example.invalid/screenshot.png");
    assert_eq!(r["rejectionReason"], "needs manual review");
    assert_eq!(r["ocrText"], "NGN 1,000,000.00\nFrom: Tunde Bakare");
    assert_eq!(r["senderLabel"], "Tunde Bakare");
    assert_eq!(r["bankLabel"], "GTBank");
    assert!(r["senderPhone"].is_string());
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
    let resp = call(
        app,
        post_empty_jwt("/api/admin/receipts/does-not-exist/confirm"),
    )
    .await;
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
    let (app, db) = test_app_with_auth_and_db().await;

    let payments_before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments")).await).await;
    let baseline = payments_before.len();

    let resp = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let updated: serde_json::Value = json_body(resp).await;
    assert_eq!(updated["status"], "confirmed");
    assert_eq!(updated["id"], "1");
    // Audit: the confirming admin is recorded on the receipt row itself.
    assert_eq!(updated["confirmedBy"], TEST_SUPER_ADMIN_SUB);

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
    // Audit: same admin is attributed on the payment created from the receipt.
    assert_eq!(new_payment["confirmedBy"], TEST_SUPER_ADMIN_SUB);

    // Audit: the `auth_event` row carries the linked member as the subject
    // (user_id), not null. Receipt 1's fixture has member_id="4".
    use surrealdb_types::SurrealValue;
    #[derive(Debug, serde::Deserialize, SurrealValue)]
    struct AuthEventRow {
        user_id: Option<String>,
        actor_id: Option<String>,
        success: bool,
    }
    let rows: Vec<AuthEventRow> = db
        .query(
            "SELECT user_id, actor_id, success FROM auth_event \
             WHERE event_type = 'receipt_confirmed' AND success = true",
        )
        .await
        .expect("select auth_event")
        .take(0)
        .expect("decode auth_event rows");
    let event = rows
        .into_iter()
        .find(|r| r.success && r.actor_id.as_deref() == Some(TEST_SUPER_ADMIN_SUB))
        .expect("expected successful receipt_confirmed auth_event for this admin");
    assert_eq!(
        event.user_id.as_deref(),
        Some("4"),
        "auth_event.user_id should be the linked member id, not null"
    );
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
    // Audit: rejecting admin is recorded so later reviewers can attribute the decision.
    assert_eq!(updated["rejectedBy"], TEST_SUPER_ADMIN_SUB);

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
        post_empty_jwt_with(
            "/api/admin/receipts/does-not-exist/confirm",
            &admin_bearer(),
        ),
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

// ── Pagination ────────────────────────────────────────────────────────────────
//
// Cover the limit/offset contract added in #16: defaults, hard cap,
// validation errors, header trio, and the count-vs-page invariant when
// filters and pagination combine. All five list endpoints share the same
// parser (`api::pagination`), so per-handler coverage is intentionally
// thin — the contract tests below pick the most informative endpoint
// for each rule and rely on the shared parser unit tests in
// `src/api/pagination.rs` for the rest.

/// Read the `X-Total-Count` header as `u32`, panicking with a clear
/// message if it's missing or unparseable. Centralised so each test
/// reads the contract the same way.
fn total_count_header(resp: &Response) -> u32 {
    resp.headers()
        .get("x-total-count")
        .expect("X-Total-Count header missing")
        .to_str()
        .expect("X-Total-Count is not valid ASCII")
        .parse::<u32>()
        .expect("X-Total-Count is not a u32")
}

#[tokio::test]
async fn pagination_default_limit_returns_all_payments_with_total_header() {
    // Fixture has 49 payments; with the default limit of 50 the body
    // returns all of them and X-Total-Count reports 49.
    let resp = call(test_app().await, get("/api/payments")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(total_count_header(&resp), 49);
    assert_eq!(resp.headers().get("x-limit").unwrap(), "50");
    assert_eq!(resp.headers().get("x-offset").unwrap(), "0");
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 49);
}

#[tokio::test]
async fn pagination_explicit_limit_truncates_body_but_not_total_count() {
    // ?limit=10 returns 10 rows in the body; the header still reports
    // the total matching the endpoint's filters (for payments, the
    // active/undeleted total) so the FE can render "showing 10 of 49".
    let resp = call(test_app().await, get("/api/payments?limit=10")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(total_count_header(&resp), 49);
    assert_eq!(resp.headers().get("x-limit").unwrap(), "10");
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 10);
}

#[tokio::test]
async fn pagination_offset_skips_rows_and_keeps_total_count_stable() {
    // Take the first 10 rows, then take the next 10 by offsetting; the
    // page two contents must not overlap with page one (id-disjoint).
    let app = test_app().await;
    let page1: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments?limit=10")).await).await;
    let resp = call(app, get("/api/payments?limit=10&offset=10")).await;
    assert_eq!(total_count_header(&resp), 49);
    assert_eq!(resp.headers().get("x-offset").unwrap(), "10");
    let page2: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(page2.len(), 10);
    let page1_ids: std::collections::HashSet<&str> =
        page1.iter().map(|p| p["id"].as_str().unwrap()).collect();
    for p in &page2 {
        let id = p["id"].as_str().unwrap();
        assert!(
            !page1_ids.contains(id),
            "offset page must not overlap with first page; saw {id} on both"
        );
    }
}

#[tokio::test]
async fn pagination_limit_over_max_returns_400() {
    let resp = call(test_app().await, get("/api/payments?limit=300")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pagination_limit_zero_returns_400() {
    // A zero-row page is never useful — clamping silently would mask
    // FE bugs. We reject and document the contract.
    let resp = call(test_app().await, get("/api/payments?limit=0")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pagination_non_numeric_limit_returns_400() {
    let resp = call(test_app().await, get("/api/payments?limit=abc")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pagination_negative_offset_returns_400() {
    // The parser accepts only non-negative integers; a leading `-` is a
    // signed digit that fails `u32::parse`.
    let resp = call(test_app().await, get("/api/payments?offset=-1")).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn pagination_filter_and_limit_combine_correctly_for_members() {
    // Group 1 has 6 members; with limit=2 the body returns 2 rows but
    // X-Total-Count still reports the filtered total (6).
    let resp = call(test_app().await, get("/api/members?groupId=1&limit=2")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(total_count_header(&resp), 6);
    let members: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(members.len(), 2);
    for m in &members {
        assert_eq!(m["groupId"], "1");
    }
}

#[tokio::test]
async fn pagination_filter_and_limit_combine_correctly_for_payments_by_cycle() {
    // Cycle 1 has 6 fixture payments. limit=3 must return 3 rows; the
    // header reports 6, not the table-wide 49.
    let resp = call(test_app().await, get("/api/payments?cycleId=1&limit=3")).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(total_count_header(&resp), 6);
    let payments: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(payments.len(), 3);
    for p in &payments {
        assert_eq!(p["cycleId"], "1");
    }
}

#[tokio::test]
async fn pagination_excludes_soft_deleted_receipts_from_total_count() {
    // The receipts fixture seeds two rows — one active, one
    // soft-deleted. After filtering, the count + body should both
    // surface only the active row.
    let resp = call(
        test_app_with_auth().await,
        get_jwt_with("/api/receipts?limit=200", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let total = total_count_header(&resp);
    let receipts: Vec<serde_json::Value> = json_body(resp).await;
    assert_eq!(
        receipts.len() as u32,
        total,
        "header must equal body length when limit > total"
    );
    assert!(
        receipts
            .iter()
            .all(|r| r.get("deletedAt").is_none() || r["deletedAt"].is_null()),
        "soft-deleted rows must be excluded from the page"
    );
}

// ── PATCH /api/receipts/{id} (Slice 5) ────────────────────────────────────────
//
// Covers the unified action endpoint: confirm / reject / flag dispatch,
// scope gating, payload validation, and the side effects (payment row +
// inbox item on confirm; rejection_reason persistence; member-scoped
// inbox message on reject/flag).

/// Pull every `inbox_item` for one user_id. Used by the PATCH + inbox
/// suites to assert side-effect rows landed where they should. The query
/// flows through the same SurrealDB handle the API uses, so an index
/// regression would fail the read here too.
async fn fetch_inbox_for_user(db: &poolpay::db::DbConn, user_id: &str) -> Vec<serde_json::Value> {
    use surrealdb_types::SurrealValue;
    #[derive(Debug, serde::Deserialize, SurrealValue)]
    struct Row {
        kind: String,
        title: String,
        body: String,
        pool_id: Option<String>,
        receipt_id: Option<String>,
        read_at: Option<String>,
    }
    let rows: Vec<Row> = db
        .query("SELECT * FROM inbox_item WHERE user_id = $uid ORDER BY created_at ASC")
        .bind(("uid", user_id.to_string()))
        .await
        .expect("inbox query")
        .take(0)
        .expect("inbox rows");
    rows.into_iter()
        .map(|r| {
            serde_json::json!({
                "kind": r.kind,
                "title": r.title,
                "body": r.body,
                "poolId": r.pool_id,
                "receiptId": r.receipt_id,
                "readAt": r.read_at,
            })
        })
        .collect()
}

#[tokio::test]
async fn patch_receipt_confirm_returns_200_and_sets_confirmed_status() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["status"], "confirmed");
    assert_eq!(body["confirmedBy"], TEST_SUPER_ADMIN_SUB);
}

#[tokio::test]
async fn patch_receipt_reject_returns_200_and_persists_reason() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt(
            "/api/receipts/1",
            serde_json::json!({"action": "reject", "reason": "wrong amount"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["status"], "rejected");
    assert_eq!(body["rejectedBy"], TEST_SUPER_ADMIN_SUB);
    assert_eq!(body["rejectionReason"], "wrong amount");
}

#[tokio::test]
async fn patch_receipt_flag_returns_200_and_sets_flagged_status() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt(
            "/api/receipts/1",
            serde_json::json!({"action": "flag", "reason": "needs review"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body: serde_json::Value = json_body(resp).await;
    assert_eq!(body["status"], "flagged");
    // `flag` is "needs review", not a rejection: `rejectedBy` must NOT be
    // populated with the flagging admin or downstream consumers will
    // interpret it as proof of rejection.
    assert!(body.get("rejectedBy").is_none() || body["rejectedBy"].is_null());
    assert_eq!(body["rejectionReason"], "needs review");
}

#[tokio::test]
async fn patch_receipt_missing_action_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"reason": "nope"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_receipt_invalid_action_returns_400() {
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "destroy"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_receipt_scoped_admin_denied_cross_group_returns_403() {
    // The scoped admin is granted access to group 1 only. Receipt 1 lives
    // in group 1, so the scoped admin succeeds; to exercise the denied
    // branch we need a receipt in a different group. Create a second
    // group + a fresh receipt row directly via the SurrealDB handle.
    use poolpay::api::models::{now_iso, ReceiptContent};
    let (app, db) = test_app_with_auth_and_db().await;

    // Create group 2 via the admin API (super-admin path).
    let g = call(
        app.clone(),
        post_json_jwt(
            "/api/admin/groups",
            serde_json::json!({"name": "Off-limits"}),
        ),
    )
    .await;
    assert_eq!(g.status(), StatusCode::CREATED);
    let new_group: serde_json::Value = json_body(g).await;
    let other_group_id = new_group["id"].as_str().unwrap().to_string();

    // Insert a pending receipt directly in that group.
    let now = now_iso();
    let other_receipt_id = "patch-foreign-receipt";
    let content = ReceiptContent {
        whatsapp_message_id: "WAMSG-FOREIGN".into(),
        group_id: other_group_id,
        chat_id: "0000@g.us".into(),
        sender_phone: "0000".into(),
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
        received_at: now.clone(),
        ingested_at: Some(poolpay::api::models::server_now()),
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
        confirmed_by: None,
        rejected_by: None,
        deleted_by: None,
    };
    let _: Option<poolpay::api::models::DbReceipt> = db
        .upsert(("receipt", other_receipt_id))
        .content(content)
        .await
        .expect("seed off-limits receipt");

    let resp = call(
        app,
        patch_json_jwt_with(
            &format!("/api/receipts/{other_receipt_id}"),
            serde_json::json!({"action": "reject"}),
            &scoped_admin_bearer(),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn patch_receipt_super_admin_allowed_cross_group() {
    // Same setup as the denied case, but called with the super-admin
    // bearer — must succeed regardless of which group the receipt lives in.
    use poolpay::api::models::{now_iso, ReceiptContent};
    let (app, db) = test_app_with_auth_and_db().await;
    let g = call(
        app.clone(),
        post_json_jwt("/api/admin/groups", serde_json::json!({"name": "Other"})),
    )
    .await;
    let new_group: serde_json::Value = json_body(g).await;
    let other_group_id = new_group["id"].as_str().unwrap().to_string();

    let now = now_iso();
    let other_receipt_id = "patch-super-cross-receipt";
    let content = ReceiptContent {
        whatsapp_message_id: "WAMSG-CROSS".into(),
        group_id: other_group_id,
        chat_id: "0001@g.us".into(),
        sender_phone: "0000".into(),
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
        received_at: now.clone(),
        ingested_at: Some(poolpay::api::models::server_now()),
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
        confirmed_by: None,
        rejected_by: None,
        deleted_by: None,
    };
    let _: Option<poolpay::api::models::DbReceipt> = db
        .upsert(("receipt", other_receipt_id))
        .content(content)
        .await
        .expect("seed cross-group receipt");

    let resp = call(
        app,
        patch_json_jwt(
            &format!("/api/receipts/{other_receipt_id}"),
            serde_json::json!({"action": "reject"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn patch_receipt_double_confirm_returns_409() {
    let app = test_app_with_auth().await;
    let first = call(
        app.clone(),
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(second.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn patch_receipt_reason_persisted_on_reject() {
    let (app, db) = test_app_with_auth_and_db().await;
    let resp = call(
        app,
        patch_json_jwt(
            "/api/receipts/1",
            serde_json::json!({"action": "reject", "reason": "duplicate"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Read the row directly via Surreal to make sure the value really
    // lives in the DB and is not just echoed back from the request body.
    let row: Option<poolpay::api::models::DbReceipt> =
        db.select(("receipt", "1")).await.expect("select receipt");
    let row = row.expect("receipt row");
    assert_eq!(row.status, "rejected");
    assert_eq!(row.rejection_reason.as_deref(), Some("duplicate"));
}

#[tokio::test]
async fn patch_receipt_confirm_creates_payment_and_inbox_item() {
    let (app, db) = test_app_with_auth_and_db().await;

    let payments_before: Vec<serde_json::Value> =
        json_body(call(app.clone(), get("/api/payments")).await).await;
    let baseline = payments_before.len();

    let resp = call(
        app.clone(),
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Payment row created.
    let payments_after: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments")).await).await;
    assert_eq!(payments_after.len(), baseline + 1);

    // Inbox item created for the matched member (member id "4" per fixtures).
    let inbox = fetch_inbox_for_user(&db, "4").await;
    assert!(
        inbox.iter().any(|r| r["kind"] == "receipt_confirmed"),
        "expected a receipt_confirmed inbox row for matched member, got {inbox:?}"
    );
}

#[tokio::test]
async fn patch_receipt_reason_too_long_returns_400() {
    let app = test_app_with_auth().await;
    let oversized = "a".repeat(281);
    let resp = call(
        app,
        patch_json_jwt(
            "/api/receipts/1",
            serde_json::json!({"action": "reject", "reason": oversized}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn patch_receipt_confirm_rejects_reason_field() {
    // `reason` is meaningless for confirm; surface a 400 so FE bugs that
    // mis-route a reject body do not silently bury an admin's note.
    let app = test_app_with_auth().await;
    let resp = call(
        app,
        patch_json_jwt(
            "/api/receipts/1",
            serde_json::json!({"action": "confirm", "reason": "should not be here"}),
        ),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── inbox_item side effects (Slice 5) ─────────────────────────────────────────
//
// Verifies the new inbox_item table behaves end-to-end: rows materialise
// on confirm, are scoped to the matched member, respect the SCHEMAFULL
// kind ASSERT, are queryable via the index path, survive a soft-delete
// of the underlying receipt, and surface a count the FE can gate on.

#[tokio::test]
async fn inbox_item_created_on_confirm() {
    let (app, db) = test_app_with_auth_and_db().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let inbox = fetch_inbox_for_user(&db, "4").await;
    assert_eq!(
        inbox.len(),
        1,
        "exactly one inbox row should land on confirm"
    );
    assert_eq!(inbox[0]["kind"], "receipt_confirmed");
}

#[tokio::test]
async fn inbox_item_scoped_to_matched_member_only() {
    let (app, db) = test_app_with_auth_and_db().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Receipt 1's matched member is "4"; every other member must have an
    // empty inbox. Pick member "1" (Adaeze) as the negative case.
    let inbox_other = fetch_inbox_for_user(&db, "1").await;
    assert!(
        inbox_other.is_empty(),
        "non-matched member must not receive an inbox row, got {inbox_other:?}"
    );
}

#[tokio::test]
async fn inbox_item_kind_enum_enforced_at_db_layer() {
    // Insert directly via Surreal with an unsupported `kind`; the
    // SCHEMAFULL ASSERT should reject it. Catches a future handler that
    // forgets to validate.
    use poolpay::api::models::{now_iso, InboxItemContent};
    let (_app, db) = test_app_with_auth_and_db().await;
    let now = now_iso();
    let content = InboxItemContent {
        user_id: "1".into(),
        kind: "bogus_kind".into(),
        title: "should fail".into(),
        body: "".into(),
        pool_id: None,
        cycle_id: None,
        receipt_id: None,
        read_at: None,
        created_at: now,
    };
    let result: Result<Option<poolpay::api::models::DbInboxItem>, _> =
        db.create("inbox_item").content(content).await;
    assert!(
        result.is_err(),
        "DB-side ASSERT must reject unknown inbox kinds; got Ok({:?})",
        result.ok()
    );
}

#[tokio::test]
async fn inbox_item_queryable_via_user_index() {
    // Confirms a receipt, then queries the index-backed (user_id) path
    // and matches the row by receipt_id. Failing this would imply the
    // schema's index never landed or the writer skipped a column.
    let (app, db) = test_app_with_auth_and_db().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    let inbox = fetch_inbox_for_user(&db, "4").await;
    let row = inbox.first().expect("expected one row");
    assert_eq!(row["receiptId"], "1");
    assert_eq!(row["poolId"], "1");
}

#[tokio::test]
async fn inbox_item_survives_receipt_soft_delete() {
    // Inbox is the user-facing audit trail; even when the underlying
    // receipt is soft-deleted later, the inbox row stays so the user can
    // still see they were notified. Confirms the FK is logical, not
    // enforced via cascade.
    use poolpay::api::models::{now_iso, ReceiptContent};
    let (app, db) = test_app_with_auth_and_db().await;
    let resp = call(
        app,
        patch_json_jwt("/api/receipts/1", serde_json::json!({"action": "confirm"})),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Soft-delete receipt 1 by replacing the row with deleted_at set.
    let now = now_iso();
    let updated = ReceiptContent {
        whatsapp_message_id: "3EB0C123ABCD4567EF89".into(),
        group_id: "1".into(),
        chat_id: "2349000000001@g.us".into(),
        sender_phone: "2348031234567".into(),
        member_id: Some("4".into()),
        cycle_id: Some("3".into()),
        extracted_amount: Some(1_000_000),
        expected_amount: Some(1_000_000),
        amount_matches: Some(true),
        status: "confirmed".into(),
        ocr_text: None,
        sender_label: None,
        bank_label: None,
        raw_image_url: None,
        rejection_reason: None,
        received_at: now.clone(),
        ingested_at: Some(poolpay::api::models::server_now()),
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: Some(now),
        confirmed_by: Some(TEST_SUPER_ADMIN_SUB.into()),
        rejected_by: None,
        deleted_by: Some(TEST_SUPER_ADMIN_SUB.into()),
    };
    let _: Option<poolpay::api::models::DbReceipt> = db
        .upsert(("receipt", "1"))
        .content(updated)
        .await
        .expect("soft-delete receipt");

    let inbox = fetch_inbox_for_user(&db, "4").await;
    assert_eq!(
        inbox.len(),
        1,
        "inbox row must survive a soft-delete of the source receipt"
    );
}

#[tokio::test]
async fn inbox_count_gates_admin_landing_when_zero() {
    // HANDOFF §5.3: if an admin has no pending receipts to review the FE
    // lands them on /home instead of /admin/receipts. The backend
    // contract supporting this is "GET /api/receipts?status=pending"
    // returning an empty list when no pending rows exist. Confirms that
    // after every pending fixture row is acted on, the queue drains.
    let app = test_app_with_auth().await;

    let before = call(
        app.clone(),
        get_jwt_with("/api/receipts?status=pending&limit=200", &admin_bearer()),
    )
    .await;
    let pre: Vec<serde_json::Value> = json_body(before).await;
    assert!(
        !pre.is_empty(),
        "fixture must seed at least one pending receipt"
    );

    for r in &pre {
        let id = r["id"].as_str().unwrap();
        let resp = call(
            app.clone(),
            patch_json_jwt(
                &format!("/api/receipts/{id}"),
                serde_json::json!({"action": "reject"}),
            ),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "reject {id}");
    }

    let after = call(
        app,
        get_jwt_with("/api/receipts?status=pending&limit=200", &admin_bearer()),
    )
    .await;
    let post: Vec<serde_json::Value> = json_body(after).await;
    assert!(
        post.is_empty(),
        "queue must drain to zero so the admin lands on /home, got {post:?}"
    );
}

// ── Bot-clock independence ────────────────────────────────────────────────────

/// A bot that lies about `received_at` must NOT be able to backdate or
/// future-date the resulting payment row. `payment_date` is sourced from
/// the server-stamped `ingested_at`, so the bot-supplied timestamp is
/// purely forensic.
#[tokio::test]
async fn confirm_receipt_sources_payment_date_from_ingested_at_not_received_at() {
    let (app, db) = test_app_with_auth_and_db().await;

    // Receipt 1 is a pre-seeded pending receipt linked to member 4 / cycle 3.
    // Force a deliberate mismatch: bot claims a wildly future `received_at`,
    // server stamped `ingested_at` lives in the recent past.
    db.query(
        "UPDATE receipt:`1` SET \
             received_at = '2099-12-31T23:59:59+00:00', \
             ingested_at = '2026-03-10T10:00:00.000Z'",
    )
    .await
    .expect("rewrite receipt 1 timestamps");

    let resp = call(app.clone(), post_empty_jwt("/api/admin/receipts/1/confirm")).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let payments: Vec<serde_json::Value> =
        json_body(call(app, get("/api/payments?limit=200")).await).await;
    let new_payment = payments
        .iter()
        .find(|p| p["reference"] == "3EB0C123ABCD4567EF89")
        .expect("payment created from receipt 1");
    assert_eq!(
        new_payment["paymentDate"], "2026-03-10",
        "payment_date must follow server ingested_at, not bot-supplied received_at"
    );
}

/// The admin queue must order by the server-stamped `ingested_at`. A
/// bot that lies about `received_at` (forward or backward) cannot move
/// its row out of true arrival order.
#[tokio::test]
async fn admin_receipt_queue_orders_by_ingested_at_not_received_at() {
    use poolpay::api::models::{now_iso, ReceiptContent};
    let (app, db) = test_app_with_auth_and_db().await;

    // Two test rows with deliberately inverted `received_at` vs
    // `ingested_at`. If the queue still ordered by `received_at`, B (with
    // the older bot timestamp) would come before A — but A was actually
    // ingested first, so the server timeline must win.
    let now = now_iso();
    let insert = |id: &'static str, received_at: &'static str, ingested_at: &'static str| {
        let content = ReceiptContent {
            whatsapp_message_id: format!("WAMSG-CLOCKTEST-{id}"),
            group_id: poolpay::api::models::EntityId::from("1".to_string()),
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
            received_at: received_at.into(),
            ingested_at: Some(ingested_at.into()),
            created_at: now.clone(),
            updated_at: now.clone(),
            deleted_at: None,
            confirmed_by: None,
            rejected_by: None,
            deleted_by: None,
        };
        let id = id.to_string();
        let db = db.clone();
        async move {
            let _: Option<poolpay::api::models::DbReceipt> = db
                .upsert(("receipt", id.as_str()))
                .content(content)
                .await
                .expect("seed clock-test receipt");
        }
    };
    // A: bot says "the future", server says "earlier in the day"
    insert(
        "clocktest-a",
        "2099-01-01T00:00:00+00:00",
        "2026-03-10T10:00:00.000Z",
    )
    .await;
    // B: bot says "the past", server says "later in the day"
    insert(
        "clocktest-b",
        "1999-01-01T00:00:00+00:00",
        "2026-03-10T10:01:00.000Z",
    )
    .await;

    let resp = call(
        app,
        get_jwt_with("/api/receipts?limit=200", &admin_bearer()),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: Vec<serde_json::Value> = json_body(resp).await;

    let idx_a = rows
        .iter()
        .position(|r| r["id"] == "clocktest-a")
        .expect("clocktest-a present in queue");
    let idx_b = rows
        .iter()
        .position(|r| r["id"] == "clocktest-b")
        .expect("clocktest-b present in queue");
    assert!(
        idx_a < idx_b,
        "A (ingested 10:00) must precede B (ingested 10:01) regardless of received_at; \
         got idx_a={idx_a} idx_b={idx_b}"
    );
}
