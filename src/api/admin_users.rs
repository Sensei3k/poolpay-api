//! Super-admin-gated user management (BE-8 PR 3).
//!
//! The three endpoints live behind the `SuperAdminUser` extractor so only
//! callers with `role = "super_admin"` can act. `POST` is scoped to
//! provisioning admin-tier users (`admin` | `super_admin`) — member
//! users are minted by the social/credentials sign-in paths, not this
//! surface. `PATCH` and `DELETE` operate on any non-deleted user row
//! regardless of current role, so a super-admin can demote an admin to
//! `member`, disable a member, or soft-delete any user. Every mutation
//! that changes `role`, `status`, or deletes a row bumps
//! `user.token_version` so in-flight JWTs for the affected user reject
//! within one access-token TTL. A super-admin cannot mutate or delete
//! their own record — the self-mutation guard forces at least one
//! other super-admin to act, which avoids the accidental lock-out
//! path a count-based "last super_admin" check would have needed.
//!
//! Uniqueness lives on `user_identity(provider, provider_subject)`. A
//! duplicate email returns 409 via a pre-check against the credentials
//! identity row; the post-insert UNIQUE path is also handled so a race
//! between two super-admins creating the same user doesn't leave an
//! orphaned `user` row behind.

use axum::{
    body::to_bytes,
    extract::{Path, Request, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId;

use crate::api::models::{
    now_iso, record_id_to_string, AppError, DbGroup, DbGroupAdmin, DbUser, DbUserIdentity,
    EntityId, GroupAdminContent, UserContent, UserIdentityContent,
};
use crate::auth::audit::record_auth_event;
use crate::auth::extractors::SuperAdminUser;
use crate::auth::password;
use crate::auth::rate_limit::ClientIp;
use crate::auth::refresh;
use crate::db::{is_unique_constraint_error, DbConn};

const CREDENTIALS_PROVIDER: &str = "credentials";
const MAX_EMAIL_LEN: usize = 320;
const MAX_PASSWORD_LEN: usize = 1024;
// Hard ceiling on inbound JSON bodies for admin-user endpoints. Even though
// these routes sit behind `SuperAdminUser`, a malicious or compromised caller
// shouldn't be able to force multi-MB allocations into `serde_json` before
// field-length checks run. 8 KiB comfortably fits email (320) + password
// (1024) + role/status + JSON framing with room to spare.
const MAX_ADMIN_USER_BODY_BYTES: usize = 8 * 1024;

/// Classify an `axum::body::to_bytes` failure into an `AppError`.
///
/// `to_bytes` collapses overflow and transport-level read failures into the
/// same `axum::Error`, so we can't cheaply distinguish them without
/// reaching for an extra dependency. A neutral "failed to read request
/// body" message stays accurate in both cases — callers that blew past the
/// cap still get a 400, and we stop mislabelling genuine read errors as
/// size violations.
fn map_body_read_error(_err: axum::Error) -> AppError {
    AppError::BadRequest("failed to read request body".into())
}

// ── Request / response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminUserRequest {
    pub email: String,
    pub initial_password: String,
    pub role: String,
}

/// Atomic create-user-with-grants payload. The user portion mirrors
/// `CreateAdminUserRequest`; `groupIds` carries the list of groups the
/// new admin should be granted scope on. The handler wraps the user +
/// identity + grant inserts in a single SurrealDB transaction so a
/// failure midway leaves no partial state behind.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminUserWithGrantsRequest {
    pub email: String,
    pub initial_password: String,
    pub role: String,
    pub group_ids: Vec<EntityId>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAdminUserRequest {
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    pub version: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserResponse {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub status: String,
    pub must_reset_password: bool,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

/// One grant echoed back in the atomic-create response. Same fields as
/// the per-call `GroupAdminGrantResponse` (defined further down) but
/// duplicated here so the FE can confirm what landed without an extra
/// read.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserGrantSummary {
    pub group_id: String,
    pub created_at: String,
    pub created_by: String,
}

/// Response shape for `POST /api/admin/users/with-grants`. Carries the
/// created user plus the grants attached inside the same transaction.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUserWithGrantsResponse {
    pub user: AdminUserResponse,
    pub grants: Vec<AdminUserGrantSummary>,
}

impl AdminUserResponse {
    fn from_db(u: &DbUser) -> Self {
        Self {
            user_id: record_id_to_string(u.id.clone()),
            email: u.email.clone(),
            role: u.role.clone(),
            status: u.status.clone(),
            must_reset_password: u.must_reset_password,
            version: u.version,
            created_at: u.created_at.clone(),
            updated_at: u.updated_at.clone(),
        }
    }
}

// ── POST /api/admin/users ─────────────────────────────────────────────────────

/// Super-admin provisions a new admin-tier user.
///
/// The role is constrained to `admin` or `super_admin` — member users are
/// only created via the social sign-in path (`ensure-user`) or as a
/// side-effect of credentials sign-in, not from this endpoint. A second
/// super-admin is intentionally supportable so operators can rotate out
/// of the role without the self-mutation guard ever locking them out.
///
/// The new user's `must_reset_password` is set to `true` so the operator
/// must rotate the seeded `initialPassword` on first sign-in via
/// `/api/auth/change-password` (BE-8 PR 2). `token_version` starts at 0.
pub async fn create_admin_user(
    SuperAdminUser(caller): SuperAdminUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    http_req: Request,
) -> Result<(StatusCode, Json<AdminUserResponse>), AppError> {
    // Cap the body before deserialising so a super-admin caller (or a
    // compromised token) cannot push a multi-MB payload through the `Json`
    // extractor before per-field length guards run.
    let body = to_bytes(http_req.into_body(), MAX_ADMIN_USER_BODY_BYTES)
        .await
        .map_err(map_body_read_error)?;
    let req: CreateAdminUserRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    let email = req.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::BadRequest("email required".into()));
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err(AppError::BadRequest("email too long".into()));
    }
    if req.initial_password.trim().is_empty() {
        return Err(AppError::BadRequest("initialPassword required".into()));
    }
    if req.initial_password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::BadRequest("initialPassword too long".into()));
    }
    if !matches!(req.role.as_str(), "admin" | "super_admin") {
        return Err(AppError::BadRequest(format!(
            "unsupported role: {}",
            req.role
        )));
    }
    let email_normalised = email.to_lowercase();
    let ip = client_ip.to_string();

    // Pre-check duplicate against the credentials identity row. Catches
    // the common case cheaply; a concurrent insert is still handled by
    // the post-insert UNIQUE branch below.
    if find_credentials_identity(&db, &email_normalised)
        .await?
        .is_some()
    {
        record_auth_event(
            &db,
            None,
            Some(caller.user_id.clone()),
            "user_created",
            false,
            Some("duplicate_email"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Conflict("email already registered".into()));
    }

    let password_hash = match password::hash(&req.initial_password) {
        Ok(h) => h,
        Err(_) => {
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some("hash_failed"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal("password hashing failed".into()));
        }
    };

    let now = now_iso();
    let user_content = UserContent {
        email: email.clone(),
        email_normalised: email_normalised.clone(),
        password_hash: Some(password_hash),
        role: req.role.clone(),
        status: "active".into(),
        token_version: 0,
        must_reset_password: true,
        version: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
    };
    let created: Option<DbUser> = db.create("user").content(user_content).await?;
    let created = match created {
        Some(u) => u,
        None => {
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some("user_insert_returned_none"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal("user insert returned none".into()));
        }
    };
    let user_id = record_id_to_string(created.id.clone());

    let identity = UserIdentityContent {
        user_id: user_id.clone(),
        provider: CREDENTIALS_PROVIDER.into(),
        provider_subject: email_normalised.clone(),
        email_at_link: email.clone(),
        created_at: now,
    };
    let identity_result: Result<Option<DbUserIdentity>, _> =
        db.create("user_identity").content(identity).await;
    match identity_result {
        Ok(Some(_)) => {}
        Ok(None) => {
            rollback_user(&db, &user_id).await;
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some("identity_insert_returned_none"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal(
                "user_identity insert returned none".into(),
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            rollback_user(&db, &user_id).await;
            if is_unique_constraint_error(&msg) {
                record_auth_event(
                    &db,
                    None,
                    Some(caller.user_id.clone()),
                    "user_created",
                    false,
                    Some("duplicate_email_race"),
                    Some(&ip),
                )
                .await;
                return Err(AppError::Conflict("email already registered".into()));
            }
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some("identity_insert_failed"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal(format!(
                "user_identity insert failed: {msg}"
            )));
        }
    }

    record_auth_event(
        &db,
        Some(user_id.clone()),
        Some(caller.user_id.clone()),
        "user_created",
        true,
        Some(&req.role),
        Some(&ip),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(AdminUserResponse::from_db(&created)),
    ))
}

// ── POST /api/admin/users/with-grants ─────────────────────────────────────────

/// Hard cap on the number of groups a single atomic create may attach
/// grants for. Caps the SQL size we construct and bounds the work each
/// request can demand of the transaction.
const MAX_GRANTS_PER_REQUEST: usize = 64;

/// Super-admin provisions a new admin-tier user *and* attaches grants
/// on one or more groups in a single SurrealDB transaction. The endpoint
/// exists because the FE add-admin flow previously orchestrated three
/// HTTP calls (create user → create grant per group → best-effort
/// compensation on failure), which could leave partial state when grant
/// `N` failed after grants `1..N-1` succeeded. The transaction collapses
/// the orchestration to one round-trip and gives the FE an
/// all-or-nothing guarantee from the DB engine.
///
/// Validation runs entirely before the transaction opens so 4xx errors
/// are cheap: empty / duplicated / over-capped `groupIds`, missing
/// fields, oversize payload, unknown role, duplicate email, and missing
/// groups all return without writing anything. Inside the transaction
/// we capture the new user's record id with `record::id($created.id)`
/// and reuse it for both the `user_identity` insert and every
/// `group_admin` insert; the UNIQUE indexes on
/// `user_identity(provider, provider_subject)` and
/// `group_admin(user_id, group_id)` are the safety net for any race
/// that slipped past the pre-checks. SurrealDB cancels the whole
/// transaction on any failure, so a UNIQUE violation on grant `N` rolls
/// back grants `1..N-1`, the identity row, and the user row in one shot.
pub async fn create_admin_user_with_grants(
    SuperAdminUser(caller): SuperAdminUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    http_req: Request,
) -> Result<(StatusCode, Json<AdminUserWithGrantsResponse>), AppError> {
    let body = to_bytes(http_req.into_body(), MAX_ADMIN_USER_BODY_BYTES)
        .await
        .map_err(map_body_read_error)?;
    let req: CreateAdminUserWithGrantsRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    let email = req.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::BadRequest("email required".into()));
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err(AppError::BadRequest("email too long".into()));
    }
    if req.initial_password.trim().is_empty() {
        return Err(AppError::BadRequest("initialPassword required".into()));
    }
    if req.initial_password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::BadRequest("initialPassword too long".into()));
    }
    // Only role "admin" is permitted here. `super_admin` is rejected
    // because super-admins bypass `GroupScopedAdmin` entirely, so any
    // `group_admin` rows attached at create-time would be dead weight —
    // and `grant_group_admin` already enforces the same rule on the
    // per-call path (returns 409 when targeting a super-admin). Keeping
    // both grant entry points aligned avoids a confusing "you can grant
    // here but not there" inconsistency.
    if req.role != "admin" {
        return Err(AppError::BadRequest(format!(
            "with-grants only supports role 'admin'; got '{}'",
            req.role
        )));
    }

    // groupIds: required, non-empty, de-duplicated, bounded.
    if req.group_ids.is_empty() {
        return Err(AppError::BadRequest(
            "groupIds must contain at least one group".into(),
        ));
    }
    if req.group_ids.len() > MAX_GRANTS_PER_REQUEST {
        return Err(AppError::BadRequest(format!(
            "groupIds must contain at most {MAX_GRANTS_PER_REQUEST} entries"
        )));
    }
    // Reject empty / whitespace-only entries up-front. Without this, an
    // empty string falls through to the existence pre-check and returns
    // 404 — a confusing error message for what's really a malformed
    // request.
    for g in &req.group_ids {
        if g.trim().is_empty() {
            return Err(AppError::BadRequest(
                "groupIds entries must not be empty".into(),
            ));
        }
    }
    // Catch caller-side duplicates explicitly: relying on the UNIQUE
    // index to surface them inside the transaction would still abort the
    // whole write, but the resulting 409 would be ambiguous between
    // "you sent the same id twice" and "another caller raced". A 400 on
    // duplicates in the request body keeps the two failure modes distinct.
    let mut seen = std::collections::HashSet::with_capacity(req.group_ids.len());
    for g in &req.group_ids {
        if !seen.insert(g.as_str()) {
            return Err(AppError::BadRequest(format!(
                "groupIds must be unique; duplicate '{g}'"
            )));
        }
    }

    let email_normalised = email.to_lowercase();
    let ip = client_ip.to_string();

    if find_credentials_identity(&db, &email_normalised)
        .await?
        .is_some()
    {
        record_auth_event(
            &db,
            None,
            Some(caller.user_id.clone()),
            "user_created",
            false,
            Some("duplicate_email"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Conflict("email already registered".into()));
    }

    // Verify every requested group exists (and is not soft-deleted)
    // before opening the transaction. Without this, an unknown group id
    // would surface inside the transaction as a successful empty insert
    // (SurrealDB will happily create a `group_admin` referencing a
    // missing group) — the relational integrity check has to be explicit.
    for gid in &req.group_ids {
        let group: Option<DbGroup> = db.select(("group", gid.as_str())).await?;
        if group.filter(|g| g.deleted_at.is_none()).is_none() {
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some("unknown_group"),
                Some(&ip),
            )
            .await;
            return Err(AppError::NotFound(format!("group {gid} does not exist")));
        }
    }

    let password_hash = match password::hash(&req.initial_password) {
        Ok(h) => h,
        Err(_) => {
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some("hash_failed"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal("password hashing failed".into()));
        }
    };

    let now = now_iso();
    let user_content = UserContent {
        email: email.clone(),
        email_normalised: email_normalised.clone(),
        password_hash: Some(password_hash),
        role: req.role.clone(),
        status: "active".into(),
        token_version: 0,
        must_reset_password: true,
        version: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
    };

    // Build the multi-statement transaction body. The grant inserts are
    // appended one per group so each can bind its `group_id` to a named
    // parameter; building one big `FOR` loop in SurrealQL would force us
    // to bind the whole `group_ids` array as a single value, which is
    // doable but harder to audit at the query-log level.
    let mut sql = String::from(
        "BEGIN TRANSACTION;\n\
         LET $created = (CREATE ONLY user CONTENT $user_content RETURN AFTER);\n\
         LET $uid = record::id($created.id);\n\
         CREATE user_identity SET \
             user_id = $uid, \
             provider = $provider, \
             provider_subject = $provider_subject, \
             email_at_link = $email_at_link, \
             created_at = $now;\n",
    );
    for i in 0..req.group_ids.len() {
        sql.push_str(&format!(
            "CREATE group_admin SET \
                 user_id = $uid, group_id = $g{i}, \
                 created_at = $now, created_by = $actor;\n"
        ));
    }
    sql.push_str(
        "RETURN $created;\n\
         COMMIT TRANSACTION;\n",
    );

    let mut q = db
        .query(sql)
        .bind(("user_content", user_content))
        .bind(("provider", CREDENTIALS_PROVIDER.to_string()))
        .bind(("provider_subject", email_normalised.clone()))
        .bind(("email_at_link", email.clone()))
        .bind(("now", now.clone()))
        .bind(("actor", caller.user_id.clone()));
    for (i, gid) in req.group_ids.iter().enumerate() {
        q = q.bind((format!("g{i}"), gid.as_str().to_string()));
    }

    // Helper to classify a transaction error into an audit reason +
    // user-facing AppError. Bound here so the two error sites below
    // (`q.await` failure and `.check()` failure) stay in lockstep.
    let classify_txn_error = |msg: &str| -> (&'static str, AppError) {
        if is_unique_constraint_error(msg) {
            (
                "duplicate_email_race",
                AppError::Conflict("email already registered".into()),
            )
        } else {
            (
                "transaction_failed",
                AppError::Internal(format!("with-grants transaction failed: {msg}")),
            )
        }
    };

    let resp = match q.await {
        Ok(r) => r,
        Err(e) => {
            let (reason, app_err) = classify_txn_error(&e.to_string());
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some(reason),
                Some(&ip),
            )
            .await;
            return Err(app_err);
        }
    };
    let mut resp = match resp.check() {
        Ok(r) => r,
        Err(e) => {
            let (reason, app_err) = classify_txn_error(&e.to_string());
            record_auth_event(
                &db,
                None,
                Some(caller.user_id.clone()),
                "user_created",
                false,
                Some(reason),
                Some(&ip),
            )
            .await;
            return Err(app_err);
        }
    };

    // The trailing `RETURN $created;` lands in the last statement slot.
    // Statement indexes are: 0 = BEGIN, 1 = LET created, 2 = LET uid,
    // 3 = CREATE user_identity, 4..4+N = group_admin inserts,
    // 4+N = RETURN, last = COMMIT. `.take()` walks left-to-right by
    // surfacing the next un-consumed result, so we pull from the end
    // by index rather than guess the slot.
    let return_slot = resp.num_statements().saturating_sub(2);
    let created_opt: Option<DbUser> = resp.take(return_slot).map_err(|e| {
        AppError::Internal(format!(
            "with-grants transaction returned unexpected shape: {e}"
        ))
    })?;
    let created = created_opt
        .ok_or_else(|| AppError::Internal("with-grants transaction returned no user row".into()))?;
    let user_id = record_id_to_string(created.id.clone());

    record_auth_event(
        &db,
        Some(user_id.clone()),
        Some(caller.user_id.clone()),
        "user_created",
        true,
        Some(&req.role),
        Some(&ip),
    )
    .await;
    for gid in &req.group_ids {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            Some(caller.user_id.clone()),
            "group_admin_granted",
            true,
            Some(&format!("group:{gid}")),
            Some(&ip),
        )
        .await;
    }

    let grants = req
        .group_ids
        .iter()
        .map(|gid| AdminUserGrantSummary {
            group_id: gid.as_str().to_string(),
            created_at: now.clone(),
            created_by: caller.user_id.clone(),
        })
        .collect();

    Ok((
        StatusCode::CREATED,
        Json(AdminUserWithGrantsResponse {
            user: AdminUserResponse::from_db(&created),
            grants,
        }),
    ))
}

// ── PATCH /api/admin/users/:id ────────────────────────────────────────────────

/// Super-admin flips `role` and/or `status` on a user row. Optimistic
/// concurrency via the caller-supplied `version`. Any mutation that
/// changes `role` or `status` bumps `token_version` — in-flight access
/// tokens for the target user reject on the next verify cycle.
///
/// A super-admin cannot patch themselves (decision 3 in the BE-8 plan).
/// Demoting, disabling, or deleting your own row requires another
/// super-admin; the guard is blanket rather than field-specific so we
/// don't accidentally allow a subtle path (e.g. status → disabled on
/// self) that would silently lock the caller out.
pub async fn update_admin_user(
    SuperAdminUser(caller): SuperAdminUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    Path(id): Path<EntityId>,
    http_req: Request,
) -> Result<Json<AdminUserResponse>, AppError> {
    // Same rationale as `create_admin_user`: bound the pre-parse body so
    // a caller cannot force `serde_json` to buffer a large payload behind
    // the super-admin gate.
    let body = to_bytes(http_req.into_body(), MAX_ADMIN_USER_BODY_BYTES)
        .await
        .map_err(map_body_read_error)?;
    let req: UpdateAdminUserRequest = serde_json::from_slice(&body)
        .map_err(|_| AppError::BadRequest("invalid JSON body".into()))?;

    if caller.user_id == id.as_str() {
        return Err(AppError::Forbidden(
            "super_admins cannot modify their own record".into(),
        ));
    }

    if let Some(r) = &req.role {
        if !matches!(r.as_str(), "super_admin" | "admin" | "member") {
            return Err(AppError::BadRequest(format!("unsupported role: {r}")));
        }
    }
    if let Some(s) = &req.status {
        if !matches!(s.as_str(), "active" | "disabled") {
            return Err(AppError::BadRequest(format!("unsupported status: {s}")));
        }
    }

    let existing: Option<DbUser> = db.select(("user", id.as_str())).await?;
    let existing = existing
        .filter(|u| u.deleted_at.is_none())
        .ok_or_else(|| AppError::NotFound(format!("user {id} does not exist")))?;

    if existing.version != req.version {
        return Err(AppError::Conflict(
            "version mismatch — record was modified by another request".into(),
        ));
    }

    let new_role = req.role.clone().unwrap_or_else(|| existing.role.clone());
    let new_status = req
        .status
        .clone()
        .unwrap_or_else(|| existing.status.clone());
    let role_changed = new_role != existing.role;
    let status_changed = new_status != existing.status;

    // A patch that doesn't actually change anything is not an error — it
    // still bumps `version` (so a stale client sees a mismatch next time)
    // but leaves `token_version` alone (no auth-state change).
    let bump_token = role_changed || status_changed;

    let now = now_iso();
    // Targeted atomic UPDATE guarded by the caller's expected `version`.
    // Only touches the fields this endpoint owns (role, status, updated_at,
    // version, token_version) so a concurrent subsystem (e.g. refresh-reuse
    // detection bumping `token_version`, or `/change-password`) can't be
    // clobbered by a snapshot-derived write. `token_version` increments
    // relative to the current DB value rather than the stale snapshot.
    let mut response = db
        .query(
            "UPDATE $id SET \
                 role = $role, \
                 status = $status, \
                 updated_at = $now, \
                 version = version + 1, \
                 token_version = IF $bump_token THEN token_version + 1 ELSE token_version END \
             WHERE version = $expected_version AND deleted_at IS NONE \
             RETURN AFTER",
        )
        .bind(("id", RecordId::new("user", id.as_str().to_string())))
        .bind(("role", new_role.clone()))
        .bind(("status", new_status.clone()))
        .bind(("now", now))
        .bind(("expected_version", existing.version))
        .bind(("bump_token", bump_token))
        .await?
        .check()?;
    let rows: Vec<DbUser> = response.take(0)?;
    let updated = rows.into_iter().next().ok_or_else(|| {
        // Row existed at SELECT time but the guarded UPDATE matched nothing:
        // a concurrent writer advanced `version` or soft-deleted the row
        // between read and write. Surface as a version mismatch so the
        // caller refetches and retries.
        AppError::Conflict("version mismatch — record was modified by another request".into())
    })?;

    let ip = client_ip.to_string();
    if role_changed {
        record_auth_event(
            &db,
            Some(id.as_str().to_string()),
            Some(caller.user_id.clone()),
            "role_changed",
            true,
            Some(&format!("{} -> {}", existing.role, new_role)),
            Some(&ip),
        )
        .await;
    }
    if status_changed && new_status == "disabled" {
        // Disable invalidates in-flight sessions immediately — revoke
        // every live refresh token so the disabled user cannot mint
        // fresh access tokens during the access-token TTL window. A
        // revoke failure is a genuine partial-failure: the status is
        // already committed but live sessions survive, so emit a
        // `success = false` audit event and surface 500 so operators
        // can retry rather than leaving an inconsistent outcome
        // hidden behind a 200.
        if let Err(e) = refresh::revoke_all_for_user(&db, id.as_str()).await {
            record_auth_event(
                &db,
                Some(id.as_str().to_string()),
                Some(caller.user_id.clone()),
                "user_disabled",
                false,
                Some("refresh_revocation_failed"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal(format!("refresh revoke failed: {e}")));
        }
        record_auth_event(
            &db,
            Some(id.as_str().to_string()),
            Some(caller.user_id.clone()),
            "user_disabled",
            true,
            None,
            Some(&ip),
        )
        .await;
    } else if status_changed && new_status == "active" {
        // Re-enable is the privileged reversal of a prior disable. No
        // refresh-token revoke needed (disable already dropped them and
        // the user must re-authenticate), but the event is emitted so
        // the audit trail shows symmetric disable/enable decisions.
        record_auth_event(
            &db,
            Some(id.as_str().to_string()),
            Some(caller.user_id.clone()),
            "user_enabled",
            true,
            None,
            Some(&ip),
        )
        .await;
    }

    Ok(Json(AdminUserResponse::from_db(&updated)))
}

// ── DELETE /api/admin/users/:id ───────────────────────────────────────────────

/// Super-admin soft-deletes a user. Same self-mutation guard as PATCH.
/// Sets `deleted_at`, bumps `token_version`, and revokes every refresh
/// token for the target user. The user row is preserved for audit —
/// `auth_event` rows and `group_admin` grants keep their `user_id`
/// dangling-reference intact.
pub async fn delete_admin_user(
    SuperAdminUser(caller): SuperAdminUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    if caller.user_id == id.as_str() {
        return Err(AppError::Forbidden(
            "super_admins cannot delete their own record".into(),
        ));
    }

    let now = now_iso();
    // Targeted atomic soft-delete — only touches the fields this endpoint
    // owns. Increments `token_version` relative to the DB value so a
    // concurrent bump (e.g. refresh-reuse detection) can't be clobbered
    // into a lower value and re-validate already-rejected JWTs. The
    // `WHERE deleted_at IS NONE` clause also makes this a 404 (not an
    // accidental re-delete) if the row vanished or was already deleted.
    let mut resp = db
        .query(
            "UPDATE $id SET \
                 deleted_at = $now, \
                 updated_at = $now, \
                 version = version + 1, \
                 token_version = token_version + 1 \
             WHERE deleted_at IS NONE \
             RETURN AFTER",
        )
        .bind(("id", RecordId::new("user", id.as_str().to_string())))
        .bind(("now", now))
        .await?
        .check()?;
    let updated: Vec<DbUser> = resp.take(0)?;
    if updated.is_empty() {
        // Either the row doesn't exist or it's already soft-deleted. Both
        // return 404 — idempotent from the caller's perspective.
        return Err(AppError::NotFound(format!("user {id} does not exist")));
    }

    let ip = client_ip.to_string();
    // Soft-delete is already committed above. If the refresh-revoke step
    // fails, live sessions for the deleted user survive until their
    // access-token TTL expires — which contradicts the endpoint
    // contract. Record a `success = false` audit event (tagged so ops
    // can distinguish it from a normal delete) and surface 500 so the
    // caller knows the revocation step did not complete, rather than
    // returning 204 on a partial outcome.
    if let Err(e) = refresh::revoke_all_for_user(&db, id.as_str()).await {
        record_auth_event(
            &db,
            Some(id.as_str().to_string()),
            Some(caller.user_id.clone()),
            "user_disabled",
            false,
            Some("soft_deleted_token_revocation_failed"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Internal(format!("refresh revoke failed: {e}")));
    }
    record_auth_event(
        &db,
        Some(id.as_str().to_string()),
        Some(caller.user_id.clone()),
        "user_disabled",
        true,
        Some("soft_deleted"),
        Some(&ip),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async fn find_credentials_identity(
    db: &DbConn,
    email_normalised: &str,
) -> Result<Option<DbUserIdentity>, AppError> {
    let mut resp = db
        .query(
            "SELECT * FROM user_identity \
             WHERE provider = $p AND provider_subject = $s LIMIT 1",
        )
        .bind(("p", CREDENTIALS_PROVIDER.to_string()))
        .bind(("s", email_normalised.to_string()))
        .await?
        .check()?;
    let rows: Vec<DbUserIdentity> = resp.take(0)?;
    Ok(rows.into_iter().next())
}

/// Best-effort cleanup for a user row created immediately before an
/// identity insert failed. The identity insert is the only
/// failure-prone step after the user write, so this tidy-up keeps the
/// error path from leaving an orphan. A cleanup failure is logged but
/// not surfaced — the caller has already returned the user-facing
/// error and the orphan will be GC'd by out-of-band tooling.
async fn rollback_user(db: &DbConn, user_id: &str) {
    let cleanup: Result<Option<DbUser>, _> = db.delete(("user", user_id)).await;
    if let Err(e) = cleanup {
        tracing::warn!(
            error = %e,
            user_id,
            "rollback_user failed after identity insert error — orphan user row"
        );
    }
}

// ── POST /api/admin/users/:id/groups/:group_id (BE-8 PR 4) ────────────────────

/// Response echoed on successful grant. Small on purpose — the grant
/// is fully identified by the path, and the audit row carries the
/// canonical record. The response exists mainly so the client can
/// confirm `createdBy` and `createdAt` without a follow-up read.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupAdminGrantResponse {
    pub user_id: String,
    pub group_id: String,
    pub created_at: String,
    pub created_by: String,
}

/// Super-admin grants one `admin`-role user access to one group.
///
/// Granting to a `super_admin` returns 409 — super-admins bypass the
/// group-scope extractor entirely (see `src/auth/extractors.rs`), so
/// the row would be dead weight. Granting to a `member` also returns
/// 409: group-admin rows are the admin-tier scope primitive, not a
/// membership indicator, and a member row here would silently widen
/// RBAC if the user were later promoted. Granting on a disabled or
/// soft-deleted user returns 409 / 404 for the same reason — the
/// target must be a live admin to receive scope.
///
/// Duplicate grants collide on the `group_admin(user_id, group_id)`
/// unique index and surface as 409 so a retry is safely idempotent.
/// The `group_admin_granted` audit row records the caller as
/// `actor_id` and the target as `user_id` so incident review can
/// answer "who granted scope on this group to this admin?" later.
pub async fn grant_group_admin(
    SuperAdminUser(caller): SuperAdminUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    Path((user_id, group_id)): Path<(EntityId, EntityId)>,
) -> Result<(StatusCode, Json<GroupAdminGrantResponse>), AppError> {
    // `ip` is bound up-front so each failure branch can emit a
    // `success: false` audit row — incident review should see
    // rejected grant attempts with the same attribution fidelity
    // as successful ones (mirrors the `create_admin_user` flow
    // added in PR 3.5).
    let ip = client_ip.to_string();

    let user: Option<DbUser> = db.select(("user", user_id.as_str())).await?;
    let user = match user.filter(|u| u.deleted_at.is_none()) {
        Some(u) => u,
        None => {
            record_auth_event(
                &db,
                Some(user_id.clone()),
                Some(caller.user_id.clone()),
                "group_admin_granted",
                false,
                Some("unknown_user"),
                Some(&ip),
            )
            .await;
            return Err(AppError::NotFound(format!("user {user_id} does not exist")));
        }
    };

    if user.status != "active" {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            Some(caller.user_id.clone()),
            "group_admin_granted",
            false,
            Some("target_not_active"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Conflict(format!(
            "user {user_id} is not active (status: {})",
            user.status
        )));
    }
    if user.role != "admin" {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            Some(caller.user_id.clone()),
            "group_admin_granted",
            false,
            Some("target_not_admin"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Conflict(format!(
            "group-admin grants only apply to admin-role users (target role: {})",
            user.role
        )));
    }

    let group: Option<DbGroup> = db.select(("group", group_id.as_str())).await?;
    if group.filter(|g| g.deleted_at.is_none()).is_none() {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            Some(caller.user_id.clone()),
            "group_admin_granted",
            false,
            Some("unknown_group"),
            Some(&ip),
        )
        .await;
        return Err(AppError::NotFound(format!(
            "group {group_id} does not exist"
        )));
    }

    let now = now_iso();
    let content = GroupAdminContent {
        user_id: user_id.clone(),
        group_id: group_id.clone(),
        created_at: now.clone(),
        created_by: caller.user_id.clone(),
    };
    let insert: Result<Option<DbGroupAdmin>, _> = db.create("group_admin").content(content).await;
    match insert {
        Ok(Some(_)) => {}
        Ok(None) => {
            record_auth_event(
                &db,
                Some(user_id.clone()),
                Some(caller.user_id.clone()),
                "group_admin_granted",
                false,
                Some("insert_returned_none"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal(
                "group_admin insert returned no row".into(),
            ));
        }
        Err(e) => {
            if is_unique_constraint_error(&e.to_string()) {
                record_auth_event(
                    &db,
                    Some(user_id.clone()),
                    Some(caller.user_id.clone()),
                    "group_admin_granted",
                    false,
                    Some("duplicate_grant"),
                    Some(&ip),
                )
                .await;
                return Err(AppError::Conflict(format!(
                    "user {user_id} already has group-admin on group {group_id}"
                )));
            }
            record_auth_event(
                &db,
                Some(user_id.clone()),
                Some(caller.user_id.clone()),
                "group_admin_granted",
                false,
                Some("insert_failed"),
                Some(&ip),
            )
            .await;
            return Err(e.into());
        }
    }

    record_auth_event(
        &db,
        Some(user_id.clone()),
        Some(caller.user_id.clone()),
        "group_admin_granted",
        true,
        Some(&format!("group:{group_id}")),
        Some(&ip),
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(GroupAdminGrantResponse {
            user_id,
            group_id,
            created_at: now,
            created_by: caller.user_id,
        }),
    ))
}

// ── DELETE /api/admin/users/:id/groups/:group_id (BE-8 PR 4) ──────────────────

/// Super-admin revokes a group-admin grant previously issued on this
/// target user. The mutation is two-part: remove the `group_admin`
/// row, then bump the target's `token_version`.
///
/// The token-version bump is load-bearing. Scope shrank — any
/// in-flight access token the target still holds would otherwise let
/// them act on the newly-revoked group for up to one access-token
/// TTL. Bumping forces re-verification against the fresh DB state
/// on the next call. This endpoint does **not** revoke refresh
/// tokens; the user still has a valid session, they just can't
/// operate on this group anymore.
///
/// Returns 404 if no matching grant exists — the deletion is
/// idempotent from the caller's perspective but the handler doesn't
/// silently swallow unknown rows, because a missing row in the audit
/// trail later would be the signature of an out-of-band manual
/// revoke that ops should see, not something we paper over here.
pub async fn revoke_group_admin(
    SuperAdminUser(caller): SuperAdminUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    Path((user_id, group_id)): Path<(EntityId, EntityId)>,
) -> Result<StatusCode, AppError> {
    // `ip` is bound up-front so the 404 branch can emit a
    // `success: false` audit row — matches the symmetry PR 3.5
    // established for admin-user mutations.
    let ip = client_ip.to_string();

    // Delete the join row via a guarded query so we can distinguish
    // "row did not exist" (→ 404) from a permission/connectivity
    // failure. `DELETE ... RETURN BEFORE` echoes the matched rows so
    // `rows.is_empty()` is the unambiguous 404 signal.
    let mut resp = db
        .query(
            "DELETE FROM group_admin \
             WHERE user_id = $uid AND group_id = $gid \
             RETURN BEFORE",
        )
        .bind(("uid", user_id.clone()))
        .bind(("gid", group_id.clone()))
        .await?
        .check()?;
    let deleted: Vec<DbGroupAdmin> = resp.take(0)?;
    if deleted.is_empty() {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            Some(caller.user_id.clone()),
            "group_admin_revoked",
            false,
            Some("unknown_grant"),
            Some(&ip),
        )
        .await;
        return Err(AppError::NotFound(format!(
            "user {user_id} has no group-admin grant on group {group_id}"
        )));
    }

    // Bump target's `token_version` so in-flight access tokens
    // reject on the next verify cycle. Relative to the current DB
    // value (not a stale snapshot) so a concurrent refresh-reuse
    // detection or PATCH role change cannot be clobbered into a
    // lower counter.
    //
    // Revoke is a two-step mutation — the `group_admin` row is
    // already gone when this runs. A bump failure here means scope
    // was dropped but in-flight JWTs still hold it until the
    // access-token TTL expires: audit the partial outcome and
    // surface 500 so operators can retry, rather than hide the
    // inconsistency behind a 204. Mirrors the partial-failure
    // handling in `update_admin_user` / `delete_admin_user` when a
    // refresh-revoke step fails after a status commit.
    //
    // The bump is unconditional — no `deleted_at IS NONE` guard.
    // If the user row is soft-deleted, the DELETE path has already
    // bumped `token_version`, so a further bump here is idempotent
    // from a security standpoint. If the row was hard-deleted
    // out-of-band, the UPDATE matches zero rows and the query
    // still returns Ok — acceptable, since there is no live
    // session to invalidate anyway.
    let bump = db
        .query(
            "UPDATE $id SET \
                 token_version = token_version + 1, \
                 updated_at = $now",
        )
        .bind(("id", RecordId::new("user", user_id.clone())))
        .bind(("now", now_iso()))
        .await
        .and_then(|r| r.check().map(|_| ()));
    if let Err(e) = bump {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            Some(caller.user_id.clone()),
            "group_admin_revoked",
            false,
            Some("token_version_bump_failed"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Internal(format!(
            "token_version bump failed after group_admin revoke: {e}"
        )));
    }

    record_auth_event(
        &db,
        Some(user_id.clone()),
        Some(caller.user_id.clone()),
        "group_admin_revoked",
        true,
        Some(&format!("group:{group_id}")),
        Some(&ip),
    )
    .await;

    Ok(StatusCode::NO_CONTENT)
}
