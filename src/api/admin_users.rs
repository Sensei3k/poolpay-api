//! Super-admin-gated user management (BE-8 PR 3).
//!
//! The three endpoints live behind the `SuperAdminUser` extractor so only
//! callers with `role = "super_admin"` can create, modify, or soft-delete
//! admin-tier users. Every mutation that changes `role`, `status`, or
//! deletes a row bumps `user.token_version` so in-flight JWTs for the
//! affected user reject within one access-token TTL. A super-admin
//! cannot mutate or delete their own record — the self-mutation guard
//! forces at least one other super-admin to act, which avoids the
//! accidental lock-out path a count-based "last super_admin" check
//! would have needed.
//!
//! Uniqueness lives on `user_identity(provider, provider_subject)`. A
//! duplicate email returns 409 via a pre-check against the credentials
//! identity row; the post-insert UNIQUE path is also handled so a race
//! between two super-admins creating the same user doesn't leave an
//! orphaned `user` row behind.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use surrealdb::types::RecordId;

use crate::api::models::{
    AppError, DbUser, DbUserIdentity, EntityId, UserContent, UserIdentityContent, now_iso,
    record_id_to_string,
};
use crate::auth::audit::record_auth_event;
use crate::auth::extractors::SuperAdminUser;
use crate::auth::password;
use crate::auth::refresh;
use crate::db::DbConn;

const CREDENTIALS_PROVIDER: &str = "credentials";
const MAX_EMAIL_LEN: usize = 320;
const MAX_PASSWORD_LEN: usize = 1024;

// ── Request / response DTOs ───────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminUserRequest {
    pub email: String,
    pub initial_password: String,
    pub role: String,
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
    pub token_version: i64,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl AdminUserResponse {
    fn from_db(u: &DbUser) -> Self {
        Self {
            user_id: record_id_to_string(u.id.clone()),
            email: u.email.clone(),
            role: u.role.clone(),
            status: u.status.clone(),
            must_reset_password: u.must_reset_password,
            token_version: u.token_version,
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
    SuperAdminUser(_): SuperAdminUser,
    State(db): State<DbConn>,
    Json(req): Json<CreateAdminUserRequest>,
) -> Result<(StatusCode, Json<AdminUserResponse>), AppError> {
    let email = req.email.trim().to_string();
    if email.is_empty() {
        return Err(AppError::BadRequest("email required".into()));
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err(AppError::BadRequest("email too long".into()));
    }
    if req.initial_password.is_empty() {
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

    // Pre-check duplicate against the credentials identity row. Catches
    // the common case cheaply; a concurrent insert is still handled by
    // the post-insert UNIQUE branch below.
    if find_credentials_identity(&db, &email_normalised)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(
            "email already registered".into(),
        ));
    }

    let password_hash = password::hash(&req.initial_password)
        .map_err(|_| AppError::Internal("password hashing failed".into()))?;

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
    let created = created
        .ok_or_else(|| AppError::Internal("user insert returned none".into()))?;
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
            return Err(AppError::Internal(
                "user_identity insert returned none".into(),
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            rollback_user(&db, &user_id).await;
            if is_unique_constraint_error(&msg) {
                return Err(AppError::Conflict("email already registered".into()));
            }
            return Err(AppError::Internal(format!(
                "user_identity insert failed: {msg}"
            )));
        }
    }

    record_auth_event(
        &db,
        Some(user_id.clone()),
        "user_created",
        true,
        Some(&req.role),
        None,
    )
    .await;

    Ok((StatusCode::CREATED, Json(AdminUserResponse::from_db(&created))))
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
    Path(id): Path<EntityId>,
    Json(req): Json<UpdateAdminUserRequest>,
) -> Result<Json<AdminUserResponse>, AppError> {
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
        AppError::Conflict(
            "version mismatch — record was modified by another request".into(),
        )
    })?;

    if role_changed {
        record_auth_event(
            &db,
            Some(id.as_str().to_string()),
            "role_changed",
            true,
            Some(&format!("{} -> {}", existing.role, new_role)),
            None,
        )
        .await;
    }
    if status_changed && new_status == "disabled" {
        // Disable invalidates in-flight sessions immediately — revoke
        // every live refresh token so the disabled user cannot mint
        // fresh access tokens during the access-token TTL window.
        if let Err(e) = refresh::revoke_all_for_user(&db, id.as_str()).await {
            tracing::warn!(error = %e, user_id = %id.as_str(), "revoke_all_for_user on disable failed");
        }
        record_auth_event(
            &db,
            Some(id.as_str().to_string()),
            "user_disabled",
            true,
            None,
            None,
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

    if let Err(e) = refresh::revoke_all_for_user(&db, id.as_str()).await {
        tracing::warn!(error = %e, user_id = %id.as_str(), "revoke_all_for_user on delete failed");
    }
    record_auth_event(
        &db,
        Some(id.as_str().to_string()),
        "user_disabled",
        true,
        Some("soft_deleted"),
        None,
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

fn is_unique_constraint_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("already contains") || lower.contains("unique") || lower.contains("duplicate")
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

