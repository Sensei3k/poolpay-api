//! Axum extractors that turn a bearer token into an attributable user.
//!
//! * `AuthenticatedUser` — any active user with a valid, fresh access token
//!   (signature + exp + token_version + status checks).
//! * `SuperAdminUser` — `AuthenticatedUser` narrowed to `role == "super_admin"`.
//! * `GroupScopedAdmin` — handler-constructed guard wrapping an
//!   `AuthenticatedUser` that has been checked against a specific
//!   `group_id`: super-admins bypass, scoped admins pass iff a matching
//!   `group_admin(user_id, group_id)` row exists. Built via
//!   `GroupScopedAdmin::ensure()` rather than `FromRequestParts` because
//!   the `group_id` is often resolved from a parent record
//!   (payment → cycle → group) inside the handler.

use axum::extract::{Extension, FromRef, FromRequestParts, State};
use axum::http::request::Parts;
use surrealdb::types::RecordId;
use tracing::{debug, warn};

use crate::api::models::{AppError, DbUser};
use crate::auth::jwt::SharedVerifier;
use crate::db::DbConn;

#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub role: String,
    pub token_version: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SuperAdminUser(pub AuthenticatedUser);

/// Wraps an `AuthenticatedUser` whose access to a specific `group_id` has
/// been verified. Built via `ensure()` so handlers can resolve `group_id`
/// from the path or a parent record before running the check.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct GroupScopedAdmin(pub AuthenticatedUser);

impl GroupScopedAdmin {
    pub async fn ensure(
        user: AuthenticatedUser,
        group_id: &str,
        db: &DbConn,
    ) -> Result<Self, AppError> {
        require_group_scope(&user, group_id, db).await?;
        Ok(Self(user))
    }

    /// Resolve the scope when the parent record may be missing. Passing
    /// `None` for `group_id` means the target record was not found — in
    /// that case super-admins receive `missing_err` (they already know
    /// every id in the system) while non-super-admins receive the same
    /// opaque 403 they would get for a cross-tenant record, so that
    /// 404 vs 403 can't be used to probe existence across groups.
    pub async fn ensure_or_deny(
        user: AuthenticatedUser,
        group_id: Option<&str>,
        db: &DbConn,
        missing_err: AppError,
    ) -> Result<Self, AppError> {
        match group_id {
            Some(gid) => Self::ensure(user, gid, db).await,
            None if user.role == "super_admin" => Err(missing_err),
            None => Err(AppError::Forbidden("forbidden".into())),
        }
    }
}

impl AuthenticatedUser {
    /// Build an `AuthenticatedUser` from an already-parsed bearer token.
    ///
    /// Factored out of `from_request_parts` so extractors that need to make
    /// a legacy-vs-JWT decision (see `auth::compat::AdminOrLegacyToken`) can
    /// parse the `Authorization` header once and reuse the token string
    /// rather than re-parsing and re-allocating it.
    pub(crate) async fn from_token<S>(
        token: &str,
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, AppError>
    where
        S: Send + Sync,
        DbConn: FromRef<S>,
    {
        // The verifier is injected via Extension so it can be shared across
        // handlers without forcing every existing route onto a new state
        // type. Missing extension = misconfigured router = refuse.
        let Extension(verifier): Extension<SharedVerifier> =
            Extension::from_request_parts(parts, state)
                .await
                .map_err(|_| AppError::Unauthorized)?;

        let claims = verifier.verify_access(token).map_err(|e| {
            // Attacker-controlled input; keep at debug to avoid log-amplification.
            // Reserve `warn!` for unexpected internal failures (e.g., DB errors).
            debug!(error = %e, "JWT verification failed");
            AppError::Unauthorized
        })?;

        let State(db): State<DbConn> = State::from_request_parts(parts, state)
            .await
            .map_err(|_| AppError::Internal("db state missing".into()))?;

        let user = load_user(&db, &claims.sub).await.map_err(|e| {
            warn!(error = %e, user = %claims.sub, "user lookup during auth failed");
            AppError::Internal(e.to_string())
        })?;

        let user = user.ok_or_else(|| {
            warn!(user = %claims.sub, "authenticated token for missing user");
            AppError::Unauthorized
        })?;

        if user.token_version != claims.token_version
            || user.status != "active"
            || user.deleted_at.is_some()
        {
            return Err(AppError::Unauthorized);
        }

        Ok(Self { user_id: claims.sub, role: user.role, token_version: user.token_version })
    }
}

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    DbConn: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(parts)?;
        Self::from_token(&token, parts, state).await
    }
}

impl<S> FromRequestParts<S> for SuperAdminUser
where
    S: Send + Sync,
    DbConn: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let inner = AuthenticatedUser::from_request_parts(parts, state).await?;
        if inner.role != "super_admin" {
            return Err(AppError::Forbidden("super_admin role required".into()));
        }
        Ok(Self(inner))
    }
}

pub async fn require_group_scope(
    user: &AuthenticatedUser,
    group_id: &str,
    db: &DbConn,
) -> Result<(), AppError> {
    if user.role == "super_admin" {
        return Ok(());
    }
    // Single opaque 403 for every non-super-admin failure path. Leaking
    // "admin role required" vs "no access to this group" tells the caller
    // whether the JWT role is at least admin — cheap information we don't
    // need to give away.
    let allowed =
        user.role == "admin" && has_group_admin(db, &user.user_id, group_id).await?;
    if allowed {
        Ok(())
    } else {
        Err(AppError::Forbidden("forbidden".into()))
    }
}

pub(crate) fn extract_bearer(parts: &Parts) -> Result<String, AppError> {
    let header = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let token = header
        .strip_prefix("Bearer ")
        .or_else(|| header.strip_prefix("bearer "))
        .ok_or(AppError::Unauthorized)?
        .trim();
    if token.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok(token.to_string())
}

async fn load_user(db: &DbConn, user_id: &str) -> Result<Option<DbUser>, surrealdb::Error> {
    let mut resp = db
        .query("SELECT * FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await?
        .check()?;
    let rows: Vec<DbUser> = resp.take(0)?;
    Ok(rows.into_iter().next())
}

async fn has_group_admin(db: &DbConn, user_id: &str, group_id: &str) -> Result<bool, AppError> {
    let mut resp = db
        .query(
            "SELECT count() FROM group_admin \
             WHERE user_id = $uid AND group_id = $gid GROUP ALL",
        )
        .bind(("uid", user_id.to_string()))
        .bind(("gid", group_id.to_string()))
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
        .check()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let counts: Vec<i64> = resp
        .take("count")
        .map_err(|e| AppError::Internal(e.to_string()))?;
    Ok(counts.first().copied().unwrap_or(0) > 0)
}
