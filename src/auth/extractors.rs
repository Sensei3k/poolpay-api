//! Axum extractors that turn a bearer token into an attributable user.
//!
//! Three guards land in BE-3 but sit behind `#[allow(dead_code)]` until
//! BE-4 mints real tokens and BE-5 flips handlers to consume them:
//!
//! * `AuthenticatedUser` — any active user with a valid, fresh access
//!   token (sig + exp + token_version + status checks).
//! * `SuperAdminUser` — `AuthenticatedUser` narrowed to `role == "super_admin"`.
//! * `require_group_scope(&user, group_id, db)` — callable guard that
//!   super-admins bypass and scoped admins pass iff a matching
//!   `group_admin(user_id, group_id)` row exists. Kept as a helper (not a
//!   typed extractor) because the `group_id` often comes from a parent
//!   record, so the handler resolves it first and then calls the guard.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use surrealdb::types::RecordId;
use tracing::warn;

use crate::api::models::{AppError, DbUser};
use crate::auth::jwt::{SharedVerifier, TokenVerifier};
use crate::db::DbConn;

/// A verified, still-active user. The `token_version` is carried so tests
/// and audit rows can record exactly which version the bearer was on.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: String,
    pub role: String,
    pub token_version: i64,
}

/// Narrowing extractor for `super_admin`-only endpoints. Unused until BE-5
/// flips `/api/admin/groups/*` and `/api/admin/whatsapp-links/*` to it.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SuperAdminUser(pub AuthenticatedUser);

impl<S> FromRequestParts<S> for AuthenticatedUser
where
    S: Send + Sync,
    DbConn: FromRef<S>,
    SharedVerifier: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let token = extract_bearer(parts)?;
        let verifier = SharedVerifier::from_ref(state);
        let claims = verifier.verify_access(&token).map_err(|e| {
            warn!(error = %e, "JWT verification failed");
            AppError::Unauthorized
        })?;

        let db = DbConn::from_ref(state);
        let user = load_user(&db, &claims.sub).await.map_err(|e| {
            warn!(error = %e, user = %claims.sub, "user lookup during auth failed");
            AppError::Internal(e.to_string())
        })?;

        let user = user.ok_or_else(|| {
            warn!(user = %claims.sub, "authenticated token for missing user");
            AppError::Unauthorized
        })?;

        // token_version mismatch = the user's JWTs were invalidated server-side
        // (password change, role change, admin-initiated kill). Fail closed.
        if user.token_version != claims.token_version {
            return Err(AppError::Unauthorized);
        }
        if user.status != "active" {
            return Err(AppError::Unauthorized);
        }
        if user.deleted_at.is_some() {
            return Err(AppError::Unauthorized);
        }

        Ok(Self {
            user_id: claims.sub,
            role: user.role,
            token_version: user.token_version,
        })
    }
}

impl<S> FromRequestParts<S> for SuperAdminUser
where
    S: Send + Sync,
    DbConn: FromRef<S>,
    SharedVerifier: FromRef<S>,
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

/// Handler-called guard. `super_admin` bypasses; `admin` passes iff a
/// `group_admin(user_id, group_id)` row exists; anything else is forbidden.
///
/// Lives as a helper rather than a typed `FromRequestParts` extractor because
/// the `group_id` is often resolved from a parent record (payment → cycle →
/// group) inside the handler before the guard can be called.
#[allow(dead_code)]
pub async fn require_group_scope(
    user: &AuthenticatedUser,
    group_id: &str,
    db: &DbConn,
) -> Result<(), AppError> {
    if user.role == "super_admin" {
        return Ok(());
    }
    if user.role != "admin" {
        return Err(AppError::Forbidden("admin role required".into()));
    }
    if has_group_admin(db, &user.user_id, group_id).await? {
        Ok(())
    } else {
        Err(AppError::Forbidden("no access to this group".into()))
    }
}

fn extract_bearer(parts: &Parts) -> Result<String, AppError> {
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

/// Concrete router state that carries both the DB handle and the token
/// verifier. Extractors read it via `FromRef`; handlers that only need the
/// DB continue to use `State<DbConn>` unchanged.
#[derive(Clone)]
pub struct AuthState {
    pub db: DbConn,
    pub verifier: SharedVerifier,
}

impl FromRef<AuthState> for DbConn {
    fn from_ref(s: &AuthState) -> Self { s.db.clone() }
}

impl FromRef<AuthState> for SharedVerifier {
    fn from_ref(s: &AuthState) -> Self { s.verifier.clone() }
}

// Silence the rust/axum unused-state warning: until BE-5 flips handlers to
// the extractors, nothing reads `AuthState` directly.
#[allow(dead_code)]
pub(crate) fn _touch(_: &dyn TokenVerifier) {}
