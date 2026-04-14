//! Compatibility shim — BE-4.
//!
//! Bridges the legacy static `ADMIN_TOKEN` bearer with the new RS256 admin
//! JWTs while BE-5 migrates handlers one resource at a time. Once every
//! handler has been flipped to `SuperAdminUser` or `GroupScopedAdmin`
//! (BE-6), this module — and `ADMIN_TOKEN` itself — is deleted.
//!
//! Acceptance rules (in order):
//!   1. `Authorization: Bearer <token>` is parsed.
//!   2. If `ADMIN_TOKEN` is set and matches the bearer in constant time,
//!      the request is accepted as `Legacy` without touching the JWT
//!      verifier or the database. Cheap, side-effect-free fast path so
//!      operator scripts keep working unchanged.
//!   3. Otherwise the bearer is verified as an access token. The carried
//!      user must be `super_admin` or `admin`; `member` tokens are 403
//!      (the legacy `AdminToken` had no equivalent of `member`, so any
//!      member JWT reaching an admin route is a guard mismatch we want
//!      to surface, not silently fall through to 401).
//!   4. Anything else → 401.

#![allow(dead_code)]

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use subtle::ConstantTimeEq;

use crate::api::models::AppError;
use crate::auth::extractors::{AuthenticatedUser, extract_bearer};
use crate::db::DbConn;

/// Result of an `AdminOrLegacyToken` extraction.
///
/// Held as an enum (rather than discarded as a unit type) so handlers
/// migrated mid-transition can attribute mutations to the JWT user when
/// one is present, and fall back to "legacy operator" auditing otherwise.
#[derive(Debug, Clone)]
pub enum AdminOrLegacyToken {
    /// The request authenticated with the legacy `ADMIN_TOKEN` bearer.
    Legacy,
    /// The request authenticated with an admin-role JWT.
    Jwt(AuthenticatedUser),
}

impl AdminOrLegacyToken {
    /// Returns the underlying user id when the request was authenticated
    /// via JWT. `None` for legacy bearer requests, since `ADMIN_TOKEN` is
    /// not tied to any user record.
    pub fn user_id(&self) -> Option<&str> {
        match self {
            Self::Legacy => None,
            Self::Jwt(u) => Some(&u.user_id),
        }
    }
}

impl<S> FromRequestParts<S> for AdminOrLegacyToken
where
    S: Send + Sync,
    DbConn: FromRef<S>,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let bearer = extract_bearer(parts)?;

        if legacy_token_matches(&bearer) {
            return Ok(Self::Legacy);
        }

        // Legacy didn't match — fall through to JWT verification. The
        // `AuthenticatedUser` extractor handles signature, audience, exp,
        // token_version, status and `deleted_at` checks; we only have to
        // narrow the role here.
        let user = AuthenticatedUser::from_request_parts(parts, state).await?;

        match user.role.as_str() {
            "super_admin" | "admin" => Ok(Self::Jwt(user)),
            _ => Err(AppError::Forbidden("admin role required".into())),
        }
    }
}

/// Constant-time compare of the presented bearer against `ADMIN_TOKEN`.
///
/// Returns `false` when `ADMIN_TOKEN` is unset or empty so that an
/// accidentally-blank deployment cannot be unlocked with a blank bearer.
fn legacy_token_matches(presented: &str) -> bool {
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_default();
    if expected.is_empty() || expected.len() != presented.len() {
        return false;
    }
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    //! Unit-level coverage for the legacy-vs-jwt decision logic. The full
    //! end-to-end path (Axum extraction, DB lookup, role gating) is
    //! exercised in `tests/auth_integration.rs`.

    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// Serializes mutation of the process-global `ADMIN_TOKEN` env var so
    /// concurrent unit tests in this module cannot race each other on the
    /// `set_var`/`remove_var` calls (which `cargo test` runs in parallel
    /// across threads by default).
    static ADMIN_TOKEN_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    /// RAII guard that restores `ADMIN_TOKEN` to its pre-test value on
    /// drop. Keeping the restore in `Drop` guarantees it runs even if the
    /// wrapped closure panics (e.g. a failing assertion), so a flaky test
    /// cannot leak a bogus `ADMIN_TOKEN` into subsequent tests.
    struct AdminTokenGuard {
        prev: Option<String>,
    }

    impl Drop for AdminTokenGuard {
        fn drop(&mut self) {
            // Safety: the lock held by the caller serializes all writers
            // to `ADMIN_TOKEN`; readers outside this module set their own
            // value before reading, so a transient restore is harmless.
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("ADMIN_TOKEN", v),
                    None => std::env::remove_var("ADMIN_TOKEN"),
                }
            }
        }
    }

    fn with_admin_token<F: FnOnce()>(value: Option<&str>, f: F) {
        let _env_lock = ADMIN_TOKEN_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let _restore = AdminTokenGuard {
            prev: std::env::var("ADMIN_TOKEN").ok(),
        };

        // Safety: serialized by `ADMIN_TOKEN_ENV_LOCK` above.
        unsafe {
            match value {
                Some(v) => std::env::set_var("ADMIN_TOKEN", v),
                None => std::env::remove_var("ADMIN_TOKEN"),
            }
        }

        f();
    }

    #[test]
    fn legacy_match_succeeds_on_exact_token() {
        with_admin_token(Some("the-real-token"), || {
            assert!(legacy_token_matches("the-real-token"));
        });
    }

    #[test]
    fn legacy_match_rejects_wrong_token() {
        with_admin_token(Some("the-real-token"), || {
            assert!(!legacy_token_matches("not-it"));
            assert!(!legacy_token_matches(""));
            assert!(!legacy_token_matches("the-real-token-extra"));
        });
    }

    #[test]
    fn legacy_match_rejects_when_admin_token_unset() {
        with_admin_token(None, || {
            assert!(!legacy_token_matches(""));
            assert!(!legacy_token_matches("anything"));
        });
    }

    #[test]
    fn legacy_match_rejects_when_admin_token_blank() {
        with_admin_token(Some(""), || {
            assert!(!legacy_token_matches(""));
            assert!(!legacy_token_matches("nope"));
        });
    }
}
