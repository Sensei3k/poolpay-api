//! Append-only audit trail for auth-security events. Writes are
//! fire-and-forget: telemetry failure must never block a request.
//!
//! Event types used across the auth surface:
//! - `login_success` / `login_failure` — verify-credentials outcomes
//! - `token_issued` / `token_issue_failure` — issue endpoint outcomes
//! - `refresh_success` / `refresh_failure` / `refresh_reuse_detected` — refresh endpoint
//! - `logout` — explicit logout (successful revoke only)
//! - `password_changed` / `password_change_failure` — change-password outcomes
//! - `user_created` — admin created a new user (BE-8)
//! - `role_changed` — super-admin flipped a user's role (BE-8)
//! - `user_disabled` — super-admin disabled or soft-deleted a user (BE-8)
//! - `group_admin_granted` / `group_admin_revoked` — BE-8 PR 4
//!
//! The list is illustrative, not constraining — `event_type` is a free
//! string on the DB side. New events land here without schema change.

use crate::api::models::{AuthEventContent, DbAuthEvent, now_iso};
use crate::db::DbConn;

/// Writes a single row to the `auth_event` table. Always returns `()`;
/// caller must not tree-shake around errors — log-and-continue is the
/// whole contract. The `success` flag is the audit-side truth (not the
/// HTTP status): a login attempt that hit a bad password is
/// `success: false` with `reason: Some("bad_password")`, even though
/// the handler returns 401 (which collapses several failure modes).
///
/// `user_id` is the **subject** of the event (the row being acted upon).
/// `actor_id` is the **operator** who performed the action. For
/// self-actions (login, refresh, change-password, …) they are the same
/// value. For admin actions (super-admin flipping another user's role)
/// they differ — `actor_id` carries the caller's id so the trail is
/// attributable to an operator during incident review.
pub(crate) async fn record_auth_event(
    db: &DbConn,
    user_id: Option<String>,
    actor_id: Option<String>,
    event_type: &str,
    success: bool,
    reason: Option<&str>,
    ip: Option<&str>,
) {
    let content = AuthEventContent {
        user_id,
        actor_id,
        event_type: event_type.into(),
        ip: ip.map(str::to_string),
        user_agent: None,
        success,
        reason: reason.map(str::to_string),
        created_at: now_iso(),
    };
    if let Err(e) = db
        .create::<Option<DbAuthEvent>>("auth_event")
        .content(content)
        .await
    {
        tracing::warn!(error = %e, event_type, "auth_event insert failed");
    }
}
