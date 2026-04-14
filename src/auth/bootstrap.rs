//! Bootstrap the first admin user from env vars.
//!
//! Runs once at startup and on demand in tests. Idempotent: if any active
//! admin user already exists, this is a no-op.

use tracing::{info, warn};

use crate::api::models::{
    AuthEventContent, DbAuthEvent, DbUser, DbUserIdentity, UserContent, UserIdentityContent,
    now_iso, record_id_to_string,
};
use crate::auth::password;
use crate::db::DbConn;

const BOOTSTRAP_EVENT_TYPE: &str = "bootstrap_admin_created";

/// Seed the initial admin account if none exists and the required env vars
/// are set. Safe to call on every boot.
pub async fn ensure_admin_user(db: &DbConn) -> Result<(), surrealdb::Error> {
    let email = std::env::var("BOOTSTRAP_ADMIN_EMAIL").unwrap_or_default();
    let password_plain = std::env::var("BOOTSTRAP_ADMIN_PASSWORD").unwrap_or_default();

    if email.is_empty() || password_plain.is_empty() {
        return Ok(());
    }

    if active_admin_exists(db).await? {
        info!("Bootstrap admin already present — skipping seed");
        return Ok(());
    }

    let password_hash = match password::hash(&password_plain) {
        Ok(h) => h,
        Err(e) => {
            warn!(error = ?e, "Failed to hash bootstrap admin password — skipping seed");
            return Ok(());
        }
    };

    let now = now_iso();
    let email_normalised = email.to_lowercase();
    let content = UserContent {
        email: email.clone(),
        email_normalised: email_normalised.clone(),
        password_hash: Some(password_hash),
        role: "admin".into(),
        status: "active".into(),
        token_version: 0,
        must_reset_password: true,
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
    };
    let created: Option<DbUser> = db.create("user").content(content).await?;
    let user_id = created.map(|u| record_id_to_string(u.id));

    // Identity row keyed on ('credentials', email_normalised) — this is how
    // verify-credentials finds the admin. Without it, login would 401.
    if let Some(uid) = user_id.as_deref() {
        let identity = UserIdentityContent {
            user_id: uid.to_string(),
            provider: "credentials".into(),
            provider_subject: email_normalised,
            email_at_link: email.clone(),
            created_at: now.clone(),
        };
        let _: Option<DbUserIdentity> = db.create("user_identity").content(identity).await?;
    }

    let event = AuthEventContent {
        user_id,
        event_type: BOOTSTRAP_EVENT_TYPE.into(),
        ip: None,
        user_agent: None,
        success: true,
        reason: None,
        created_at: now,
    };
    let _: Option<DbAuthEvent> = db.create("auth_event").content(event).await?;

    info!(email_redacted = redact(&email), "Bootstrap admin created");
    Ok(())
}

async fn active_admin_exists(db: &DbConn) -> Result<bool, surrealdb::Error> {
    let mut resp = db
        .query("SELECT count() FROM user WHERE role = 'admin' AND deleted_at IS NONE GROUP ALL")
        .await?
        .check()?;
    let rows: Vec<i64> = resp.take("count").unwrap_or_default();
    Ok(rows.first().copied().unwrap_or(0) > 0)
}

/// Redact everything except the first character and the domain, so the log
/// line is useful for ops without echoing the raw address.
fn redact(email: &str) -> String {
    match email.split_once('@') {
        Some((local, domain)) => {
            let first = local.chars().next().unwrap_or('?');
            format!("{first}***@{domain}")
        }
        None => "***".into(),
    }
}
