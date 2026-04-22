//! Bootstrap the first admin user from env vars.
//!
//! Runs once at startup and on demand in tests. Idempotent: if any active
//! admin user already exists, this is a no-op.

use tracing::{info, warn};

use crate::api::models::{
    AuthEventContent, DbAuthEvent, DbGroup, DbGroupAdmin, DbUser, DbUserIdentity,
    GroupAdminContent, UserContent, UserIdentityContent, now_iso, record_id_to_string,
};
use crate::auth::password;
use crate::db::{DbConn, is_unique_constraint_error};

const BOOTSTRAP_EVENT_TYPE: &str = "bootstrap_admin_created";
const CREDENTIALS_PROVIDER: &str = "credentials";

/// Dev-only fixture password for `seed_dummy_admins`. Only applied when
/// `SEED_ON_EMPTY=true`, so production boots cannot accidentally plant it.
const DUMMY_ADMIN_PASSWORD: &str = "PoolPayQA2026!";
const DUMMY_ADMIN_EMAILS: [&str; 2] = ["admin1@poolpay.test", "admin2@poolpay.test"];
/// Fixture group id mirrors `db::FIXTURE_GROUP_ID` — kept in sync manually
/// because `FIXTURE_GROUP_ID` is a private constant in `db.rs`. If the
/// business-fixture group id ever changes, update this too.
const DUMMY_ADMIN_GROUP_GRANT_ID: &str = "1";

/// Seed the initial admin account if none exists and the required env vars
/// are set. Safe to call on every boot.
pub async fn ensure_admin_user(db: &DbConn) -> Result<(), surrealdb::Error> {
    let email = std::env::var("BOOTSTRAP_ADMIN_EMAIL")
        .unwrap_or_default()
        .trim()
        .to_string();
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
        // Seed the first operator as super_admin — they vet and admit all
        // subsequent admins. Only super_admins can manage other admin users
        // (add, promote, disable, assign/revoke group access).
        role: "super_admin".into(),
        status: "active".into(),
        token_version: 0,
        must_reset_password: true,
        version: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
    };
    let created: Option<DbUser> = db.create("user").content(content).await?;
    let user_id = match created {
        Some(u) => record_id_to_string(u.id),
        None => {
            warn!(
                email_redacted = redact(&email),
                "Bootstrap admin user create returned no record — skipping seed"
            );
            return Ok(());
        }
    };

    // Identity row keyed on ('credentials', email_normalised) — this is how
    // verify-credentials finds the admin. Without it, login would 401.
    let identity = UserIdentityContent {
        user_id: user_id.clone(),
        provider: "credentials".into(),
        provider_subject: email_normalised,
        email_at_link: email.clone(),
        created_at: now.clone(),
    };
    let _: Option<DbUserIdentity> = db.create("user_identity").content(identity).await?;

    let event = AuthEventContent {
        user_id: Some(user_id.clone()),
        actor_id: Some(user_id),
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
        .query("SELECT count() FROM user WHERE role IN ['admin', 'super_admin'] AND status = 'active' AND deleted_at IS NONE GROUP ALL")
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

/// Dev-only: seed two fixture admin users so the admin-management UI has
/// clickable targets without forcing manual `POST /api/admin/users` calls.
///
/// - `admin1@poolpay.test` — active admin with a `group_admin` grant on
///   fixture group `1` (exercises the group-scoped extractor path).
/// - `admin2@poolpay.test` — active admin with no grants (exercises the
///   "grant a new group" flow).
///
/// Both use `must_reset_password: false` so login is one-shot, unlike the
/// bootstrap super-admin. Idempotent on every email: a restart re-checks
/// `user_identity` and skips anything already present. Gated on
/// `SEED_ON_EMPTY=true` so production boots never execute this path.
pub async fn seed_dummy_admins(db: &DbConn) -> Result<(), surrealdb::Error> {
    if std::env::var("SEED_ON_EMPTY").as_deref() != Ok("true") {
        return Ok(());
    }

    // Attribute fixture grants + audit events to the real super-admin so the
    // audit trail is symmetric with the endpoint-driven path. If no
    // super-admin exists yet (bootstrap env vars were unset), skip — there's
    // no plausible actor to record.
    let super_admin_id = match find_super_admin_id(db).await? {
        Some(id) => id,
        None => {
            info!("seed_dummy_admins: no super-admin present — skipping");
            return Ok(());
        }
    };

    for (idx, email) in DUMMY_ADMIN_EMAILS.iter().enumerate() {
        let created =
            ensure_admin_fixture(db, email, DUMMY_ADMIN_PASSWORD, &super_admin_id).await?;
        // Only admin1 (index 0) gets the group grant — admin2 stays
        // ungranted so the dashboard has a target for testing grant creation.
        if idx == 0 {
            if let Some(user_id) = created {
                ensure_group_admin_grant(
                    db,
                    &user_id,
                    DUMMY_ADMIN_GROUP_GRANT_ID,
                    &super_admin_id,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn find_super_admin_id(db: &DbConn) -> Result<Option<String>, surrealdb::Error> {
    let mut resp = db
        .query(
            "SELECT * FROM user \
             WHERE role = 'super_admin' AND status = 'active' AND deleted_at IS NONE \
             LIMIT 1",
        )
        .await?
        .check()?;
    let users: Vec<DbUser> = resp.take(0).unwrap_or_default();
    Ok(users.into_iter().next().map(|u| record_id_to_string(u.id)))
}

/// Returns the newly-created user id if the fixture row was inserted; `None`
/// if the email already existed (so the caller can skip follow-up writes
/// like group grants and know this run was a no-op for that email).
async fn ensure_admin_fixture(
    db: &DbConn,
    email: &str,
    password_plain: &str,
    super_admin_id: &str,
) -> Result<Option<String>, surrealdb::Error> {
    let email_normalised = email.to_lowercase();

    let mut resp = db
        .query(
            "SELECT * FROM user_identity \
             WHERE provider = $p AND provider_subject = $s LIMIT 1",
        )
        .bind(("p", CREDENTIALS_PROVIDER.to_string()))
        .bind(("s", email_normalised.clone()))
        .await?
        .check()?;
    let existing: Vec<DbUserIdentity> = resp.take(0).unwrap_or_default();
    if !existing.is_empty() {
        info!(
            email_redacted = redact(email),
            "fixture admin already seeded — skipping"
        );
        return Ok(None);
    }

    let password_hash = match password::hash(password_plain) {
        Ok(h) => h,
        Err(e) => {
            warn!(
                error = ?e,
                email_redacted = redact(email),
                "fixture admin hash failed — skipping"
            );
            return Ok(None);
        }
    };

    let now = now_iso();
    let user_content = UserContent {
        email: email.to_string(),
        email_normalised: email_normalised.clone(),
        password_hash: Some(password_hash),
        role: "admin".into(),
        status: "active".into(),
        token_version: 0,
        // Dev fixtures skip the first-login rotation so the login flow is
        // one-shot. The real `POST /api/admin/users` path still sets this
        // to true — only this seed path differs.
        must_reset_password: false,
        version: 1,
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
    };
    let created: Option<DbUser> = db.create("user").content(user_content).await?;
    let user_id = match created {
        Some(u) => record_id_to_string(u.id),
        None => {
            warn!(
                email_redacted = redact(email),
                "fixture admin create returned no record — skipping"
            );
            return Ok(None);
        }
    };

    let identity = UserIdentityContent {
        user_id: user_id.clone(),
        provider: CREDENTIALS_PROVIDER.into(),
        provider_subject: email_normalised,
        email_at_link: email.to_string(),
        created_at: now.clone(),
    };
    let _: Option<DbUserIdentity> = db.create("user_identity").content(identity).await?;

    let event = AuthEventContent {
        user_id: Some(user_id.clone()),
        actor_id: Some(super_admin_id.to_string()),
        event_type: "user_created".into(),
        ip: None,
        user_agent: None,
        success: true,
        reason: Some("fixture_seed".into()),
        created_at: now,
    };
    let _: Option<DbAuthEvent> = db.create("auth_event").content(event).await?;

    info!(
        email_redacted = redact(email),
        "fixture admin created"
    );
    Ok(Some(user_id))
}

async fn ensure_group_admin_grant(
    db: &DbConn,
    user_id: &str,
    group_id: &str,
    super_admin_id: &str,
) -> Result<(), surrealdb::Error> {
    // Skip cleanly if the business-fixture group isn't present — e.g. a
    // partial DB where `seed()` didn't run but a super-admin already exists.
    let group: Option<DbGroup> = db.select(("group", group_id)).await?;
    if group.filter(|g| g.deleted_at.is_none()).is_none() {
        info!(
            group_id,
            "fixture group missing — skipping group_admin grant"
        );
        return Ok(());
    }

    let now = now_iso();
    let content = GroupAdminContent {
        user_id: user_id.to_string(),
        group_id: group_id.to_string(),
        created_at: now.clone(),
        created_by: super_admin_id.to_string(),
    };
    let insert: Result<Option<DbGroupAdmin>, _> = db.create("group_admin").content(content).await;
    match insert {
        Ok(_) => {
            let event = AuthEventContent {
                user_id: Some(user_id.to_string()),
                actor_id: Some(super_admin_id.to_string()),
                event_type: "group_admin_granted".into(),
                ip: None,
                user_agent: None,
                success: true,
                reason: Some("fixture_seed".into()),
                created_at: now,
            };
            let _: Option<DbAuthEvent> = db.create("auth_event").content(event).await?;
            info!(user_id, group_id, "fixture group_admin grant created");
            Ok(())
        }
        Err(e) if is_unique_constraint_error(&e.to_string()) => {
            info!(
                user_id,
                group_id, "fixture group_admin grant already exists — skipping"
            );
            Ok(())
        }
        Err(e) => Err(e),
    }
}
