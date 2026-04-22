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
/// `SEED_ON_EMPTY=true` **and** `APP_ENV` is `development` or `test`, so
/// production boots cannot accidentally plant it.
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
/// `user_identity`, skips already-present rows, and re-asserts admin1's
/// fixture grant even when the user already existed (so a manual
/// `group_admin` delete is restored by a restart). Gated on
/// `SEED_ON_EMPTY=true` **and** `APP_ENV` ∈ {`development`, `test`} so any
/// other deploy — including unset `APP_ENV` — fails closed. This mirrors
/// the `/api/test/reset` gate in `src/api/mod.rs`.
pub async fn seed_dummy_admins(db: &DbConn) -> Result<(), surrealdb::Error> {
    let flag_enabled = std::env::var("SEED_ON_EMPTY").as_deref() == Ok("true");
    let env_allows_fixtures = matches!(
        std::env::var("APP_ENV").as_deref(),
        Ok("development" | "test")
    );
    seed_dummy_admins_with_flag(db, flag_enabled && env_allows_fixtures).await
}

/// Internal entry point that takes an explicit boolean instead of reading
/// process env. `seed_dummy_admins` calls this after evaluating the
/// `SEED_ON_EMPTY` + `APP_ENV` gates; tests call it directly so they never
/// have to mutate env vars at runtime (which would race with concurrent
/// `std::env::var` reads elsewhere in the suite).
pub async fn seed_dummy_admins_with_flag(
    db: &DbConn,
    enabled: bool,
) -> Result<(), surrealdb::Error> {
    if !enabled {
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
        let user_id = ensure_admin_fixture(db, email, DUMMY_ADMIN_PASSWORD, &super_admin_id)
            .await?;
        // Only admin1 (index 0) gets the group grant — admin2 stays
        // ungranted so the dashboard has a target for testing grant creation.
        // Re-asserting the grant on every run (not just when the user was
        // created this run) restores it after manual cleanup / partial prior
        // runs; `ensure_group_admin_grant` is idempotent on unique conflict.
        if idx == 0 {
            if let Some(user_id) = user_id {
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

/// Returns the fixture admin's user id whether the row was inserted this
/// run or already existed. Callers use this id to re-assert follow-up
/// writes (like admin1's `group_admin` grant) so idempotency holds even
/// when the user row survived but a grant was manually deleted. `Ok(None)`
/// is reserved for skip cases where we could not produce a usable id
/// (e.g. password hash failed, `create` returned no record).
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
    if let Some(identity) = existing.into_iter().next() {
        info!(
            email_redacted = redact(email),
            "fixture admin already seeded — reusing user_id"
        );
        return Ok(Some(identity.user_id));
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

    // Mirror `admin_users::create_admin_user`: if the identity insert fails
    // or returns no record, roll back the user row we just created so we
    // don't leave an orphan that a subsequent run would skip past (or
    // worse, duplicate via non-unique `email_normalised`).
    let identity = UserIdentityContent {
        user_id: user_id.clone(),
        provider: CREDENTIALS_PROVIDER.into(),
        provider_subject: email_normalised,
        email_at_link: email.to_string(),
        created_at: now.clone(),
    };
    let identity_result: Result<Option<DbUserIdentity>, _> =
        db.create("user_identity").content(identity).await;
    match identity_result {
        Ok(Some(_)) => {}
        Ok(None) => {
            warn!(
                email_redacted = redact(email),
                user_id = user_id.as_str(),
                "fixture admin identity create returned no record — rolling back user"
            );
            rollback_fixture_user(db, &user_id).await;
            return Ok(None);
        }
        Err(e) => {
            warn!(
                email_redacted = redact(email),
                user_id = user_id.as_str(),
                error = %e,
                "fixture admin identity create failed — rolling back user"
            );
            rollback_fixture_user(db, &user_id).await;
            return Err(e);
        }
    }

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

/// Best-effort cleanup for an orphan user row left behind when
/// `user_identity` fails to insert. Mirrors `admin_users::rollback_user`:
/// the caller has already decided to bail, so a secondary failure is
/// logged but not surfaced.
async fn rollback_fixture_user(db: &DbConn, user_id: &str) {
    let cleanup: Result<Option<DbUser>, _> = db.delete(("user", user_id)).await;
    if let Err(e) = cleanup {
        warn!(
            error = %e,
            user_id,
            "fixture admin rollback failed after identity error — orphan user row"
        );
    }
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
        Ok(Some(_)) => {
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
        // `create(...).content(...)` returning `Ok(None)` with no error is
        // treated as an internal anomaly elsewhere in the codebase — log
        // loudly so ops can spot it, but don't emit a `group_admin_granted`
        // audit event or fail the boot; the fixture seed is best-effort.
        Ok(None) => {
            warn!(
                user_id,
                group_id,
                "fixture group_admin grant returned no record — skipping audit event"
            );
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
