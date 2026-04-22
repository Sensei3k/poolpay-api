//! Bootstrap the first admin user from env vars.
//!
//! Runs once at startup and on demand in tests. Idempotent: if any active
//! admin user already exists, this is a no-op.

use surrealdb::types::RecordId;
use tracing::{info, warn};

use crate::api::models::{
    AuthEventContent, DbAuthEvent, DbGroup, DbGroupAdmin, DbUser, DbUserIdentity,
    GroupAdminContent, UserContent, UserIdentityContent, now_iso, record_id_to_string,
};
use crate::auth::password;
use crate::db::{DbConn, FIXTURE_GROUP_ID, is_unique_constraint_error};

const BOOTSTRAP_EVENT_TYPE: &str = "bootstrap_admin_created";
const CREDENTIALS_PROVIDER: &str = "credentials";

/// Dev-only fixture password for `seed_dummy_admins`. Only applied when
/// `SEED_ON_EMPTY=true` **and** `APP_ENV` is `development` or `test`, so
/// production boots cannot accidentally plant it.
const DUMMY_ADMIN_PASSWORD: &str = "PoolPayQA2026!";

/// Declarative spec for the dev-only fixture admin accounts. Each row pairs
/// an email with its role and whether to receive a `group_admin` grant on
/// `FIXTURE_GROUP_ID` — lets us cover every role × grant combination the
/// admin UI can render without branching inside the seed loop.
///
/// Current matrix:
/// - admin1: `admin` + FIXTURE_GROUP_ID grant — typical group admin.
/// - admin2: `admin`, no grant — target for manually testing grant creation.
/// - admin3: `super_admin`, no grant — second super-admin so super-admin-on-
///   super-admin flows (e.g. demotion) can be exercised without touching
///   the bootstrap account.
/// - admin4: `admin`, no grant — stable "orphan admin" baseline that stays
///   ungranted even after admin2 gets manually granted during testing.
struct DummyAdmin {
    email: &'static str,
    role: &'static str,
    grant_fixture_group: bool,
}

const DUMMY_ADMINS: [DummyAdmin; 4] = [
    DummyAdmin { email: "admin1@poolpay.test", role: "admin",       grant_fixture_group: true  },
    DummyAdmin { email: "admin2@poolpay.test", role: "admin",       grant_fixture_group: false },
    DummyAdmin { email: "admin3@poolpay.test", role: "super_admin", grant_fixture_group: false },
    DummyAdmin { email: "admin4@poolpay.test", role: "admin",       grant_fixture_group: false },
];

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
///
/// Marked `#[doc(hidden)]` — `pub` is required because integration tests
/// live in the external `tests/` crate, but it must not be treated as part
/// of the public surface. Production code should call `seed_dummy_admins`
/// so the env-based safety gates are always evaluated. Mirrors the pattern
/// used by `auth::hmac::sign_for_testing`.
#[doc(hidden)]
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

    for spec in DUMMY_ADMINS.iter() {
        let user_id = ensure_admin_fixture(
            db,
            spec.email,
            DUMMY_ADMIN_PASSWORD,
            spec.role,
            &super_admin_id,
        )
        .await?;
        // Re-asserting the grant on every run (not just when the user was
        // created this run) restores it after manual cleanup / partial prior
        // runs; `ensure_group_admin_grant` is idempotent on unique conflict.
        if spec.grant_fixture_group {
            if let Some(user_id) = user_id {
                ensure_group_admin_grant(db, &user_id, FIXTURE_GROUP_ID, &super_admin_id).await?;
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
    role: &str,
    super_admin_id: &str,
) -> Result<Option<String>, surrealdb::Error> {
    // Defence-in-depth: `role` is only ever sourced from the in-module
    // `DUMMY_ADMINS` `const`, but guard against a typo slipping in during
    // future edits so a bogus role can't be silently written to `user.role`
    // (where extractors + admin_users UPDATE queries compare against the
    // exact strings `"admin"` / `"super_admin"`).
    assert!(
        matches!(role, "admin" | "super_admin"),
        "fixture admin role must be 'admin' or 'super_admin', got {role:?}"
    );
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
        // Don't blindly trust the identity pointer — the underlying `user`
        // row may have been soft-deleted or disabled via the admin UI since
        // the fixture was first seeded. Reusing a stale pointer would let
        // `ensure_group_admin_grant` award a grant to a non-admin, and
        // silently mask a broken fixture. Verify the user is still an
        // active admin before returning its id.
        let linked: Option<DbUser> = db.select(("user", identity.user_id.as_str())).await?;
        return match linked {
            Some(u)
                if u.deleted_at.is_none()
                    && u.status == "active"
                    && matches!(u.role.as_str(), "admin" | "super_admin") =>
            {
                // Reconcile drift: if the fixture spec now declares a role
                // different from what's persisted (e.g. admin3 was demoted
                // to `admin` via the UI since the last boot), restore the
                // spec'd role so the declared fixture matrix is the source
                // of truth. Mirrors `admin_users::update` — bump `version`
                // for OCC and `token_version` to invalidate any live access
                // tokens the reconciled user still holds.
                if u.role.as_str() != role {
                    reconcile_fixture_role(db, &identity.user_id, role).await?;
                    info!(
                        email_redacted = redact(email),
                        user_id = identity.user_id.as_str(),
                        from = u.role.as_str(),
                        to = role,
                        "fixture admin role drifted from spec — reconciled"
                    );
                } else {
                    info!(
                        email_redacted = redact(email),
                        "fixture admin already seeded — reusing user_id"
                    );
                }
                Ok(Some(identity.user_id))
            }
            Some(_) => {
                warn!(
                    email_redacted = redact(email),
                    user_id = identity.user_id.as_str(),
                    "fixture admin identity points at a disabled/non-admin user — skipping grant"
                );
                Ok(None)
            }
            None => {
                warn!(
                    email_redacted = redact(email),
                    user_id = identity.user_id.as_str(),
                    "fixture admin identity points at a missing user — skipping grant"
                );
                Ok(None)
            }
        };
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
        role: role.into(),
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
    // Fixture seeding must not fail startup on a transient audit-write
    // error. The user + identity rows are already persisted, so degrade to
    // a warn-and-continue on audit issues — matches the best-effort
    // contract documented on `seed_dummy_admins`.
    let audit_result: Result<Option<DbAuthEvent>, _> =
        db.create("auth_event").content(event).await;
    if let Err(e) = audit_result {
        warn!(
            email_redacted = redact(email),
            user_id = user_id.as_str(),
            error = %e,
            "fixture admin auth_event insert failed — continuing"
        );
    }

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

/// Reconcile a persisted fixture admin's role to the spec. Used when
/// `ensure_admin_fixture` detects that `user.role` has drifted from the
/// `DUMMY_ADMINS` entry (typically because the UI was used to promote or
/// demote the fixture between restarts). Bumps `version` (OCC) and
/// `token_version` (invalidates cached access tokens) to match the
/// semantics of the real `PATCH /api/admin/users/:id` role-change path.
async fn reconcile_fixture_role(
    db: &DbConn,
    user_id: &str,
    new_role: &str,
) -> Result<(), surrealdb::Error> {
    let now = now_iso();
    db.query(
        "UPDATE $id SET \
             role = $role, \
             updated_at = $now, \
             version = version + 1, \
             token_version = token_version + 1 \
         WHERE deleted_at IS NONE",
    )
    .bind(("id", RecordId::new("user", user_id.to_string())))
    .bind(("role", new_role.to_string()))
    .bind(("now", now))
    .await?
    .check()?;
    Ok(())
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
            // Grant row is already persisted; treat the audit write as
            // best-effort so a transient audit failure doesn't abort the
            // dev-only seed path (which is already best-effort per the
            // comment below on the `Ok(None)` arm).
            let audit_result: Result<Option<DbAuthEvent>, _> =
                db.create("auth_event").content(event).await;
            if let Err(e) = audit_result {
                warn!(
                    user_id,
                    group_id,
                    error = %e,
                    "fixture group_admin grant audit event insert failed — continuing"
                );
            }
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
