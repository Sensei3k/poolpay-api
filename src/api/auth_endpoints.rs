//! HMAC-gated endpoints called by NextAuth to authenticate users and to
//! provision / link social identities. Rust never mints user-facing tokens
//! here — these endpoints only answer "is this password valid?" and
//! "make sure a user row exists for this social identity".

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::api::models::{
    AppError, AuthEventContent, DbAuthEvent, DbUser, DbUserIdentity, UserContent,
    UserIdentityContent, now_iso, record_id_to_string,
};
use crate::auth::hmac::HmacVerifiedJson;
use crate::auth::password;
use crate::db::DbConn;

// ── verify-credentials ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCredentialsRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyCredentialsResponse {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub must_reset_password: bool,
}

pub async fn verify_credentials(
    State(db): State<DbConn>,
    HmacVerifiedJson(req): HmacVerifiedJson<VerifyCredentialsRequest>,
) -> Result<Json<VerifyCredentialsResponse>, AppError> {
    let email_normalised = req.email.trim().to_lowercase();
    if email_normalised.is_empty() || req.password.is_empty() {
        let _ = record_auth_event(&db, None, "login_failure", false, Some("missing_fields")).await;
        return Err(AppError::Unauthorized);
    }

    let user = find_user_by_email_normalised(&db, &email_normalised).await?;
    let stored_hash = user.as_ref().and_then(|u| u.password_hash.as_deref());
    let matches = password::verify_or_dummy(&req.password, stored_hash)?;

    let Some(user) = user else {
        let _ = record_auth_event(&db, None, "login_failure", false, Some("unknown_email")).await;
        return Err(AppError::Unauthorized);
    };

    if !matches {
        let uid = record_id_to_string(user.id.clone());
        let _ = record_auth_event(&db, Some(uid), "login_failure", false, Some("bad_password"))
            .await;
        return Err(AppError::Unauthorized);
    }

    if user.status != "active" || user.deleted_at.is_some() {
        let uid = record_id_to_string(user.id.clone());
        let _ = record_auth_event(&db, Some(uid), "login_failure", false, Some("disabled")).await;
        return Err(AppError::Unauthorized);
    }

    let user_id = record_id_to_string(user.id);
    let _ = record_auth_event(&db, Some(user_id.clone()), "login_success", true, None).await;

    Ok(Json(VerifyCredentialsResponse {
        user_id,
        email: user.email,
        role: user.role,
        must_reset_password: user.must_reset_password,
    }))
}

// ── ensure-user (social JIT provisioning) ─────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureUserRequest {
    pub provider: String,
    pub provider_subject: String,
    pub email: String,
    pub email_verified: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureUserResponse {
    pub user_id: String,
    pub email: String,
    pub role: String,
    pub created: bool,
}

pub async fn ensure_user(
    State(db): State<DbConn>,
    HmacVerifiedJson(req): HmacVerifiedJson<EnsureUserRequest>,
) -> Result<Json<EnsureUserResponse>, AppError> {
    if !matches!(req.provider.as_str(), "google" | "github" | "apple") {
        return Err(AppError::BadRequest(format!(
            "unsupported provider: {}",
            req.provider
        )));
    }
    if req.provider_subject.trim().is_empty() {
        return Err(AppError::BadRequest("providerSubject required".into()));
    }
    let email_normalised = req.email.trim().to_lowercase();
    if email_normalised.is_empty() {
        return Err(AppError::BadRequest("email required".into()));
    }

    if let Some(identity) =
        find_identity(&db, &req.provider, &req.provider_subject).await?
    {
        let user = find_user_by_id(&db, &identity.user_id)
            .await?
            .ok_or_else(|| AppError::Internal("identity references missing user".into()))?;
        return Ok(Json(EnsureUserResponse {
            user_id: identity.user_id,
            email: user.email,
            role: user.role,
            created: false,
        }));
    }

    let (user_id, user_email, role, created) = if req.email_verified {
        match find_user_by_email_normalised(&db, &email_normalised).await? {
            Some(u) => {
                let id = record_id_to_string(u.id);
                (id, u.email, u.role, false)
            }
            None => create_social_user(&db, &req.email, &email_normalised).await?,
        }
    } else {
        // Unverified provider email → never link to an existing account.
        // Use a provider-scoped normalised key so we don't collide with
        // (or squat on) a legitimate verified signup of the same address.
        let scoped = format!(
            "unverified:{}:{}",
            req.provider, req.provider_subject
        );
        create_social_user(&db, &req.email, &scoped).await?
    };

    let identity = UserIdentityContent {
        user_id: user_id.clone(),
        provider: req.provider,
        provider_subject: req.provider_subject,
        email_at_link: req.email,
        created_at: now_iso(),
    };
    let _: Option<DbUserIdentity> = db.create("user_identity").content(identity).await?;

    Ok(Json(EnsureUserResponse {
        user_id,
        email: user_email,
        role,
        created,
    }))
}

async fn create_social_user(
    db: &DbConn,
    email: &str,
    email_normalised: &str,
) -> Result<(String, String, String, bool), AppError> {
    let now = now_iso();
    let content = UserContent {
        email: email.to_string(),
        email_normalised: email_normalised.to_string(),
        password_hash: None,
        role: "member".into(),
        status: "active".into(),
        token_version: 0,
        must_reset_password: false,
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
    };
    let created: Option<DbUser> = db.create("user").content(content).await?;
    let created = created.ok_or_else(|| AppError::Internal("user insert returned none".into()))?;
    Ok((
        record_id_to_string(created.id),
        created.email,
        created.role,
        true,
    ))
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async fn find_user_by_email_normalised(
    db: &DbConn,
    email_normalised: &str,
) -> Result<Option<DbUser>, AppError> {
    let mut resp = db
        .query("SELECT * FROM user WHERE email_normalised = $email LIMIT 1")
        .bind(("email", email_normalised.to_string()))
        .await?
        .check()?;
    let rows: Vec<DbUser> = resp.take(0)?;
    Ok(rows.into_iter().next())
}

async fn find_user_by_id(db: &DbConn, id: &str) -> Result<Option<DbUser>, AppError> {
    let row: Option<DbUser> = db.select(("user", id)).await?;
    Ok(row)
}

async fn find_identity(
    db: &DbConn,
    provider: &str,
    provider_subject: &str,
) -> Result<Option<DbUserIdentity>, AppError> {
    let mut resp = db
        .query(
            "SELECT * FROM user_identity \
             WHERE provider = $p AND provider_subject = $s LIMIT 1",
        )
        .bind(("p", provider.to_string()))
        .bind(("s", provider_subject.to_string()))
        .await?
        .check()?;
    let rows: Vec<DbUserIdentity> = resp.take(0)?;
    Ok(rows.into_iter().next())
}

async fn record_auth_event(
    db: &DbConn,
    user_id: Option<String>,
    event_type: &str,
    success: bool,
    reason: Option<&str>,
) -> Result<(), AppError> {
    let content = AuthEventContent {
        user_id,
        event_type: event_type.into(),
        ip: None,
        user_agent: None,
        success,
        reason: reason.map(str::to_string),
        created_at: now_iso(),
    };
    let _: Option<DbAuthEvent> = db.create("auth_event").content(content).await?;
    Ok(())
}
