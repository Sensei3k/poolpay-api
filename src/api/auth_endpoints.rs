//! HMAC-gated endpoints called by NextAuth to authenticate users and to
//! provision social identities. Rust never mints user-facing tokens here —
//! these endpoints only answer "is this password valid?" and "make sure a
//! user row exists for this social identity".
//!
//! Identity model: uniqueness lives on `user_identity(provider, provider_subject)`.
//! `user.email_normalised` is a non-unique lookup attribute — accounts are
//! never auto-linked on email match. A second provider for the same person
//! becomes a deliberate, authenticated FE linking flow (not in BE-1).

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};

use crate::api::models::{
    AppError, AuthEventContent, DbAuthEvent, DbUser, DbUserIdentity, UserContent,
    UserIdentityContent, now_iso, record_id_to_string,
};
use crate::auth::hmac::HmacVerifiedJson;
use crate::auth::password;
use crate::auth::rate_limit::{ClientIp, CredentialFailureLimiter};
use crate::db::DbConn;

const CREDENTIALS_PROVIDER: &str = "credentials";

// Per-field length caps. HMAC already caps the whole body at 1 MiB, but within
// that budget a multi-hundred-KB password would burn Argon2 CPU and a
// pathological provider_subject would bloat the DB. Reject at the edge.
const MAX_EMAIL_LEN: usize = 320; // RFC 5321 local+domain max
const MAX_PASSWORD_LEN: usize = 1024;
const MAX_PROVIDER_SUBJECT_LEN: usize = 255;

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
    Extension(limiter): Extension<CredentialFailureLimiter>,
    ClientIp(client_ip): ClientIp,
    HmacVerifiedJson(req): HmacVerifiedJson<VerifyCredentialsRequest>,
) -> Result<Json<VerifyCredentialsResponse>, AppError> {
    if req.email.len() > MAX_EMAIL_LEN {
        return Err(AppError::BadRequest("email too long".into()));
    }
    if req.password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::BadRequest("password too long".into()));
    }
    let email_normalised = req.email.trim().to_lowercase();

    // Run the actual credential check. Success and failure produce identical
    // error shapes to the caller (`AppError::Unauthorized` — mapped to 401),
    // but failure carries the `user_id` (if any) and a reason tag so we can
    // emit a precise `auth_event` and charge the composite limiter.
    let result = authenticate_credentials(&db, &email_normalised, &req.password).await;

    let client_ip_str = client_ip.to_string();
    match result {
        Ok(user) => {
            let user_id = record_id_to_string(user.id);
            let _ = record_auth_event(
                &db,
                Some(user_id.clone()),
                "login_success",
                true,
                None,
                Some(&client_ip_str),
            )
            .await;
            Ok(Json(VerifyCredentialsResponse {
                user_id,
                email: user.email,
                role: user.role,
                must_reset_password: user.must_reset_password,
            }))
        }
        Err(AuthFailure::Internal(e)) => Err(e),
        Err(AuthFailure::Rejected { user_id, reason }) => {
            // Charge the (ip, email) bucket. If the caller has already
            // exhausted their budget, upgrade 401 → 429 so a brute-force
            // client visibly backs off instead of silently grinding.
            let key = (client_ip, email_normalised.clone());
            match limiter.charge_failure(&key) {
                Ok(()) => {
                    let _ = record_auth_event(
                        &db,
                        user_id,
                        "login_failure",
                        false,
                        Some(reason),
                        Some(&client_ip_str),
                    )
                    .await;
                    Err(AppError::Unauthorized)
                }
                Err(retry_after_secs) => {
                    let _ = record_auth_event(
                        &db,
                        user_id,
                        "login_failure",
                        false,
                        Some("rate_limited"),
                        Some(&client_ip_str),
                    )
                    .await;
                    Err(AppError::TooManyRequests {
                        retry_after_secs: Some(retry_after_secs),
                    })
                }
            }
        }
    }
}

/// Outcome of `authenticate_credentials` — either the verified active user or
/// a tagged failure. `Internal` covers DB-level surprises that must not be
/// masked as a 401.
enum AuthFailure {
    Rejected {
        user_id: Option<String>,
        reason: &'static str,
    },
    Internal(AppError),
}

impl From<AppError> for AuthFailure {
    fn from(e: AppError) -> Self {
        AuthFailure::Internal(e)
    }
}

async fn authenticate_credentials(
    db: &DbConn,
    email_normalised: &str,
    password: &str,
) -> Result<DbUser, AuthFailure> {
    if email_normalised.is_empty() || password.is_empty() {
        return Err(AuthFailure::Rejected {
            user_id: None,
            reason: "missing_fields",
        });
    }

    // Lookup via user_identity — the canonical identity key. Every credentials
    // user has exactly one ('credentials', email_normalised) identity row,
    // enforced by the UNIQUE index on user_identity.
    let identity = find_identity(db, CREDENTIALS_PROVIDER, email_normalised).await?;
    let user = match &identity {
        Some(i) => {
            let u = find_user_by_id(db, &i.user_id).await?;
            if u.is_none() {
                // Orphaned identity — row exists but its user is gone. This
                // indicates DB corruption, not a user-facing auth failure.
                return Err(AuthFailure::Internal(AppError::Internal(
                    "identity references missing user".into(),
                )));
            }
            u
        }
        None => None,
    };

    let stored_hash = user.as_ref().and_then(|u| u.password_hash.as_deref());
    let matches = password::verify_or_dummy(password, stored_hash)?;

    let Some(user) = user else {
        return Err(AuthFailure::Rejected {
            user_id: None,
            reason: "unknown_email",
        });
    };

    if !matches {
        let uid = record_id_to_string(user.id.clone());
        return Err(AuthFailure::Rejected {
            user_id: Some(uid),
            reason: "bad_password",
        });
    }

    if user.status != "active" || user.deleted_at.is_some() {
        let uid = record_id_to_string(user.id.clone());
        return Err(AuthFailure::Rejected {
            user_id: Some(uid),
            reason: "disabled",
        });
    }

    Ok(user)
}

// ── ensure-user (social JIT provisioning) ─────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnsureUserRequest {
    pub provider: String,
    pub provider_subject: String,
    pub email: String,
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
    if req.provider_subject.len() > MAX_PROVIDER_SUBJECT_LEN {
        return Err(AppError::BadRequest("providerSubject too long".into()));
    }
    if req.email.trim().is_empty() {
        return Err(AppError::BadRequest("email required".into()));
    }
    if req.email.len() > MAX_EMAIL_LEN {
        return Err(AppError::BadRequest("email too long".into()));
    }

    // Same subject twice → idempotent reuse.
    if let Some(identity) = find_identity(&db, &req.provider, &req.provider_subject).await? {
        let user = find_user_by_id(&db, &identity.user_id)
            .await?
            .ok_or_else(|| AppError::Internal("identity references missing user".into()))?;
        reject_if_not_active(&user)?;
        return Ok(Json(EnsureUserResponse {
            user_id: identity.user_id,
            email: user.email,
            role: user.role,
            created: false,
        }));
    }

    // New subject → always a new user. We deliberately do NOT look up by
    // email. Account linking is an explicit FE flow for a signed-in user.
    let (user_id, user_email, role) = create_social_user(&db, &req.email).await?;

    let identity = UserIdentityContent {
        user_id: user_id.clone(),
        provider: req.provider.clone(),
        provider_subject: req.provider_subject.clone(),
        email_at_link: req.email,
        created_at: now_iso(),
    };

    match db
        .create::<Option<DbUserIdentity>>("user_identity")
        .content(identity)
        .await
    {
        Ok(_) => Ok(Json(EnsureUserResponse {
            user_id,
            email: user_email,
            role,
            created: true,
        })),
        Err(err) if is_unique_constraint_error(&err.to_string()) => {
            // A concurrent ensure_user for the same (provider, subject) won the
            // identity insert race. Reuse the existing row and clean up the
            // user we just created so it doesn't remain orphaned.
            let existing = find_identity(&db, &req.provider, &req.provider_subject)
                .await?
                .ok_or_else(|| {
                    AppError::Internal(
                        "user_identity insert raced but identity was not found".into(),
                    )
                })?;
            let existing_user = find_user_by_id(&db, &existing.user_id)
                .await?
                .ok_or_else(|| AppError::Internal("identity references missing user".into()))?;
            reject_if_not_active(&existing_user)?;

            let _: Option<DbUser> = db.delete(("user", user_id.as_str())).await.unwrap_or(None);

            Ok(Json(EnsureUserResponse {
                user_id: existing.user_id,
                email: existing_user.email,
                role: existing_user.role,
                created: false,
            }))
        }
        Err(err) => Err(err.into()),
    }
}

fn reject_if_not_active(user: &DbUser) -> Result<(), AppError> {
    if user.status != "active" || user.deleted_at.is_some() {
        return Err(AppError::Forbidden("user is not active".into()));
    }
    Ok(())
}

fn is_unique_constraint_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("already contains") || lower.contains("unique") || lower.contains("duplicate")
}

async fn create_social_user(
    db: &DbConn,
    email: &str,
) -> Result<(String, String, String), AppError> {
    let now = now_iso();
    let trimmed_email = email.trim().to_string();
    let content = UserContent {
        email: trimmed_email.clone(),
        email_normalised: trimmed_email.to_lowercase(),
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
    Ok((record_id_to_string(created.id), created.email, created.role))
}

// ── DB helpers ────────────────────────────────────────────────────────────────

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
    ip: Option<&str>,
) -> Result<(), AppError> {
    let content = AuthEventContent {
        user_id,
        event_type: event_type.into(),
        ip: ip.map(str::to_string),
        user_agent: None,
        success,
        reason: reason.map(str::to_string),
        created_at: now_iso(),
    };
    // auth_event writes are fire-and-forget at every callsite: telemetry
    // failure must never block a login. We still warn so ops can alert on
    // "auth_event insert failed" without the error propagating into the
    // request path. Always return Ok to make misuse impossible.
    if let Err(e) = db
        .create::<Option<DbAuthEvent>>("auth_event")
        .content(content)
        .await
    {
        tracing::warn!(error = %e, event_type, "auth_event insert failed");
    }
    Ok(())
}
