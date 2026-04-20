//! HMAC-gated endpoints called by NextAuth to authenticate users and to
//! provision social identities. Rust never mints user-facing tokens here —
//! these endpoints only answer "is this password valid?" and "make sure a
//! user row exists for this social identity".
//!
//! Identity model: uniqueness lives on `user_identity(provider, provider_subject)`.
//! `user.email_normalised` is a non-unique lookup attribute — accounts are
//! never auto-linked on email match. A second provider for the same person
//! becomes a deliberate, authenticated FE linking flow (not in BE-1).

use axum::{
    Extension, Json,
    body::to_bytes,
    extract::{Request, State},
};
use serde::{Deserialize, Serialize};

use crate::api::models::{
    AppError, AuthEventContent, DbAuthEvent, DbUser, DbUserIdentity, UserContent,
    UserIdentityContent, now_iso, record_id_to_string,
};
use crate::auth::extractors::AuthenticatedUser;
use crate::auth::hmac::HmacVerifiedJson;
use crate::auth::jwt::SharedVerifier;
use crate::auth::password;
use crate::auth::rate_limit::{ClientIp, CredentialFailureLimiter};
use crate::auth::refresh::{self, RefreshError};
use crate::db::DbConn;
use surrealdb::types::RecordId;

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
            record_auth_event(
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
                    record_auth_event(
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
                    record_auth_event(
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

// ── change-password ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChangePasswordRequest {
    #[serde(default)]
    pub current_password: Option<String>,
    pub new_password: String,
}

/// Bearer-authenticated password change. Two branches keyed on whether the
/// user currently has a credentials hash:
///
/// * **Change** (hash present): requires `currentPassword`, verifies it,
///   rotates the hash, bumps `token_version`, and revokes every live
///   refresh token for the user so any sibling session dies — the classic
///   re-auth trigger after a credential rotation.
/// * **Set** (hash is `None`): a social-only user adding a password as a
///   second sign-in method. Accepts without `currentPassword`, inserts a
///   `credentials` identity row, bumps `token_version`. Does NOT revoke
///   refresh tokens: this is additive, not a re-auth event.
///
/// Returns `204 No Content` on success. Mounted outside the HMAC
/// sub-router so `AuthenticatedUser` is the sole gate — per-IP limiting
/// is not doubled-charged against already-authenticated callers.
pub async fn change_password(
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<axum::http::StatusCode, AppError> {
    if req.new_password.is_empty() {
        return Err(AppError::BadRequest("newPassword required".into()));
    }
    if req.new_password.len() > MAX_PASSWORD_LEN {
        return Err(AppError::BadRequest("newPassword too long".into()));
    }

    let db_user = find_user_by_id(&db, &user.user_id)
        .await?
        .ok_or_else(|| AppError::Internal("authenticated user not found".into()))?;

    let ip = client_ip.to_string();
    let new_hash = password::hash(&req.new_password)?;
    let now = now_iso();

    match db_user.password_hash.as_deref() {
        Some(existing_hash) => {
            // Change path: verify current then rotate. Every failure path
            // writes an audit row before returning so brute-force probes are
            // observable even when the client keeps receiving 401s.
            let Some(current) = req.current_password.as_deref() else {
                return Err(AppError::BadRequest(
                    "currentPassword required to change an existing password".into(),
                ));
            };
            if !password::verify(current, existing_hash)? {
                record_auth_event(
                    &db,
                    Some(user.user_id.clone()),
                    "password_change_failure",
                    false,
                    Some("bad_current"),
                    Some(&ip),
                )
                .await;
                return Err(AppError::Unauthorized);
            }

            update_password_hash(&db, &user.user_id, Some(&new_hash), &now).await?;
            refresh::bump_token_version(&db, &user.user_id)
                .await
                .map_err(|e| AppError::Internal(format!("token_version bump failed: {e}")))?;
            refresh::revoke_all_for_user(&db, &user.user_id)
                .await
                .map_err(|e| AppError::Internal(format!("refresh revoke failed: {e}")))?;

            record_auth_event(
                &db,
                Some(user.user_id),
                "password_changed",
                true,
                None,
                Some(&ip),
            )
            .await;
        }
        None => {
            // Set path: social user adding a credentials identity. No
            // currentPassword required by design (there is none to verify).
            update_password_hash(&db, &user.user_id, Some(&new_hash), &now).await?;

            let identity = UserIdentityContent {
                user_id: user.user_id.clone(),
                provider: CREDENTIALS_PROVIDER.into(),
                provider_subject: db_user.email_normalised.clone(),
                email_at_link: db_user.email.clone(),
                created_at: now.clone(),
            };
            match db
                .create::<Option<DbUserIdentity>>("user_identity")
                .content(identity)
                .await
            {
                Ok(_) => {}
                Err(err) if is_unique_constraint_error(&err.to_string()) => {
                    // A prior set attempt already inserted the identity —
                    // rotating the hash alone is the correct idempotent
                    // outcome, no error to surface.
                }
                Err(err) => return Err(err.into()),
            }

            refresh::bump_token_version(&db, &user.user_id)
                .await
                .map_err(|e| AppError::Internal(format!("token_version bump failed: {e}")))?;

            record_auth_event(
                &db,
                Some(user.user_id),
                "password_changed",
                true,
                Some("set"),
                Some(&ip),
            )
            .await;
        }
    }

    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn update_password_hash(
    db: &DbConn,
    user_id: &str,
    new_hash: Option<&str>,
    now_rfc3339: &str,
) -> Result<(), AppError> {
    db.query(
        "UPDATE $id SET password_hash = $h, must_reset_password = false, updated_at = $now",
    )
    .bind(("id", RecordId::new("user", user_id.to_string())))
    .bind(("h", new_hash.map(str::to_string)))
    .bind(("now", now_rfc3339.to_string()))
    .await?
    .check()?;
    Ok(())
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

// ── issue (initial token pair) ────────────────────────────────────────────────

/// Upper bound on the user-id field accepted by `/api/auth/issue`. Matches the
/// 128-char cap used on the refresh-token field below to keep the field-level
/// budget symmetric across both token-minting handlers. The raw body cap for
/// `/api/auth/issue` is enforced upstream by `HmacVerifiedJson`
/// (`MAX_BODY_BYTES` = 1 MiB in `auth::hmac`), not by `MAX_REFRESH_BODY_BYTES`.
const MAX_USER_ID_LEN: usize = 128;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssueTokenRequest {
    pub(crate) user_id: String,
}

/// Mint the initial `(access_token, refresh_token)` pair for a user that the
/// NextAuth layer has just authenticated — either via
/// `/api/auth/verify-credentials` (credentials sign-in) or
/// `/api/auth/ensure-user` (social sign-in). HMAC-gated by the
/// `HmacVerifiedJson` extractor on this handler so only NextAuth can call it —
/// the `user_id` in the body is server-trusted after the HMAC check, there is
/// no password re-verification here by design.
///
/// Response shape mirrors `/api/auth/refresh` so the FE can reuse a single
/// typed client for both the initial issue and subsequent rotations.
pub(crate) async fn issue_token_endpoint(
    State(db): State<DbConn>,
    Extension(verifier): Extension<SharedVerifier>,
    ClientIp(client_ip): ClientIp,
    HmacVerifiedJson(req): HmacVerifiedJson<IssueTokenRequest>,
) -> Result<Json<RefreshResponse>, AppError> {
    let user_id = req.user_id.trim().to_string();
    if user_id.is_empty() {
        return Err(AppError::BadRequest("userId required".into()));
    }
    if user_id.len() > MAX_USER_ID_LEN {
        return Err(AppError::BadRequest("userId too long".into()));
    }

    let ip = client_ip.to_string();

    // Load fresh — role and token_version are authoritative only at load time.
    let user = match refresh::load_user(&db, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Mirror the `/refresh` precedent: write a single failure audit
            // row for unknown subject so ops can alert on credential-spray
            // patterns against this endpoint, then 401 uniformly.
            record_auth_event(
                &db,
                None,
                "token_issue_failure",
                false,
                Some("unknown_user"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Unauthorized);
        }
        Err(e) => {
            tracing::error!(error = %e, "issue load_user failed");
            record_auth_event(
                &db,
                Some(user_id.clone()),
                "token_issue_failure",
                false,
                Some("db_error"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal("token issue failed".into()));
        }
    };

    if user.deleted_at.is_some() {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            "token_issue_failure",
            false,
            Some("soft_deleted"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Unauthorized);
    }
    if user.status != "active" {
        record_auth_event(
            &db,
            Some(user_id.clone()),
            "token_issue_failure",
            false,
            Some("disabled"),
            Some(&ip),
        )
        .await;
        return Err(AppError::Unauthorized);
    }

    // Mint the access token *before* persisting a refresh row so a signing
    // failure (misconfigured keys, etc.) cannot leave an orphan refresh token
    // in the DB that no client ever received.
    let access = match verifier.mint_access(&user_id, &user.role, user.token_version) {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "mint access on issue failed");
            record_auth_event(
                &db,
                Some(user_id.clone()),
                "token_issue_failure",
                false,
                Some("mint_access_failed"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal("token issue failed".into()));
        }
    };

    let issued = match refresh::issue(&db, &user_id).await {
        Ok(i) => i,
        Err(e) => {
            tracing::error!(error = %e, "issue refresh failed");
            record_auth_event(
                &db,
                Some(user_id.clone()),
                "token_issue_failure",
                false,
                Some("db_error"),
                Some(&ip),
            )
            .await;
            return Err(AppError::Internal("token issue failed".into()));
        }
    };

    record_auth_event(&db, Some(user_id), "token_issued", true, None, Some(&ip)).await;

    Ok(Json(RefreshResponse {
        access_token: access,
        refresh_token: issued.plaintext,
        expires_at: issued.expires_at,
    }))
}

// ── refresh + logout ──────────────────────────────────────────────────────────

const MAX_REFRESH_TOKEN_LEN: usize = 128;

// Hard cap on the raw request body for the public refresh/logout endpoints.
// `MAX_REFRESH_TOKEN_LEN` bounds the *field* but `Json` would still buffer
// an arbitrarily large body before rejecting it, which is a trivial memory
// DoS vector on un-authenticated routes. 4 KiB easily fits a 128-char token
// plus JSON framing.
const MAX_REFRESH_BODY_BYTES: usize = 4 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
}

/// Rotate a refresh token and mint a fresh access token. Dead code from the
/// client perspective until BE-4 wires NextAuth to start calling it.
///
/// Every failure path produces `401 Unauthorized` with no body hint — the
/// caller cannot distinguish "expired" from "reused" from "unknown" because
/// that distinction is only useful to an attacker.
pub async fn refresh_token_endpoint(
    State(db): State<DbConn>,
    Extension(verifier): Extension<SharedVerifier>,
    ClientIp(client_ip): ClientIp,
    http_req: Request,
) -> Result<Json<RefreshResponse>, AppError> {
    // Malformed JSON / wrong content-type / oversized bodies must not leak a
    // distinguishing 400/413/415 — collapse every decode failure to the same
    // 401 the rest of this handler returns. Reading bytes manually also caps
    // buffer size at `MAX_REFRESH_BODY_BYTES` to bound parser memory.
    let body = to_bytes(http_req.into_body(), MAX_REFRESH_BODY_BYTES)
        .await
        .map_err(|_| AppError::Unauthorized)?;
    let req: RefreshRequest =
        serde_json::from_slice(&body).map_err(|_| AppError::Unauthorized)?;
    if req.refresh_token.is_empty() || req.refresh_token.len() > MAX_REFRESH_TOKEN_LEN {
        return Err(AppError::Unauthorized);
    }

    let ip = client_ip.to_string();
    let (new_token, user_id) = match refresh::rotate(&db, &req.refresh_token).await {
        Ok(pair) => pair,
        Err(RefreshError::ReuseDetected) => {
            // `rotate` already killed the family, bumped token_version, and
            // wrote the audit row — we only need to 401 the caller.
            return Err(AppError::Unauthorized);
        }
        Err(RefreshError::NotFound | RefreshError::Expired) => {
            record_auth_event(&db, None, "refresh_failure", false, Some("invalid"), Some(&ip))
                .await;
            return Err(AppError::Unauthorized);
        }
        Err(e @ (RefreshError::Db(_) | RefreshError::Internal(_))) => {
            // Log internally but collapse to 401 so the response shape cannot
            // be used as an oracle distinguishing server-side failures from
            // invalid/expired/reused tokens.
            tracing::error!(error = %e, "refresh rotate failed");
            return Err(AppError::Unauthorized);
        }
    };

    // Mint a matching access token. The user row is loaded fresh to pick up
    // the latest role + token_version — those can change between refreshes.
    let user = match refresh::load_user(&db, &user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(AppError::Unauthorized),
        Err(e) => {
            tracing::error!(error = %e, "refresh load_user failed");
            return Err(AppError::Unauthorized);
        }
    };

    if user.status != "active" || user.deleted_at.is_some() {
        return Err(AppError::Unauthorized);
    }

    let access = verifier
        .mint_access(&user_id, &user.role, user.token_version)
        .map_err(|e| {
            tracing::error!(error = %e, "mint access on refresh failed");
            AppError::Unauthorized
        })?;

    record_auth_event(&db, Some(user_id), "refresh_success", true, None, Some(&ip)).await;

    Ok(Json(RefreshResponse {
        access_token: access,
        refresh_token: new_token.plaintext,
        expires_at: new_token.expires_at,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogoutRequest {
    pub refresh_token: String,
}

/// Revoke the entire refresh-token family the caller belongs to. Always
/// returns 204 — we do not signal whether the token was known so logout
/// cannot be used as an oracle.
pub async fn logout_endpoint(
    State(db): State<DbConn>,
    ClientIp(client_ip): ClientIp,
    http_req: Request,
) -> Result<axum::http::StatusCode, AppError> {
    // Strict "always 204" contract: malformed JSON / wrong content-type /
    // oversized bodies must not surface Axum's default 400/413/415 —
    // silently return 204 so logout cannot be probed as an oracle, while
    // still bounding parser memory via `MAX_REFRESH_BODY_BYTES`.
    let body = match to_bytes(http_req.into_body(), MAX_REFRESH_BODY_BYTES).await {
        Ok(b) => b,
        Err(_) => return Ok(axum::http::StatusCode::NO_CONTENT),
    };
    let req: LogoutRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return Ok(axum::http::StatusCode::NO_CONTENT),
    };
    if req.refresh_token.is_empty() || req.refresh_token.len() > MAX_REFRESH_TOKEN_LEN {
        return Ok(axum::http::StatusCode::NO_CONTENT);
    }
    let ip = client_ip.to_string();
    match refresh::revoke_by_presented(&db, &req.refresh_token).await {
        Ok(user_id) => {
            record_auth_event(&db, Some(user_id), "logout", true, None, Some(&ip)).await;
        }
        Err(RefreshError::NotFound) => {
            // Unknown token — still return 204 to avoid leaking validity.
        }
        Err(e) => {
            tracing::warn!(error = %e, "logout revoke failed");
        }
    }
    Ok(axum::http::StatusCode::NO_CONTENT)
}

async fn record_auth_event(
    db: &DbConn,
    user_id: Option<String>,
    event_type: &str,
    success: bool,
    reason: Option<&str>,
    ip: Option<&str>,
) {
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
    // request path. Returning `()` makes that contract explicit — callers
    // cannot mistake this for a fallible operation worth handling.
    if let Err(e) = db
        .create::<Option<DbAuthEvent>>("auth_event")
        .content(content)
        .await
    {
        tracing::warn!(error = %e, event_type, "auth_event insert failed");
    }
}
