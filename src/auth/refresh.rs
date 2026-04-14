//! Refresh-token storage with rotation-on-use and family revocation.
//!
//! Security model (Plan 3 / BE-3):
//!
//! * Tokens are 32 random bytes, base64url-encoded, handed to the client
//!   exactly once. Only `sha256(token)` hex is persisted, so a DB leak
//!   cannot be replayed as-is.
//! * Every use rotates the token: the old row is marked `revoked_at` +
//!   `replaced_by`, a new row lands in the same `family_id`.
//! * Presenting an already-revoked token is treated as evidence of theft —
//!   the entire `family_id` is revoked, the user's `token_version` is
//!   bumped (invalidating any in-flight access tokens within the 15-min
//!   access TTL), and an `auth_event{refresh_reuse_detected}` is written.
//!   This is RFC 6749 BCP section 4.12.
//! * Logout revokes every row in the family in one shot.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use surrealdb::types::RecordId;
use tracing::warn;

use crate::api::models::{
    AuthEventContent, DbAuthEvent, DbRefreshToken, DbUser, RefreshTokenContent, now_iso,
    record_id_to_string,
};
use crate::db::DbConn;

/// 14 days — matches the default refresh TTL in `JwtConfig`.
const DEFAULT_REFRESH_TTL_SECS: i64 = 14 * 24 * 60 * 60;

/// Plaintext refresh token material handed to the client. Never persisted.
pub struct IssuedRefreshToken {
    pub plaintext: String,
    pub family_id: String,
    pub expires_at: String,
}

/// Error surface for the refresh flow. Handlers translate these to
/// `AppError::Unauthorized` uniformly — the distinction is for logging.
#[derive(Debug)]
pub enum RefreshError {
    NotFound,
    Expired,
    ReuseDetected,
    Db(surrealdb::Error),
    Internal(String),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound => f.write_str("refresh token not found"),
            Self::Expired => f.write_str("refresh token expired"),
            Self::ReuseDetected => f.write_str("refresh token reuse detected"),
            Self::Db(e) => write!(f, "database error: {e}"),
            Self::Internal(s) => write!(f, "internal error: {s}"),
        }
    }
}

impl std::error::Error for RefreshError {}

impl From<surrealdb::Error> for RefreshError {
    fn from(e: surrealdb::Error) -> Self { Self::Db(e) }
}

/// Issue a brand-new refresh token for `user_id`. Used at login time and by
/// the ensure-user JIT flow — both land in BE-4.
#[allow(dead_code)]
pub async fn issue(db: &DbConn, user_id: &str) -> Result<IssuedRefreshToken, RefreshError> {
    let plaintext = random_token();
    let family_id = random_family_id();
    let now = now_iso();
    let expires_at = expires_at_from(&now, refresh_ttl_secs());

    let content = RefreshTokenContent {
        user_id: user_id.to_string(),
        hashed_token: hash_token(&plaintext),
        family_id: family_id.clone(),
        issued_at: now,
        expires_at: expires_at.clone(),
        revoked_at: None,
        replaced_by: None,
    };
    let _: Option<DbRefreshToken> = db.create("refresh_token").content(content).await?;
    Ok(IssuedRefreshToken { plaintext, family_id, expires_at })
}

/// Rotate a presented refresh token. Happy path: revoke the presented row
/// and issue a new one in the same family. Theft path: if the row is
/// already revoked, revoke the entire family, bump the user's
/// `token_version`, and surface `ReuseDetected`.
///
/// Returns the new token plus the `user_id` it belongs to so the caller can
/// mint a matching access token.
pub async fn rotate(
    db: &DbConn,
    presented: &str,
) -> Result<(IssuedRefreshToken, String), RefreshError> {
    let hashed = hash_token(presented);
    let row = load_by_hash(db, &hashed).await?.ok_or(RefreshError::NotFound)?;

    // Cheap pre-checks. These are not the authoritative guard — the atomic
    // revoke below is — but they short-circuit the obvious cases without
    // writing a new row first.
    if row.revoked_at.is_some() {
        handle_reuse(db, &row).await;
        return Err(RefreshError::ReuseDetected);
    }
    if is_expired(&row.expires_at) {
        return Err(RefreshError::Expired);
    }

    let now = now_iso();
    let new_plain = random_token();
    let new_hashed = hash_token(&new_plain);
    let expires_at = expires_at_from(&now, refresh_ttl_secs());

    let new_content = RefreshTokenContent {
        user_id: row.user_id.clone(),
        hashed_token: new_hashed,
        family_id: row.family_id.clone(),
        issued_at: now.clone(),
        expires_at: expires_at.clone(),
        revoked_at: None,
        replaced_by: None,
    };
    let new_row: Option<DbRefreshToken> =
        db.create("refresh_token").content(new_content).await?;
    let new_id = match new_row {
        Some(r) => record_id_to_string(r.id),
        None => return Err(RefreshError::Internal("new refresh_token row not returned".into())),
    };

    // Atomic guard: only one concurrent rotate per row can win the
    // `WHERE revoked_at IS NONE` clause. The loser gets zero affected rows
    // back, which is exactly the reuse/theft signal. This closes the
    // TOCTOU window between the pre-check above and the revoke: two
    // callers presenting the same refresh token in parallel cannot both
    // walk away with live tokens in the same family.
    let old_id = record_id_to_string(row.id.clone());
    let revoked = try_revoke_unrevoked(db, &old_id, &now, &new_id).await?;
    if !revoked {
        // Someone else already rotated this row. Roll back our freshly
        // minted row so the family doesn't accumulate orphans, then run
        // the full reuse response (kill family, bump token_version, audit).
        // Best-effort cleanup — surface DB errors in logs so orphan rows
        // are observable, but do not fail the caller: the authoritative
        // outcome (reuse detected) is already decided.
        if let Err(err) = db
            .delete::<Option<DbRefreshToken>>(("refresh_token", new_id.as_str()))
            .await
        {
            warn!(
                error = %err,
                new_id = %new_id,
                "failed to delete orphan refresh_token row after lost rotation race",
            );
        }
        handle_reuse(db, &row).await;
        return Err(RefreshError::ReuseDetected);
    }

    Ok((
        IssuedRefreshToken { plaintext: new_plain, family_id: row.family_id, expires_at },
        row.user_id,
    ))
}

/// Revoke every live row in `family_id`. Callers provide their own audit
/// event_type (`logout` vs `refresh_reuse_detected`).
pub async fn revoke_family(db: &DbConn, family_id: &str) -> Result<(), RefreshError> {
    let now = now_iso();
    db.query("UPDATE refresh_token SET revoked_at = $now WHERE family_id = $fid AND revoked_at IS NONE")
        .bind(("now", now))
        .bind(("fid", family_id.to_string()))
        .await?
        .check()?;
    Ok(())
}

/// Revoke the family of a presented refresh token. Used by `/api/auth/logout`.
/// Returns the `user_id` so the caller can audit under the right subject.
pub async fn revoke_by_presented(
    db: &DbConn,
    presented: &str,
) -> Result<String, RefreshError> {
    let hashed = hash_token(presented);
    let row = load_by_hash(db, &hashed).await?.ok_or(RefreshError::NotFound)?;
    revoke_family(db, &row.family_id).await?;
    Ok(row.user_id)
}

/// Run every side-effect of reuse detection — family kill, token_version
/// bump, audit row — and swallow all errors. The caller must always be
/// able to return a uniform 401: surfacing a 500 from here would turn a
/// detected-theft signal into a different response code, which is itself
/// an oracle. Any DB failure is logged for ops but never propagated.
async fn handle_reuse(db: &DbConn, stolen: &DbRefreshToken) {
    if let Err(e) = revoke_family(db, &stolen.family_id).await {
        warn!(error = %e, family_id = %stolen.family_id, "reuse: revoke_family failed");
    }
    if let Err(e) = bump_token_version(db, &stolen.user_id).await {
        warn!(error = %e, user = %stolen.user_id, "reuse: bump_token_version failed");
    }
    let event = AuthEventContent {
        user_id: Some(stolen.user_id.clone()),
        event_type: "refresh_reuse_detected".into(),
        ip: None,
        user_agent: None,
        success: false,
        reason: Some(format!("family_id={}", stolen.family_id)),
        created_at: now_iso(),
    };
    if let Err(e) = db.create::<Option<DbAuthEvent>>("auth_event").content(event).await {
        warn!(error = %e, "Failed to record refresh_reuse_detected auth_event");
    }
}

async fn bump_token_version(db: &DbConn, user_id: &str) -> Result<(), RefreshError> {
    db.query("UPDATE $id SET token_version = token_version + 1, updated_at = $now")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .bind(("now", now_iso()))
        .await?
        .check()?;
    Ok(())
}

async fn load_by_hash(
    db: &DbConn,
    hashed: &str,
) -> Result<Option<DbRefreshToken>, RefreshError> {
    let mut resp = db
        .query("SELECT * FROM refresh_token WHERE hashed_token = $h LIMIT 1")
        .bind(("h", hashed.to_string()))
        .await?
        .check()?;
    let rows: Vec<DbRefreshToken> = resp.take(0)?;
    Ok(rows.into_iter().next())
}

/// Atomically revoke a refresh-token row iff it is still live. Returns
/// `true` if this call did the revoke, `false` if the row was already
/// revoked (i.e. a concurrent rotate or a replay won the race). Callers
/// treat `false` as reuse detection.
async fn try_revoke_unrevoked(
    db: &DbConn,
    id: &str,
    at: &str,
    replaced_by: &str,
) -> Result<bool, RefreshError> {
    let mut resp = db
        .query(
            "UPDATE $id SET revoked_at = $at, replaced_by = $rb \
             WHERE revoked_at IS NONE RETURN AFTER",
        )
        .bind(("id", RecordId::new("refresh_token", id.to_string())))
        .bind(("at", at.to_string()))
        .bind(("rb", replaced_by.to_string()))
        .await?
        .check()?;
    let updated: Vec<DbRefreshToken> = resp.take(0)?;
    Ok(!updated.is_empty())
}

fn is_expired(expires_at: &str) -> bool {
    match chrono::DateTime::parse_from_rfc3339(expires_at) {
        Ok(ts) => chrono::Utc::now() > ts.with_timezone(&chrono::Utc),
        Err(_) => true,
    }
}

fn refresh_ttl_secs() -> i64 {
    std::env::var("JWT_REFRESH_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_REFRESH_TTL_SECS)
}

fn expires_at_from(now_rfc3339: &str, ttl_secs: i64) -> String {
    let now = chrono::DateTime::parse_from_rfc3339(now_rfc3339)
        .map(|ts| ts.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now());
    (now + chrono::Duration::seconds(ttl_secs)).to_rfc3339()
}

fn hash_token(plain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plain.as_bytes());
    hex::encode(hasher.finalize())
}

fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_family_id() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Load the user a refresh token belongs to. Exposed so the logout handler
/// can validate the subject before auditing.
#[allow(dead_code)]
pub async fn load_user(db: &DbConn, user_id: &str) -> Result<Option<DbUser>, surrealdb::Error> {
    let mut resp = db
        .query("SELECT * FROM $id")
        .bind(("id", RecordId::new("user", user_id.to_string())))
        .await?
        .check()?;
    let rows: Vec<DbUser> = resp.take(0)?;
    Ok(rows.into_iter().next())
}
