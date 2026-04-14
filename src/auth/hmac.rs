//! HMAC-SHA256 request authentication for NextAuth → backend calls.
//!
//! The NextAuth app signs each request with a shared secret. We verify:
//!   - `X-Signature: sha256=<hex>` over `timestamp + "." + raw_body`
//!   - `X-Timestamp` within ±60 s of server time (prevents replay)
//!
//! The extractor re-serialises the body for downstream JSON deserialisation.

use axum::{
    body::{Bytes, to_bytes},
    extract::{FromRequest, Request},
    http::HeaderMap,
};
use hmac::{Hmac, Mac};
use serde::de::DeserializeOwned;
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::api::models::AppError;

type HmacSha256 = Hmac<Sha256>;

/// Max body size accepted by HMAC-protected endpoints (1 MiB — NextAuth
/// payloads are a few hundred bytes at most).
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Replay protection window in seconds.
const TIMESTAMP_TOLERANCE_SECS: i64 = 60;

/// Extractor: verifies the HMAC signature then deserialises the JSON body
/// into `T`. Returns 401 for any signing/replay/body failure so the caller
/// cannot probe which specific check failed.
pub struct HmacVerifiedJson<T>(pub T);

impl<S, T> FromRequest<S> for HmacVerifiedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let secret = std::env::var("NEXTAUTH_BACKEND_SECRET").unwrap_or_default();
        if secret.is_empty() {
            tracing::error!("NEXTAUTH_BACKEND_SECRET is not set — rejecting HMAC request");
            return Err(AppError::Unauthorized);
        }

        let (parts, body) = req.into_parts();
        let timestamp = extract_timestamp(&parts.headers)?;
        let signature_hex = extract_signature(&parts.headers)?;

        let bytes = to_bytes(body, MAX_BODY_BYTES)
            .await
            .map_err(|_| AppError::Unauthorized)?;

        verify_signature(&secret, timestamp, &bytes, &signature_hex)?;

        let value: T = serde_json::from_slice(&bytes).map_err(|_| AppError::Unauthorized)?;
        Ok(HmacVerifiedJson(value))
    }
}

fn extract_timestamp(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let ts: i64 = raw.parse().map_err(|_| AppError::Unauthorized)?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > TIMESTAMP_TOLERANCE_SECS {
        return Err(AppError::Unauthorized);
    }
    Ok(ts)
}

fn extract_signature(headers: &HeaderMap) -> Result<String, AppError> {
    let raw = headers
        .get("x-signature")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let hex_part = raw.strip_prefix("sha256=").ok_or(AppError::Unauthorized)?;
    Ok(hex_part.to_string())
}

fn verify_signature(
    secret: &str,
    timestamp: i64,
    body: &Bytes,
    provided_hex: &str,
) -> Result<(), AppError> {
    let provided = hex::decode(provided_hex).map_err(|_| AppError::Unauthorized)?;

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| AppError::Unauthorized)?;
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    let expected = mac.finalize().into_bytes();

    if expected.len() != provided.len()
        || !bool::from(expected.as_slice().ct_eq(provided.as_slice()))
    {
        return Err(AppError::Unauthorized);
    }
    Ok(())
}

/// Sign a payload using the same scheme. Exposed for integration tests so
/// they can build valid requests without reimplementing the signing logic.
#[doc(hidden)]
pub fn sign_for_testing(secret: &str, timestamp: i64, body: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}
