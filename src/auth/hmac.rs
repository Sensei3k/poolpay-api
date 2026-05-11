//! HMAC-SHA256 request authentication.
//!
//! Two secret bindings ride the same machinery:
//!   - [`HmacVerifiedJson`]  — `NEXTAUTH_BACKEND_SECRET` (NextAuth → backend)
//!   - [`WebhookVerifiedJson`] — `WA_WEBHOOK_SECRET`     (WhatsApp bot → backend)
//!
//! Every verified path enforces:
//!   - `X-Signature: sha256=<hex>` over `timestamp + "." + raw_body`
//!   - `X-Timestamp` within ±60 s of server time (replay window)
//!   - Body ≤ 1 MiB
//!
//! Both extractors fail closed (401) when their bound env var is unset, empty,
//! or whitespace-only — so a misconfigured deployment cannot accept signed
//! requests under an empty key. The exact reason for rejection is never
//! leaked: every verification failure collapses to a single
//! `AppError::Unauthorized`.

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

/// Max body size accepted by any HMAC-protected endpoint. NextAuth payloads
/// are a few hundred bytes; WhatsApp webhook payloads carry a single image
/// URL + parsed text, so the same 1 MiB ceiling fits both.
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Replay protection window in seconds. Symmetric: rejects both stale
/// timestamps (delivery delayed past the window) and future timestamps
/// (clock skew or naive forgery).
const TIMESTAMP_TOLERANCE_SECS: i64 = 60;

/// Source of the shared HMAC secret for a particular extractor.
///
/// Implementors point at a single env var; the extractor resolves it on
/// every request so an operator can rotate a secret without restarting the
/// process. The resolver is also the place where empty / whitespace-only
/// values fail closed — see [`resolve_secret`].
pub trait HmacSecretSource {
    /// Name of the env var the secret is read from. Reported in logs when
    /// the var is missing so operators can trace misconfiguration without
    /// leaking the secret itself.
    fn env_var_name() -> &'static str;
}

/// Binds the NextAuth backend secret. The signed-body callers are the
/// Next.js NextAuth handlers calling into this Rust API.
pub struct NextAuthBackendSecret;

impl HmacSecretSource for NextAuthBackendSecret {
    fn env_var_name() -> &'static str {
        "NEXTAUTH_BACKEND_SECRET"
    }
}

/// Binds the WhatsApp webhook secret. The signed-body caller is the
/// out-of-process WhatsApp bot posting receipts at
/// `POST /api/webhooks/whatsapp`.
pub struct WhatsappWebhookSecret;

impl HmacSecretSource for WhatsappWebhookSecret {
    fn env_var_name() -> &'static str {
        "WA_WEBHOOK_SECRET"
    }
}

/// Extractor: verifies the HMAC signature then deserialises the JSON body
/// into `T`. Returns 401 for any signing/replay/body failure so the caller
/// cannot probe which specific check failed. Bound to
/// `NEXTAUTH_BACKEND_SECRET` for NextAuth → backend traffic.
pub struct HmacVerifiedJson<T>(pub T);

impl<S, T> FromRequest<S> for HmacVerifiedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let value = verify_with::<NextAuthBackendSecret, T>(req).await?;
        Ok(HmacVerifiedJson(value))
    }
}

/// Extractor: same verification contract as [`HmacVerifiedJson`], but bound
/// to `WA_WEBHOOK_SECRET`. Mounted on `POST /api/webhooks/whatsapp` so the
/// WhatsApp bot cannot reach NextAuth-gated routes (and vice versa) even
/// if one secret leaks.
pub struct WebhookVerifiedJson<T>(pub T);

impl<S, T> FromRequest<S> for WebhookVerifiedJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = AppError;

    async fn from_request(req: Request, _state: &S) -> Result<Self, Self::Rejection> {
        let value = verify_with::<WhatsappWebhookSecret, T>(req).await?;
        Ok(WebhookVerifiedJson(value))
    }
}

/// Core verification path shared by every HMAC-bound extractor. Generic
/// over the secret source so a future signed endpoint can mount the same
/// machinery against a different env var without duplicating the
/// timestamp/signature/body logic (and risking drift).
async fn verify_with<Src, T>(req: Request) -> Result<T, AppError>
where
    Src: HmacSecretSource,
    T: DeserializeOwned,
{
    let secret = resolve_secret::<Src>()?;

    let (parts, body) = req.into_parts();
    let timestamp = extract_timestamp(&parts.headers)?;
    let signature_hex = extract_signature(&parts.headers)?;

    let bytes = to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| AppError::Unauthorized)?;

    verify_signature(&secret, timestamp, &bytes, &signature_hex)?;

    serde_json::from_slice(&bytes).map_err(|_| AppError::Unauthorized)
}

/// Read the secret env var for a given source, treating unset, empty, or
/// whitespace-only values as misconfiguration. Logged once per failed
/// request so a noisy 401 line surfaces in production even when the
/// caller's request shape is otherwise plausible.
fn resolve_secret<Src: HmacSecretSource>() -> Result<String, AppError> {
    let name = Src::env_var_name();
    let raw = std::env::var(name).unwrap_or_default();
    if raw.trim().is_empty() {
        tracing::error!(env_var = name, "HMAC secret is not set — rejecting request");
        return Err(AppError::Unauthorized);
    }
    Ok(raw)
}

fn extract_timestamp(headers: &HeaderMap) -> Result<i64, AppError> {
    let raw = headers
        .get("x-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;
    let ts: i64 = raw.parse().map_err(|_| AppError::Unauthorized)?;
    let now = chrono::Utc::now().timestamp();
    // Explicit saturating bounds rather than `(now - ts).abs()`: a near
    // `i64::MIN` timestamp would wrap signed subtraction and `i64::MIN.abs()`
    // is itself `i64::MIN` (overflow), which can slip past a naive
    // `.abs() > TIMESTAMP_TOLERANCE_SECS` check at a narrow `now`. Saturating
    // arithmetic clamps to the i64 range so out-of-window timestamps stay
    // out-of-window regardless of how extreme the attacker-supplied value is.
    let lower = now.saturating_sub(TIMESTAMP_TOLERANCE_SECS);
    let upper = now.saturating_add(TIMESTAMP_TOLERANCE_SECS);
    if ts < lower || ts > upper {
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
