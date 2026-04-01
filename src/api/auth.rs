use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};
use subtle::ConstantTimeEq;

use super::models::AppError;

/// Axum extractor that validates the `Authorization: Bearer <token>` header
/// against the `ADMIN_TOKEN` environment variable.
///
/// Include `_auth: AdminToken` in any handler signature to gate it behind
/// admin authentication. Returns 401 on missing/invalid token.
pub struct AdminToken;

impl<S: Send + Sync> FromRequestParts<S> for AdminToken {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let expected = std::env::var("ADMIN_TOKEN").unwrap_or_default();

        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();

        let token = header.strip_prefix("Bearer ").unwrap_or_default();

        let length_ok = expected.len() == token.len();
        let content_ok: bool = expected.as_bytes().ct_eq(token.as_bytes()).into();

        if expected.is_empty() || !length_ok || !content_ok {
            return Err(AppError::Unauthorized);
        }

        Ok(AdminToken)
    }
}
