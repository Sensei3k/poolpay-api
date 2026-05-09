//! Pagination helpers shared by every public list endpoint.
//!
//! The shape is intentionally minimal: a `?limit=` and `?offset=` query
//! pair with sane defaults and a hard cap, plus a small struct that the
//! handler uses to drive `LIMIT … START …` clauses and the matching
//! `X-Limit` / `X-Offset` / `X-Total-Count` response headers.
//!
//! Body shape stays a flat JSON array — pagination metadata travels via
//! headers so existing FE consumers don't need a coordinated migration.

use axum::http::{HeaderName, HeaderValue};
use serde::Deserialize;

use crate::api::models::AppError;

/// Default page size when `?limit` is omitted.
pub const DEFAULT_LIMIT: u32 = 50;

/// Hard cap on `?limit` to keep response sizes bounded. Requests above
/// this are rejected with 400 rather than silently clamped — clamping
/// would mask client bugs (a UI asking for 1000 rows and only getting
/// 200) and make API contract debugging painful.
pub const MAX_LIMIT: u32 = 200;

/// Header names exposed alongside paginated list responses. Constants so
/// every handler emits the exact same casing and tests can match by name.
pub const HEADER_TOTAL_COUNT: HeaderName = HeaderName::from_static("x-total-count");
pub const HEADER_LIMIT: HeaderName = HeaderName::from_static("x-limit");
pub const HEADER_OFFSET: HeaderName = HeaderName::from_static("x-offset");

/// Raw query params before validation. Both fields are `Option<String>`
/// so we can produce a clear 400 on non-numeric values rather than the
/// terse default Axum extractor error (`Failed to deserialize query
/// string: invalid digit found in string`), which leaks the parser
/// internals and isn't actionable for FE devs.
#[derive(Debug, Default, Deserialize)]
pub struct PaginationParams {
    pub limit: Option<String>,
    pub offset: Option<String>,
}

/// Parsed and validated pagination state. Constructed via
/// [`Pagination::from_params`].
#[derive(Debug, Clone, Copy)]
pub struct Pagination {
    pub limit: u32,
    pub offset: u32,
}

impl Pagination {
    /// Apply defaults and the `MAX_LIMIT` cap. A `?limit=0` request is
    /// rejected with 400 — a zero-row page is never a useful answer and
    /// returning an empty array on `limit=0` would hide client bugs the
    /// same way silent clamping does.
    pub fn from_params(params: &PaginationParams) -> Result<Self, AppError> {
        let limit = match params.limit.as_deref() {
            None => DEFAULT_LIMIT,
            Some(raw) => parse_u32(raw, "limit")?,
        };
        if limit == 0 {
            return Err(AppError::BadRequest("limit must be >= 1".into()));
        }
        if limit > MAX_LIMIT {
            return Err(AppError::BadRequest(format!(
                "limit must be <= {MAX_LIMIT}"
            )));
        }

        let offset = match params.offset.as_deref() {
            None => 0,
            Some(raw) => parse_u32(raw, "offset")?,
        };

        Ok(Self { limit, offset })
    }
}

fn parse_u32(raw: &str, field: &str) -> Result<u32, AppError> {
    raw.parse::<u32>()
        .map_err(|_| AppError::BadRequest(format!("{field} must be a non-negative integer")))
}

/// Format a `u32` as a header value. Numeric values are always valid
/// header bytes, so the `from_str` call cannot fail in practice — the
/// `expect` documents the invariant rather than papering over it.
pub fn header_u32(value: u32) -> HeaderValue {
    HeaderValue::from_str(&value.to_string())
        .expect("decimal u32 is always a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(limit: Option<&str>, offset: Option<&str>) -> PaginationParams {
        PaginationParams {
            limit: limit.map(str::to_string),
            offset: offset.map(str::to_string),
        }
    }

    #[test]
    fn defaults_when_unset() {
        let p = Pagination::from_params(&params(None, None)).unwrap();
        assert_eq!(p.limit, DEFAULT_LIMIT);
        assert_eq!(p.offset, 0);
    }

    #[test]
    fn rejects_zero_limit() {
        let err = Pagination::from_params(&params(Some("0"), None)).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn rejects_over_max_limit() {
        let err = Pagination::from_params(&params(Some("201"), None)).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn accepts_max_limit() {
        let p = Pagination::from_params(&params(Some("200"), None)).unwrap();
        assert_eq!(p.limit, MAX_LIMIT);
    }

    #[test]
    fn rejects_non_numeric_limit() {
        let err = Pagination::from_params(&params(Some("abc"), None)).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn rejects_negative_offset() {
        let err = Pagination::from_params(&params(None, Some("-1"))).unwrap_err();
        assert!(matches!(err, AppError::BadRequest(_)));
    }

    #[test]
    fn accepts_offset() {
        let p = Pagination::from_params(&params(Some("10"), Some("20"))).unwrap();
        assert_eq!(p.limit, 10);
        assert_eq!(p.offset, 20);
    }
}
