use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey};
use surrealdb_types::SurrealValue;

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

/// Unified API error type — implements `IntoResponse` so handlers can use `?`
/// directly and always return a JSON body with an `"error"` field.
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    BadRequest(String),
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            // Don't leak internal error details to the caller.
            AppError::Internal(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "an internal error occurred".to_string(),
            ),
        };
        (status, Json(ErrorBody { error: message })).into_response()
    }
}

impl From<surrealdb::Error> for AppError {
    fn from(e: surrealdb::Error) -> Self {
        tracing::error!(error = %e, "SurrealDB error");
        AppError::Internal(e.to_string())
    }
}

// ── Domain enums ──────────────────────────────────────────────────────────────

/// Valid statuses for a circle member.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemberStatus {
    Active,
    Inactive,
}

impl std::str::FromStr for MemberStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "inactive" => Ok(Self::Inactive),
            _ => Err(format!("unknown member status: {s}")),
        }
    }
}

/// Valid statuses for a savings cycle.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CycleStatus {
    Active,
    Closed,
}

impl std::str::FromStr for CycleStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "closed" => Ok(Self::Closed),
            _ => Err(format!("unknown cycle status: {s}")),
        }
    }
}

/// Supported payment currencies.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Currency {
    NGN,
}

impl std::str::FromStr for Currency {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "NGN" => Ok(Self::NGN),
            _ => Err(format!("unsupported currency: {s}")),
        }
    }
}

impl std::fmt::Display for Currency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Currency::NGN => write!(f, "NGN"),
        }
    }
}

// ── DB-side structs (used when reading from SurrealDB) ────────────────────────
//
// Fields stored as snake_case in SurrealDB — no serde renames needed.
// String fields are kept here to keep SurrealValue derive simple; enum
// conversion happens in the TryFrom impls below.

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbMember {
    pub id: RecordId,
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: String,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbCycle {
    pub id: RecordId,
    pub cycle_number: i64,
    pub start_date: String,
    pub end_date: String,
    pub contribution_per_member: i64,
    pub total_amount: i64,
    pub recipient_member_id: i64,
    pub status: String,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbPayment {
    pub id: RecordId,
    pub member_id: i64,
    pub cycle_id: i64,
    pub amount: i64,
    pub currency: String,
    pub payment_date: String,
}

// ── API response structs (serialized to JSON for the frontend) ────────────────
//
// camelCase renames kept here — these are the types the Next.js frontend expects.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: i64,
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: MemberStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cycle {
    pub id: i64,
    #[serde(rename = "cycleNumber")]
    pub cycle_number: i64,
    #[serde(rename = "startDate")]
    pub start_date: String,
    #[serde(rename = "endDate")]
    pub end_date: String,
    #[serde(rename = "contributionPerMember")]
    pub contribution_per_member: i64,
    #[serde(rename = "totalAmount")]
    pub total_amount: i64,
    #[serde(rename = "recipientMemberId")]
    pub recipient_member_id: i64,
    pub status: CycleStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub id: i64,
    #[serde(rename = "memberId")]
    pub member_id: i64,
    #[serde(rename = "cycleId")]
    pub cycle_id: i64,
    pub amount: i64,
    pub currency: Currency,
    #[serde(rename = "paymentDate")]
    pub payment_date: String,
}

// ── DB-to-API conversions ─────────────────────────────────────────────────────

/// Extract the integer key from a SurrealDB RecordId (e.g. `member:1` → 1).
///
/// Returns `AppError::Internal` rather than panicking if the key is not a
/// number — non-integer keys mean a record was written outside normal code paths.
pub(crate) fn record_id_to_i64(rid: RecordId) -> Result<i64, AppError> {
    match rid.key {
        RecordIdKey::Number(n) => Ok(n),
        other => Err(AppError::Internal(format!(
            "expected integer RecordId key, got: {other:?}"
        ))),
    }
}

impl TryFrom<DbMember> for Member {
    type Error = AppError;
    fn try_from(db: DbMember) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_i64(db.id)?,
            name: db.name,
            phone: db.phone,
            position: db.position,
            status: db
                .status
                .parse()
                .map_err(|e: String| AppError::Internal(e))?,
        })
    }
}

impl TryFrom<DbCycle> for Cycle {
    type Error = AppError;
    fn try_from(db: DbCycle) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_i64(db.id)?,
            cycle_number: db.cycle_number,
            start_date: db.start_date,
            end_date: db.end_date,
            contribution_per_member: db.contribution_per_member,
            total_amount: db.total_amount,
            recipient_member_id: db.recipient_member_id,
            status: db
                .status
                .parse()
                .map_err(|e: String| AppError::Internal(e))?,
        })
    }
}

impl TryFrom<DbPayment> for Payment {
    type Error = AppError;
    fn try_from(db: DbPayment) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_i64(db.id)?,
            member_id: db.member_id,
            cycle_id: db.cycle_id,
            amount: db.amount,
            currency: db
                .currency
                .parse()
                .map_err(|e: String| AppError::Internal(e))?,
            payment_date: db.payment_date,
        })
    }
}

// ── DB-side insert structs (no id — SurrealDB owns the record ID) ─────────────

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct MemberContent {
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct CycleContent {
    pub cycle_number: i64,
    pub start_date: String,
    pub end_date: String,
    pub contribution_per_member: i64,
    pub total_amount: i64,
    pub recipient_member_id: i64,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct PaymentContent {
    pub member_id: i64,
    pub cycle_id: i64,
    pub amount: i64,
    pub currency: String,
    pub payment_date: String,
}

// ── Request body ──────────────────────────────────────────────────────────────

/// Request body for POST /api/payments.
#[derive(Debug, Deserialize)]
pub struct CreatePaymentRequest {
    #[serde(rename = "memberId")]
    pub member_id: i64,
    #[serde(rename = "cycleId")]
    pub cycle_id: i64,
    pub amount: i64,
    pub currency: String,
    #[serde(rename = "paymentDate")]
    pub payment_date: String,
}

impl CreatePaymentRequest {
    /// Validate all fields before writing to the database.
    pub fn validate(&self) -> Result<(), AppError> {
        if self.member_id <= 0 {
            return Err(AppError::BadRequest(
                "memberId must be a positive integer".into(),
            ));
        }
        if self.cycle_id <= 0 {
            return Err(AppError::BadRequest(
                "cycleId must be a positive integer".into(),
            ));
        }
        if self.amount <= 0 {
            return Err(AppError::BadRequest(
                "amount must be a positive integer (in kobo)".into(),
            ));
        }
        self.currency
            .parse::<Currency>()
            .map_err(|e| AppError::BadRequest(e))?;
        if !is_valid_date(&self.payment_date) {
            return Err(AppError::BadRequest(
                "paymentDate must be a valid YYYY-MM-DD date".into(),
            ));
        }
        Ok(())
    }
}

/// Validate that a string is a plausible YYYY-MM-DD date.
///
/// Checks format and digit positions only — does not validate calendar
/// semantics (e.g. month ≤ 12). Sufficient as an API boundary check.
fn is_valid_date(s: &str) -> bool {
    if s.len() != 10 {
        return false;
    }
    let b = s.as_bytes();
    b[4] == b'-'
        && b[7] == b'-'
        && b[..4].iter().all(|c| c.is_ascii_digit())
        && b[5..7].iter().all(|c| c.is_ascii_digit())
        && b[8..10].iter().all(|c| c.is_ascii_digit())
}
