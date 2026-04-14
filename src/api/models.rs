use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey};
use surrealdb_types::SurrealValue;

/// Stable alias for entity IDs across the API and DB layers.
/// If the underlying representation changes, only this line needs updating.
pub type EntityId = String;

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
    Unauthorized,
    Forbidden(String),
    Conflict(String),
    /// `retry_after_secs` populates the `Retry-After` header when present.
    TooManyRequests {
        retry_after_secs: Option<u64>,
    },
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::NotFound(msg) => simple(StatusCode::NOT_FOUND, msg),
            AppError::BadRequest(msg) => simple(StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized => simple(StatusCode::UNAUTHORIZED, "unauthorized".to_string()),
            AppError::Forbidden(msg) => simple(StatusCode::FORBIDDEN, msg),
            AppError::Conflict(msg) => simple(StatusCode::CONFLICT, msg),
            AppError::TooManyRequests { retry_after_secs } => {
                let mut resp = simple(StatusCode::TOO_MANY_REQUESTS, "too many requests".to_string());
                if let Some(secs) = retry_after_secs {
                    if let Ok(v) = HeaderValue::from_str(&secs.to_string()) {
                        resp.headers_mut().insert(header::RETRY_AFTER, v);
                    }
                }
                resp
            }
            // Don't leak internal error details to the caller.
            AppError::Internal(_) => simple(
                StatusCode::INTERNAL_SERVER_ERROR,
                "an internal error occurred".to_string(),
            ),
        }
    }
}

fn simple(status: StatusCode, message: String) -> Response {
    (status, Json(ErrorBody { error: message })).into_response()
}

impl From<surrealdb::Error> for AppError {
    fn from(e: surrealdb::Error) -> Self {
        tracing::error!(error = %e, "SurrealDB error");
        AppError::Internal(e.to_string())
    }
}

// ── Domain enums ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GroupStatus {
    Active,
    Closed,
}

impl std::str::FromStr for GroupStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "active" => Ok(Self::Active),
            "closed" => Ok(Self::Closed),
            _ => Err(format!("unknown group status: {s}")),
        }
    }
}

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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CycleStatus {
    Pending,
    Active,
    Closed,
}

impl std::str::FromStr for CycleStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "closed" => Ok(Self::Closed),
            _ => Err(format!("unknown cycle status: {s}")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReceiptStatus {
    Pending,
    Confirmed,
    Rejected,
}

impl std::str::FromStr for ReceiptStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "confirmed" => Ok(Self::Confirmed),
            "rejected" => Ok(Self::Rejected),
            _ => Err(format!("unknown receipt status: {s}")),
        }
    }
}

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

// ── DB-side structs (used when reading from SurrealDB) ──────────────────────
//
// Fields stored as snake_case in SurrealDB — no serde renames needed.

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbGroup {
    pub id: RecordId,
    pub name: String,
    pub status: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub version: i64,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbMember {
    pub id: RecordId,
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: String,
    pub group_id: EntityId,
    pub notes: Option<String>,
    pub joined_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub version: i64,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbCycle {
    pub id: RecordId,
    pub cycle_number: i64,
    pub start_date: String,
    pub end_date: String,
    pub contribution_per_member: i64,
    pub total_amount: i64,
    pub recipient_member_id: EntityId,
    pub status: String,
    pub group_id: EntityId,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub version: i64,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbReceipt {
    pub id: RecordId,
    pub whatsapp_message_id: String,
    pub group_id: EntityId,
    pub chat_id: String,
    pub sender_phone: String,
    pub member_id: Option<EntityId>,
    pub cycle_id: Option<EntityId>,
    pub extracted_amount: Option<i64>,
    pub expected_amount: Option<i64>,
    pub amount_matches: Option<bool>,
    pub status: String,
    pub ocr_text: Option<String>,
    pub sender_label: Option<String>,
    pub bank_label: Option<String>,
    pub received_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbGroupLink {
    pub id: RecordId,
    pub chat_id: String,
    pub group_id: EntityId,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbPayment {
    pub id: RecordId,
    pub member_id: EntityId,
    pub cycle_id: EntityId,
    pub amount: i64,
    pub currency: String,
    pub payment_date: String,
    pub payment_method: Option<String>,
    pub reference: Option<String>,
    pub confirmed_at: Option<String>,
    pub confirmed_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

// ── API response structs (serialized to JSON for the frontend) ──────────────
//
// camelCase renames — these are the types the Next.js frontend expects.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: EntityId,
    pub name: String,
    pub status: GroupStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: EntityId,
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: MemberStatus,
    #[serde(rename = "groupId")]
    pub group_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(rename = "joinedAt", skip_serializing_if = "Option::is_none")]
    pub joined_at: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Cycle {
    pub id: EntityId,
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
    pub recipient_member_id: EntityId,
    pub status: CycleStatus,
    #[serde(rename = "groupId")]
    pub group_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub id: EntityId,
    #[serde(rename = "memberId")]
    pub member_id: EntityId,
    #[serde(rename = "cycleId")]
    pub cycle_id: EntityId,
    pub amount: i64,
    pub currency: Currency,
    #[serde(rename = "paymentDate")]
    pub payment_date: String,
    #[serde(rename = "paymentMethod", skip_serializing_if = "Option::is_none")]
    pub payment_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    #[serde(rename = "confirmedAt", skip_serializing_if = "Option::is_none")]
    pub confirmed_at: Option<String>,
    #[serde(rename = "confirmedBy", skip_serializing_if = "Option::is_none")]
    pub confirmed_by: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub id: EntityId,
    #[serde(rename = "whatsappMessageId")]
    pub whatsapp_message_id: String,
    #[serde(rename = "groupId")]
    pub group_id: EntityId,
    #[serde(rename = "chatId")]
    pub chat_id: String,
    #[serde(rename = "senderPhone")]
    pub sender_phone: String,
    #[serde(rename = "memberId", skip_serializing_if = "Option::is_none")]
    pub member_id: Option<EntityId>,
    #[serde(rename = "cycleId", skip_serializing_if = "Option::is_none")]
    pub cycle_id: Option<EntityId>,
    #[serde(rename = "extractedAmount", skip_serializing_if = "Option::is_none")]
    pub extracted_amount: Option<i64>,
    #[serde(rename = "expectedAmount", skip_serializing_if = "Option::is_none")]
    pub expected_amount: Option<i64>,
    #[serde(rename = "amountMatches", skip_serializing_if = "Option::is_none")]
    pub amount_matches: Option<bool>,
    pub status: ReceiptStatus,
    #[serde(rename = "ocrText", skip_serializing_if = "Option::is_none")]
    pub ocr_text: Option<String>,
    #[serde(rename = "senderLabel", skip_serializing_if = "Option::is_none")]
    pub sender_label: Option<String>,
    #[serde(rename = "bankLabel", skip_serializing_if = "Option::is_none")]
    pub bank_label: Option<String>,
    #[serde(rename = "receivedAt")]
    pub received_at: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupLink {
    pub id: EntityId,
    #[serde(rename = "chatId")]
    pub chat_id: String,
    #[serde(rename = "groupId")]
    pub group_id: EntityId,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    #[serde(rename = "deletedAt", skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<String>,
}

// ── DB-to-API conversions ───────────────────────────────────────────────────

/// Extract the string key from a SurrealDB RecordId.
pub(crate) fn record_id_to_string(rid: RecordId) -> String {
    match rid.key {
        RecordIdKey::Number(n) => n.to_string(),
        RecordIdKey::String(s) => s,
        other => unreachable!("unexpected RecordIdKey variant: {other:?}"),
    }
}

impl TryFrom<DbGroup> for Group {
    type Error = AppError;
    fn try_from(db: DbGroup) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_string(db.id),
            name: db.name,
            status: db.status.parse().map_err(|e: String| AppError::Internal(e))?,
            description: db.description,
            created_at: db.created_at,
            updated_at: db.updated_at,
            deleted_at: db.deleted_at,
            version: db.version,
        })
    }
}

impl TryFrom<DbMember> for Member {
    type Error = AppError;
    fn try_from(db: DbMember) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_string(db.id),
            name: db.name,
            phone: db.phone,
            position: db.position,
            status: db.status.parse().map_err(|e: String| AppError::Internal(e))?,
            group_id: db.group_id,
            notes: db.notes,
            joined_at: db.joined_at,
            created_at: db.created_at,
            updated_at: db.updated_at,
            deleted_at: db.deleted_at,
            version: db.version,
        })
    }
}

impl TryFrom<DbCycle> for Cycle {
    type Error = AppError;
    fn try_from(db: DbCycle) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_string(db.id),
            cycle_number: db.cycle_number,
            start_date: db.start_date,
            end_date: db.end_date,
            contribution_per_member: db.contribution_per_member,
            total_amount: db.total_amount,
            recipient_member_id: db.recipient_member_id,
            status: db.status.parse().map_err(|e: String| AppError::Internal(e))?,
            group_id: db.group_id,
            notes: db.notes,
            created_at: db.created_at,
            updated_at: db.updated_at,
            version: db.version,
        })
    }
}

impl TryFrom<DbPayment> for Payment {
    type Error = AppError;
    fn try_from(db: DbPayment) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_string(db.id),
            member_id: db.member_id,
            cycle_id: db.cycle_id,
            amount: db.amount,
            currency: db.currency.parse().map_err(|e: String| AppError::Internal(e))?,
            payment_date: db.payment_date,
            payment_method: db.payment_method,
            reference: db.reference,
            confirmed_at: db.confirmed_at,
            confirmed_by: db.confirmed_by,
            created_at: db.created_at,
            updated_at: db.updated_at,
            deleted_at: db.deleted_at,
        })
    }
}

impl TryFrom<DbReceipt> for Receipt {
    type Error = AppError;
    fn try_from(db: DbReceipt) -> Result<Self, AppError> {
        Ok(Self {
            id: record_id_to_string(db.id),
            whatsapp_message_id: db.whatsapp_message_id,
            group_id: db.group_id,
            chat_id: db.chat_id,
            sender_phone: db.sender_phone,
            member_id: db.member_id,
            cycle_id: db.cycle_id,
            extracted_amount: db.extracted_amount,
            expected_amount: db.expected_amount,
            amount_matches: db.amount_matches,
            status: db.status.parse().map_err(|e: String| AppError::Internal(e))?,
            ocr_text: db.ocr_text,
            sender_label: db.sender_label,
            bank_label: db.bank_label,
            received_at: db.received_at,
            created_at: db.created_at,
            updated_at: db.updated_at,
            deleted_at: db.deleted_at,
        })
    }
}

impl From<DbGroupLink> for GroupLink {
    fn from(db: DbGroupLink) -> Self {
        Self {
            id: record_id_to_string(db.id),
            chat_id: db.chat_id,
            group_id: db.group_id,
            created_at: db.created_at,
            updated_at: db.updated_at,
            deleted_at: db.deleted_at,
        }
    }
}

// ── DB-side insert structs (no id — SurrealDB owns the record ID) ───────────

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct GroupContent {
    pub name: String,
    pub status: String,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct MemberContent {
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: String,
    pub group_id: EntityId,
    pub notes: Option<String>,
    pub joined_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct CycleContent {
    pub cycle_number: i64,
    pub start_date: String,
    pub end_date: String,
    pub contribution_per_member: i64,
    pub total_amount: i64,
    pub recipient_member_id: EntityId,
    pub status: String,
    pub group_id: EntityId,
    pub notes: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub version: i64,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct PaymentContent {
    pub member_id: EntityId,
    pub cycle_id: EntityId,
    pub amount: i64,
    pub currency: String,
    pub payment_date: String,
    pub payment_method: Option<String>,
    pub reference: Option<String>,
    pub confirmed_at: Option<String>,
    pub confirmed_by: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct ReceiptContent {
    pub whatsapp_message_id: String,
    pub group_id: EntityId,
    pub chat_id: String,
    pub sender_phone: String,
    pub member_id: Option<EntityId>,
    pub cycle_id: Option<EntityId>,
    pub extracted_amount: Option<i64>,
    pub expected_amount: Option<i64>,
    pub amount_matches: Option<bool>,
    pub status: String,
    pub ocr_text: Option<String>,
    pub sender_label: Option<String>,
    pub bank_label: Option<String>,
    pub received_at: String,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, SurrealValue)]
pub struct GroupLinkContent {
    pub chat_id: String,
    pub group_id: EntityId,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

// ── Request bodies ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

impl CreateGroupRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        let trimmed = self.name.trim();
        if trimmed.is_empty() || trimmed.len() > 100 {
            return Err(AppError::BadRequest(
                "name must be between 1 and 100 characters".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub status: Option<String>,
    pub description: Option<String>,
    pub version: i64,
}

impl UpdateGroupRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if let Some(name) = &self.name {
            let trimmed = name.trim();
            if trimmed.is_empty() || trimmed.len() > 100 {
                return Err(AppError::BadRequest(
                    "name must be between 1 and 100 characters".into(),
                ));
            }
        }
        if let Some(status) = &self.status {
            status.parse::<GroupStatus>().map_err(AppError::BadRequest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateMemberRequest {
    pub name: String,
    pub phone: String,
    pub position: i64,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(rename = "joinedAt", default)]
    pub joined_at: Option<String>,
}

impl CreateMemberRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.name.trim().is_empty() {
            return Err(AppError::BadRequest("name must not be empty".into()));
        }
        if self.phone.trim().is_empty() {
            return Err(AppError::BadRequest("phone must not be empty".into()));
        }
        if self.position <= 0 {
            return Err(AppError::BadRequest(
                "position must be a positive integer".into(),
            ));
        }
        if let Some(date) = &self.joined_at {
            if !is_valid_date(date) {
                return Err(AppError::BadRequest(
                    "joinedAt must be a valid YYYY-MM-DD date".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateMemberRequest {
    pub name: Option<String>,
    pub phone: Option<String>,
    pub position: Option<i64>,
    pub status: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(rename = "joinedAt", default)]
    pub joined_at: Option<String>,
    pub version: i64,
}

impl UpdateMemberRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if let Some(name) = &self.name {
            if name.trim().is_empty() {
                return Err(AppError::BadRequest("name must not be empty".into()));
            }
        }
        if let Some(phone) = &self.phone {
            if phone.trim().is_empty() {
                return Err(AppError::BadRequest("phone must not be empty".into()));
            }
        }
        if let Some(pos) = self.position {
            if pos <= 0 {
                return Err(AppError::BadRequest(
                    "position must be a positive integer".into(),
                ));
            }
        }
        if let Some(status) = &self.status {
            status.parse::<MemberStatus>().map_err(AppError::BadRequest)?;
        }
        if let Some(joined_at) = &self.joined_at {
            if !is_valid_date(joined_at) {
                return Err(AppError::BadRequest(
                    "joinedAt must be a valid YYYY-MM-DD date".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateCycleRequest {
    #[serde(rename = "cycleNumber")]
    pub cycle_number: i64,
    #[serde(rename = "startDate")]
    pub start_date: String,
    #[serde(rename = "endDate")]
    pub end_date: String,
    #[serde(rename = "contributionPerMember")]
    pub contribution_per_member: i64,
    #[serde(rename = "recipientMemberId")]
    pub recipient_member_id: EntityId,
    #[serde(default)]
    pub notes: Option<String>,
}

impl CreateCycleRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.cycle_number <= 0 {
            return Err(AppError::BadRequest(
                "cycleNumber must be a positive integer".into(),
            ));
        }
        if !is_valid_date(&self.start_date) {
            return Err(AppError::BadRequest(
                "startDate must be a valid YYYY-MM-DD date".into(),
            ));
        }
        if !is_valid_date(&self.end_date) {
            return Err(AppError::BadRequest(
                "endDate must be a valid YYYY-MM-DD date".into(),
            ));
        }
        // Both dates already validated as parseable above.
        let start = chrono::NaiveDate::parse_from_str(&self.start_date, "%Y-%m-%d").unwrap();
        let end = chrono::NaiveDate::parse_from_str(&self.end_date, "%Y-%m-%d").unwrap();
        if start > end {
            return Err(AppError::BadRequest(
                "startDate must be before or equal to endDate".into(),
            ));
        }
        if self.contribution_per_member <= 0 {
            return Err(AppError::BadRequest(
                "contributionPerMember must be a positive integer (in kobo)".into(),
            ));
        }
        if self.recipient_member_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "recipientMemberId must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateCycleRequest {
    #[serde(rename = "startDate")]
    pub start_date: Option<String>,
    #[serde(rename = "endDate")]
    pub end_date: Option<String>,
    #[serde(rename = "contributionPerMember")]
    pub contribution_per_member: Option<i64>,
    #[serde(rename = "recipientMemberId")]
    pub recipient_member_id: Option<EntityId>,
    pub status: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    pub version: i64,
}

impl UpdateCycleRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if let Some(date) = &self.start_date {
            if !is_valid_date(date) {
                return Err(AppError::BadRequest(
                    "startDate must be a valid YYYY-MM-DD date".into(),
                ));
            }
        }
        if let Some(date) = &self.end_date {
            if !is_valid_date(date) {
                return Err(AppError::BadRequest(
                    "endDate must be a valid YYYY-MM-DD date".into(),
                ));
            }
        }
        if let Some(amount) = self.contribution_per_member {
            if amount <= 0 {
                return Err(AppError::BadRequest(
                    "contributionPerMember must be a positive integer (in kobo)".into(),
                ));
            }
        }
        if let Some(status) = &self.status {
            status.parse::<CycleStatus>().map_err(AppError::BadRequest)?;
        }
        if let Some(recipient_id) = &self.recipient_member_id {
            if recipient_id.trim().is_empty() {
                return Err(AppError::BadRequest(
                    "recipientMemberId must not be empty".into(),
                ));
            }
        }
        // When both dates are provided, enforce ordering.
        if let (Some(start), Some(end)) = (&self.start_date, &self.end_date) {
            let s = chrono::NaiveDate::parse_from_str(start, "%Y-%m-%d").unwrap();
            let e = chrono::NaiveDate::parse_from_str(end, "%Y-%m-%d").unwrap();
            if s > e {
                return Err(AppError::BadRequest(
                    "startDate must be before or equal to endDate".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Request body for POST /api/payments.
#[derive(Debug, Deserialize)]
pub struct CreatePaymentRequest {
    #[serde(rename = "memberId")]
    pub member_id: EntityId,
    #[serde(rename = "cycleId")]
    pub cycle_id: EntityId,
    pub amount: i64,
    pub currency: String,
    #[serde(rename = "paymentDate")]
    pub payment_date: String,
}

impl CreatePaymentRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.member_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "memberId must not be empty".into(),
            ));
        }
        if self.cycle_id.trim().is_empty() {
            return Err(AppError::BadRequest(
                "cycleId must not be empty".into(),
            ));
        }
        if self.amount <= 0 {
            return Err(AppError::BadRequest(
                "amount must be a positive integer (in kobo)".into(),
            ));
        }
        self.currency
            .parse::<Currency>()
            .map_err(AppError::BadRequest)?;
        if !is_valid_date(&self.payment_date) {
            return Err(AppError::BadRequest(
                "paymentDate must be a valid YYYY-MM-DD date".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateWhatsappLinkRequest {
    #[serde(rename = "chatId")]
    pub chat_id: String,
    #[serde(rename = "groupId")]
    pub group_id: EntityId,
}

impl CreateWhatsappLinkRequest {
    pub fn validate(&self) -> Result<(), AppError> {
        if self.chat_id.trim().is_empty() {
            return Err(AppError::BadRequest("chatId must not be empty".into()));
        }
        if self.group_id.trim().is_empty() {
            return Err(AppError::BadRequest("groupId must not be empty".into()));
        }
        Ok(())
    }
}

/// Validate that a string is a valid YYYY-MM-DD calendar date.
fn is_valid_date(s: &str) -> bool {
    chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

/// Return the current UTC timestamp as an ISO 8601 string.
pub fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

// ── Auth models ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct UserContent {
    pub email: String,
    pub email_normalised: String,
    pub password_hash: Option<String>,
    pub role: String,
    pub status: String,
    pub token_version: i64,
    pub must_reset_password: bool,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbUser {
    pub id: RecordId,
    pub email: String,
    pub email_normalised: String,
    pub password_hash: Option<String>,
    pub role: String,
    pub status: String,
    pub token_version: i64,
    pub must_reset_password: bool,
    pub created_at: String,
    pub updated_at: String,
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct UserIdentityContent {
    pub user_id: String,
    pub provider: String,
    pub provider_subject: String,
    pub email_at_link: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbUserIdentity {
    pub id: RecordId,
    pub user_id: String,
    pub provider: String,
    pub provider_subject: String,
    pub email_at_link: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct AuthEventContent {
    pub user_id: Option<String>,
    pub event_type: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub reason: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize, SurrealValue)]
pub struct DbAuthEvent {
    pub id: RecordId,
    pub user_id: Option<String>,
    pub event_type: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
    pub reason: Option<String>,
    pub created_at: String,
}

/// Row shape for minting a new refresh token. `hashed_token` is the sha256
/// hex of the opaque 32-byte random value handed to the client — the
/// plaintext never hits disk, so a DB leak cannot be replayed as-is.
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct RefreshTokenContent {
    pub user_id: String,
    pub hashed_token: String,
    pub family_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub replaced_by: Option<String>,
}

#[derive(Debug, Clone, Deserialize, SurrealValue)]
pub struct DbRefreshToken {
    pub id: RecordId,
    pub user_id: String,
    pub hashed_token: String,
    pub family_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
    pub replaced_by: Option<String>,
}

/// Grants one `admin`-role user access to one group. Presence of a row is
/// the RBAC check; deleting the row is the revocation primitive (and bumps
/// the target user's `token_version`).
#[derive(Debug, Clone, Serialize, Deserialize, SurrealValue)]
pub struct GroupAdminContent {
    pub user_id: String,
    pub group_id: String,
    pub created_at: String,
    pub created_by: String,
}

#[derive(Debug, Clone, Deserialize, SurrealValue)]
#[allow(dead_code)] // Wired to handlers in BE-7; kept here so BE-3 sets the shape.
pub struct DbGroupAdmin {
    pub id: RecordId,
    pub user_id: String,
    pub group_id: String,
    pub created_at: String,
    pub created_by: String,
}

