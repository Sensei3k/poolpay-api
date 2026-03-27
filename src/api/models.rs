use serde::{Deserialize, Serialize};
use surrealdb::types::{RecordId, RecordIdKey};
use surrealdb_types::SurrealValue;

// --- DB-side structs (used when reading from SurrealDB) ---
// Fields stored as snake_case in SurrealDB — no serde renames needed here.
// SurrealValue derive uses the Rust field name unless #[surreal(rename)] is present.

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

// --- API response structs (serialized to JSON for the frontend) ---
// camelCase renames kept here — these are the types the Next.js frontend expects.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Member {
    pub id: i64,
    pub name: String,
    pub phone: String,
    pub position: i64,
    pub status: String,
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
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub id: i64,
    #[serde(rename = "memberId")]
    pub member_id: i64,
    #[serde(rename = "cycleId")]
    pub cycle_id: i64,
    pub amount: i64,
    pub currency: String,
    #[serde(rename = "paymentDate")]
    pub payment_date: String,
}

// --- DB-to-API conversions ---

/// Extract the integer key from a SurrealDB RecordId (e.g. `member:1` → 1).
/// Panics if the key is not a Number — all our records use integer keys.
fn record_id_to_i64(rid: RecordId) -> i64 {
    match rid.key {
        RecordIdKey::Number(n) => n,
        _ => panic!("RecordId key must be an integer"),
    }
}

impl From<DbMember> for Member {
    fn from(db: DbMember) -> Self {
        Self {
            id: record_id_to_i64(db.id),
            name: db.name,
            phone: db.phone,
            position: db.position,
            status: db.status,
        }
    }
}

impl From<DbCycle> for Cycle {
    fn from(db: DbCycle) -> Self {
        Self {
            id: record_id_to_i64(db.id),
            cycle_number: db.cycle_number,
            start_date: db.start_date,
            end_date: db.end_date,
            contribution_per_member: db.contribution_per_member,
            total_amount: db.total_amount,
            recipient_member_id: db.recipient_member_id,
            status: db.status,
        }
    }
}

impl From<DbPayment> for Payment {
    fn from(db: DbPayment) -> Self {
        Self {
            id: record_id_to_i64(db.id),
            member_id: db.member_id,
            cycle_id: db.cycle_id,
            amount: db.amount,
            currency: db.currency,
            payment_date: db.payment_date,
        }
    }
}

// --- DB-side insert structs (no id field — SurrealDB owns the record ID) ---
// snake_case field names — SurrealValue derive serialises using Rust field names by default.

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
