use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::error;

use crate::api::models::{
    CreatePaymentRequest, Cycle, DbCycle, DbMember, DbPayment, Member, Payment, PaymentContent,
};
use crate::db::{reseed, DbConn};

/// Query params for GET /api/payments — cycleId filter is optional.
#[derive(Debug, Deserialize)]
pub struct PaymentsQuery {
    #[serde(rename = "cycleId")]
    pub cycle_id: Option<i64>,
}

// --- GET handlers ---

pub async fn get_members(State(db): State<DbConn>) -> Result<Json<Vec<Member>>, StatusCode> {
    let rows: Vec<DbMember> = match db.select("member").await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to fetch members");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Ok(Json(rows.into_iter().map(Member::from).collect()))
}

pub async fn get_cycles(State(db): State<DbConn>) -> Result<Json<Vec<Cycle>>, StatusCode> {
    let rows: Vec<DbCycle> = match db.select("cycle").await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to fetch cycles");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    Ok(Json(rows.into_iter().map(Cycle::from).collect()))
}

pub async fn get_payments(
    State(db): State<DbConn>,
    Query(params): Query<PaymentsQuery>,
) -> Result<Json<Vec<Payment>>, StatusCode> {
    let rows: Vec<DbPayment> = match db.select("payment").await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to fetch payments");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };

    let payments: Vec<Payment> = rows.into_iter().map(Payment::from).collect();

    // Apply optional cycle_id filter in-process — simple enough that a second DB
    // query would be premature abstraction for this data volume.
    let filtered = match params.cycle_id {
        Some(cid) => payments.into_iter().filter(|p| p.cycle_id == cid).collect(),
        None => payments,
    };

    Ok(Json(filtered))
}

// --- POST handler ---

pub async fn create_payment(
    State(db): State<DbConn>,
    Json(body): Json<CreatePaymentRequest>,
) -> Result<Json<Payment>, StatusCode> {
    // Derive a new ID from the current timestamp (milliseconds) — simple, collision-
    // resistant at the low transaction volume of an ajo circle.
    let id = chrono::Utc::now().timestamp_millis();

    let content = PaymentContent {
        member_id: body.member_id,
        cycle_id: body.cycle_id,
        amount: body.amount,
        currency: body.currency.clone(),
        payment_date: body.payment_date.clone(),
    };

    if let Err(e) = db.upsert::<Option<DbPayment>>(("payment", id)).content(content).await {
        error!(error = %e, "Failed to create payment");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(Json(Payment {
        id,
        member_id: body.member_id,
        cycle_id: body.cycle_id,
        amount: body.amount,
        currency: body.currency,
        payment_date: body.payment_date,
    }))
}

// --- DELETE handler ---

/// DELETE /api/payments/:memberId/:cycleId
///
/// Removes the payment for the given member+cycle combination. Matches the
/// frontend's removePayment(memberId, cycleId) signature — the frontend does
/// not track individual payment IDs.
pub async fn delete_payment(
    State(db): State<DbConn>,
    Path((member_id, cycle_id)): Path<(i64, i64)>,
) -> StatusCode {
    let rows: Vec<DbPayment> = match db.select("payment").await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "Failed to fetch payments for delete");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let payments: Vec<Payment> = rows.into_iter().map(Payment::from).collect();

    let to_delete: Vec<i64> = payments
        .into_iter()
        .filter(|p| p.member_id == member_id && p.cycle_id == cycle_id)
        .map(|p| p.id)
        .collect();

    if to_delete.is_empty() {
        return StatusCode::NOT_FOUND;
    }

    for id in to_delete {
        if let Err(e) = db.delete::<Option<DbPayment>>(("payment", id)).await {
            error!(error = %e, payment_id = id, "Failed to delete payment");
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    }

    StatusCode::NO_CONTENT
}

// --- Dev-only reset handler ---

/// POST /api/test/reset
///
/// Reseeds the payment table back to fixture state. Dev only — used by E2E tests
/// to guarantee a clean, deterministic starting state before each test run.
pub async fn reset_db(State(db): State<DbConn>) -> StatusCode {
    match reseed(&db).await {
        Ok(_) => StatusCode::OK,
        Err(e) => {
            error!(error = %e, "Failed to reseed database");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}
