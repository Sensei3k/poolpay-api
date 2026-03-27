use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::error;

use crate::api::models::{
    AppError, CreatePaymentRequest, Cycle, DbCycle, DbMember, DbPayment, Member, Payment,
    PaymentContent, record_id_to_i64,
};
use crate::db::{reseed, DbConn};

/// Query params for GET /api/payments — cycleId filter is optional.
#[derive(Debug, Deserialize)]
pub struct PaymentsQuery {
    #[serde(rename = "cycleId")]
    pub cycle_id: Option<i64>,
}

// ── GET handlers ──────────────────────────────────────────────────────────────

pub async fn get_members(State(db): State<DbConn>) -> Result<Json<Vec<Member>>, AppError> {
    let rows: Vec<DbMember> = db.select("member").await?;
    let members: Result<Vec<Member>, AppError> = rows.into_iter().map(Member::try_from).collect();
    Ok(Json(members?))
}

pub async fn get_cycles(State(db): State<DbConn>) -> Result<Json<Vec<Cycle>>, AppError> {
    let rows: Vec<DbCycle> = db.select("cycle").await?;
    let cycles: Result<Vec<Cycle>, AppError> = rows.into_iter().map(Cycle::try_from).collect();
    Ok(Json(cycles?))
}

pub async fn get_payments(
    State(db): State<DbConn>,
    Query(params): Query<PaymentsQuery>,
) -> Result<Json<Vec<Payment>>, AppError> {
    let rows: Vec<DbPayment> = db.select("payment").await?;
    let payments: Result<Vec<Payment>, AppError> =
        rows.into_iter().map(Payment::try_from).collect();
    let payments = payments?;

    // Apply optional cycle_id filter in-process — simple enough at this data volume.
    let filtered = match params.cycle_id {
        Some(cid) => payments.into_iter().filter(|p| p.cycle_id == cid).collect(),
        None => payments,
    };

    Ok(Json(filtered))
}

// ── POST handler ──────────────────────────────────────────────────────────────

pub async fn create_payment(
    State(db): State<DbConn>,
    Json(body): Json<CreatePaymentRequest>,
) -> Result<(StatusCode, Json<Payment>), AppError> {
    body.validate()?;

    // Verify member and cycle exist before writing — prevents dangling references.
    let member: Option<DbMember> = db.select(("member", body.member_id)).await?;
    if member.is_none() {
        return Err(AppError::NotFound(format!(
            "member {} does not exist",
            body.member_id
        )));
    }
    let cycle: Option<DbCycle> = db.select(("cycle", body.cycle_id)).await?;
    if cycle.is_none() {
        return Err(AppError::NotFound(format!(
            "cycle {} does not exist",
            body.cycle_id
        )));
    }

    // Timestamp-based ID: unique at the low transaction volume of an ajo circle.
    let id = chrono::Utc::now().timestamp_millis();

    let content = PaymentContent {
        member_id: body.member_id,
        cycle_id: body.cycle_id,
        amount: body.amount,
        currency: body.currency.clone(),
        payment_date: body.payment_date.clone(),
    };

    // Read back the written record so the response reflects what is actually stored.
    let created: Option<DbPayment> = db.upsert(("payment", id)).content(content).await?;
    let db_payment = created.ok_or_else(|| {
        error!(id, "Upsert returned None — payment may not have been persisted");
        AppError::Internal("payment was not created".into())
    })?;

    Ok((StatusCode::CREATED, Json(Payment::try_from(db_payment)?)))
}

// ── DELETE handler ────────────────────────────────────────────────────────────

/// DELETE /api/payments/:memberId/:cycleId
///
/// Removes the payment(s) for the given member+cycle combination using a
/// WHERE-filtered query rather than a full table scan.
pub async fn delete_payment(
    State(db): State<DbConn>,
    Path((member_id, cycle_id)): Path<(i64, i64)>,
) -> Result<StatusCode, AppError> {
    // Targeted SELECT avoids loading every payment just to filter in-process.
    let rows: Vec<DbPayment> = db
        .query("SELECT * FROM payment WHERE member_id = $mid AND cycle_id = $cid")
        .bind(("mid", member_id))
        .bind(("cid", cycle_id))
        .await?
        .take(0)?;

    if rows.is_empty() {
        return Err(AppError::NotFound(format!(
            "no payment found for member {member_id} in cycle {cycle_id}"
        )));
    }

    for row in rows {
        let id = record_id_to_i64(row.id)?;
        db.delete::<Option<DbPayment>>(("payment", id)).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Dev-only reset handler ────────────────────────────────────────────────────

/// POST /api/test/reset
///
/// Reseeds all tables back to fixture state. Dev/test only — this route is not
/// registered when APP_ENV=production. Used by E2E tests to guarantee a clean,
/// deterministic starting state before each test run.
pub async fn reset_db(State(db): State<DbConn>) -> Result<StatusCode, AppError> {
    reseed(&db).await?;
    Ok(StatusCode::OK)
}
