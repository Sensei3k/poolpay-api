use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use tracing::error;

use super::auth::AdminToken;
use crate::api::models::{
    AppError, CreateCycleRequest, CreateGroupRequest, CreateMemberRequest, CreatePaymentRequest,
    Cycle, CycleContent, DbCycle, DbGroup, DbMember, DbPayment, Group, GroupContent, Member,
    MemberContent, Payment, PaymentContent, UpdateCycleRequest, UpdateGroupRequest,
    UpdateMemberRequest, now_iso, record_id_to_i64,
};
use crate::db::{DbConn, reseed};

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GroupIdQuery {
    #[serde(rename = "groupId")]
    pub group_id: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentsQuery {
    #[serde(rename = "cycleId")]
    pub cycle_id: Option<i64>,
}

// ── Public GET handlers ──────────────────────────────────────────────────────

pub async fn get_groups(State(db): State<DbConn>) -> Result<Json<Vec<Group>>, AppError> {
    let rows: Vec<DbGroup> = db.select("group").await?;
    let groups: Result<Vec<Group>, AppError> = rows
        .into_iter()
        .map(Group::try_from)
        .collect();
    let groups = groups?;
    let filtered: Vec<Group> = groups.into_iter().filter(|g| g.deleted_at.is_none()).collect();
    Ok(Json(filtered))
}

pub async fn get_members(
    State(db): State<DbConn>,
    Query(params): Query<GroupIdQuery>,
) -> Result<Json<Vec<Member>>, AppError> {
    let rows: Vec<DbMember> = db.select("member").await?;
    let members: Result<Vec<Member>, AppError> = rows.into_iter().map(Member::try_from).collect();
    let members = members?;

    let filtered: Vec<Member> = members
        .into_iter()
        .filter(|m| m.deleted_at.is_none())
        .filter(|m| params.group_id.map_or(true, |gid| m.group_id == gid))
        .collect();

    Ok(Json(filtered))
}

pub async fn get_cycles(
    State(db): State<DbConn>,
    Query(params): Query<GroupIdQuery>,
) -> Result<Json<Vec<Cycle>>, AppError> {
    let rows: Vec<DbCycle> = db.select("cycle").await?;
    let cycles: Result<Vec<Cycle>, AppError> = rows.into_iter().map(Cycle::try_from).collect();
    let cycles = cycles?;

    let filtered: Vec<Cycle> = cycles
        .into_iter()
        .filter(|c| params.group_id.map_or(true, |gid| c.group_id == gid))
        .collect();

    Ok(Json(filtered))
}

pub async fn get_payments(
    State(db): State<DbConn>,
    Query(params): Query<PaymentsQuery>,
) -> Result<Json<Vec<Payment>>, AppError> {
    let rows: Vec<DbPayment> = db.select("payment").await?;
    let payments: Result<Vec<Payment>, AppError> =
        rows.into_iter().map(Payment::try_from).collect();
    let payments = payments?;

    let filtered: Vec<Payment> = payments
        .into_iter()
        .filter(|p| p.deleted_at.is_none())
        .filter(|p| params.cycle_id.map_or(true, |cid| p.cycle_id == cid))
        .collect();

    Ok(Json(filtered))
}

// ── Admin Group handlers ─────────────────────────────────────────────────────

pub async fn create_group(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Json(body): Json<CreateGroupRequest>,
) -> Result<(StatusCode, Json<Group>), AppError> {
    body.validate()?;

    let id = chrono::Utc::now().timestamp_millis();
    let now = now_iso();
    let content = GroupContent {
        name: body.name.trim().to_string(),
        status: "active".into(),
        description: body.description,
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
        version: 1,
    };

    let created: Option<DbGroup> = db.upsert(("group", id)).content(content).await?;
    let db_group = created.ok_or_else(|| AppError::Internal("group was not created".into()))?;

    Ok((StatusCode::CREATED, Json(Group::try_from(db_group)?)))
}

pub async fn update_group(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateGroupRequest>,
) -> Result<Json<Group>, AppError> {
    body.validate()?;

    let existing: Option<DbGroup> = db.select(("group", id)).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("group {id} does not exist")))?;

    if existing.version != body.version {
        return Err(AppError::Conflict(
            "version mismatch — record was modified by another request".into(),
        ));
    }

    let content = GroupContent {
        name: body.name.map(|n| n.trim().to_string()).unwrap_or(existing.name),
        status: body.status.unwrap_or(existing.status),
        description: body.description.or(existing.description),
        created_at: existing.created_at,
        updated_at: now_iso(),
        deleted_at: existing.deleted_at,
        version: existing.version + 1,
    };

    let updated: Option<DbGroup> = db.upsert(("group", id)).content(content).await?;
    let db_group = updated.ok_or_else(|| AppError::Internal("group update failed".into()))?;

    Ok(Json(Group::try_from(db_group)?))
}

pub async fn delete_group(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<i64>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbGroup> = db.select(("group", id)).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("group {id} does not exist")))?;

    // Check for members in this group.
    let members: Vec<DbMember> = db
        .query("SELECT * FROM member WHERE group_id = $gid AND deleted_at IS NONE")
        .bind(("gid", id))
        .await?
        .take(0)?;

    if !members.is_empty() {
        return Err(AppError::Conflict(
            "cannot delete group that still has members".into(),
        ));
    }

    // Check for cycles in this group.
    let cycles: Vec<DbCycle> = db
        .query("SELECT * FROM cycle WHERE group_id = $gid")
        .bind(("gid", id))
        .await?
        .take(0)?;

    if !cycles.is_empty() {
        return Err(AppError::Conflict(
            "cannot delete group that still has cycles".into(),
        ));
    }

    // Soft delete.
    let now = now_iso();
    let content = GroupContent {
        name: existing.name,
        status: existing.status,
        description: existing.description,
        created_at: existing.created_at,
        updated_at: now.clone(),
        deleted_at: Some(now),
        version: existing.version + 1,
    };
    let _: Option<DbGroup> = db.upsert(("group", id)).content(content).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Admin Member handlers ────────────────────────────────────────────────────

pub async fn create_member(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(group_id): Path<i64>,
    Json(body): Json<CreateMemberRequest>,
) -> Result<(StatusCode, Json<Member>), AppError> {
    body.validate()?;

    // Verify group exists and is not soft-deleted.
    let group: Option<DbGroup> = db.select(("group", group_id)).await?;
    match &group {
        None => return Err(AppError::NotFound(format!("group {group_id} does not exist"))),
        Some(g) if g.deleted_at.is_some() => {
            return Err(AppError::NotFound(format!("group {group_id} does not exist")));
        }
        _ => {}
    }

    // Check phone uniqueness within this group. Trim first so the query
    // matches the canonicalized value that will be stored.
    let phone_trimmed = body.phone.trim().to_string();
    let dupes: Vec<DbMember> = db
        .query("SELECT * FROM member WHERE group_id = $gid AND phone = $phone AND deleted_at IS NONE")
        .bind(("gid", group_id))
        .bind(("phone", phone_trimmed))
        .await?
        .take(0)?;

    if !dupes.is_empty() {
        return Err(AppError::Conflict(
            "a member with this phone number already exists in this group".into(),
        ));
    }

    let id = chrono::Utc::now().timestamp_millis();
    let now = now_iso();
    let content = MemberContent {
        name: body.name.trim().to_string(),
        phone: body.phone.trim().to_string(),
        position: body.position,
        status: "active".into(),
        group_id,
        notes: body.notes,
        joined_at: body.joined_at,
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
        version: 1,
    };

    let created: Option<DbMember> = db.upsert(("member", id)).content(content).await?;
    let db_member = created.ok_or_else(|| AppError::Internal("member was not created".into()))?;

    Ok((StatusCode::CREATED, Json(Member::try_from(db_member)?)))
}

pub async fn update_member(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateMemberRequest>,
) -> Result<Json<Member>, AppError> {
    body.validate()?;

    let existing: Option<DbMember> = db.select(("member", id)).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("member {id} does not exist")))?;

    if existing.version != body.version {
        return Err(AppError::Conflict(
            "version mismatch — record was modified by another request".into(),
        ));
    }

    // If phone is being changed, check uniqueness within the group.
    if let Some(new_phone) = &body.phone {
        let dupes: Vec<DbMember> = db
            .query("SELECT * FROM member WHERE group_id = $gid AND phone = $phone AND deleted_at IS NONE AND id != $mid")
            .bind(("gid", existing.group_id))
            .bind(("phone", new_phone.trim().to_string()))
            .bind(("mid", surrealdb::types::RecordId::new("member", id)))
            .await?
            .take(0)?;

        if !dupes.is_empty() {
            return Err(AppError::Conflict(
                "a member with this phone number already exists in this group".into(),
            ));
        }
    }

    let content = MemberContent {
        name: body.name.map(|n| n.trim().to_string()).unwrap_or(existing.name),
        phone: body.phone.map(|p| p.trim().to_string()).unwrap_or(existing.phone),
        position: body.position.unwrap_or(existing.position),
        status: body.status.unwrap_or(existing.status),
        group_id: existing.group_id,
        notes: body.notes.or(existing.notes),
        joined_at: body.joined_at.or(existing.joined_at),
        created_at: existing.created_at,
        updated_at: now_iso(),
        deleted_at: existing.deleted_at,
        version: existing.version + 1,
    };

    let updated: Option<DbMember> = db.upsert(("member", id)).content(content).await?;
    let db_member = updated.ok_or_else(|| AppError::Internal("member update failed".into()))?;

    Ok(Json(Member::try_from(db_member)?))
}

pub async fn delete_member(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<i64>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbMember> = db.select(("member", id)).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("member {id} does not exist")))?;

    // Check if member is a recipient of any active cycle.
    let active_cycles: Vec<DbCycle> = db
        .query("SELECT * FROM cycle WHERE recipient_member_id = $mid AND status = 'active'")
        .bind(("mid", id))
        .await?
        .take(0)?;

    if !active_cycles.is_empty() {
        return Err(AppError::Conflict(
            "cannot delete member who is the recipient of an active cycle".into(),
        ));
    }

    // Soft delete.
    let now = now_iso();
    let content = MemberContent {
        name: existing.name,
        phone: existing.phone,
        position: existing.position,
        status: existing.status,
        group_id: existing.group_id,
        notes: existing.notes,
        joined_at: existing.joined_at,
        created_at: existing.created_at,
        updated_at: now.clone(),
        deleted_at: Some(now),
        version: existing.version + 1,
    };
    let _: Option<DbMember> = db.upsert(("member", id)).content(content).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Admin Cycle handlers ─────────────────────────────────────────────────────

pub async fn create_cycle(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(group_id): Path<i64>,
    Json(body): Json<CreateCycleRequest>,
) -> Result<(StatusCode, Json<Cycle>), AppError> {
    body.validate()?;

    // Verify group exists and is not soft-deleted.
    let group: Option<DbGroup> = db.select(("group", group_id)).await?;
    match &group {
        None => return Err(AppError::NotFound(format!("group {group_id} does not exist"))),
        Some(g) if g.deleted_at.is_some() => {
            return Err(AppError::NotFound(format!("group {group_id} does not exist")));
        }
        _ => {}
    }

    // Verify recipient is in the same group and is not soft-deleted.
    let recipient: Option<DbMember> = db.select(("member", body.recipient_member_id)).await?;
    match recipient {
        None => {
            return Err(AppError::NotFound(format!(
                "member {} does not exist",
                body.recipient_member_id
            )));
        }
        Some(m) if m.deleted_at.is_some() => {
            return Err(AppError::BadRequest(
                "recipientMemberId refers to a deleted member".into(),
            ));
        }
        Some(m) if m.group_id != group_id => {
            return Err(AppError::BadRequest(
                "recipientMemberId must belong to the same group".into(),
            ));
        }
        _ => {}
    }

    // Count active members in the group for total_amount calculation.
    let active_members: Vec<DbMember> = db
        .query("SELECT * FROM member WHERE group_id = $gid AND status = 'active' AND deleted_at IS NONE")
        .bind(("gid", group_id))
        .await?
        .take(0)?;

    let total_amount = body.contribution_per_member * active_members.len() as i64;

    let id = chrono::Utc::now().timestamp_millis();
    let now = now_iso();
    let content = CycleContent {
        cycle_number: body.cycle_number,
        start_date: body.start_date,
        end_date: body.end_date,
        contribution_per_member: body.contribution_per_member,
        total_amount,
        recipient_member_id: body.recipient_member_id,
        status: "pending".into(),
        group_id,
        notes: body.notes,
        created_at: now.clone(),
        updated_at: now,
        version: 1,
    };

    let created: Option<DbCycle> = db.upsert(("cycle", id)).content(content).await?;
    let db_cycle = created.ok_or_else(|| AppError::Internal("cycle was not created".into()))?;

    Ok((StatusCode::CREATED, Json(Cycle::try_from(db_cycle)?)))
}

pub async fn update_cycle(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<i64>,
    Json(body): Json<UpdateCycleRequest>,
) -> Result<Json<Cycle>, AppError> {
    body.validate()?;

    let existing: Option<DbCycle> = db.select(("cycle", id)).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("cycle {id} does not exist")))?;

    if existing.version != body.version {
        return Err(AppError::Conflict(
            "version mismatch — record was modified by another request".into(),
        ));
    }

    // Validate new recipient belongs to the same group and is not soft-deleted.
    if let Some(new_rid) = body.recipient_member_id {
        let recipient: Option<DbMember> = db.select(("member", new_rid)).await?;
        match recipient {
            None => {
                return Err(AppError::NotFound(format!(
                    "member {new_rid} does not exist"
                )));
            }
            Some(m) if m.deleted_at.is_some() => {
                return Err(AppError::BadRequest(
                    "recipientMemberId refers to a deleted member".into(),
                ));
            }
            Some(m) if m.group_id != existing.group_id => {
                return Err(AppError::BadRequest(
                    "recipientMemberId must belong to the same group".into(),
                ));
            }
            _ => {}
        }
    }

    let contribution = body.contribution_per_member.unwrap_or(existing.contribution_per_member);

    // Recompute total_amount if contribution changed.
    let total_amount = if body.contribution_per_member.is_some() {
        let active_members: Vec<DbMember> = db
            .query("SELECT * FROM member WHERE group_id = $gid AND status = 'active' AND deleted_at IS NONE")
            .bind(("gid", existing.group_id))
            .await?
            .take(0)?;
        contribution * active_members.len() as i64
    } else {
        existing.total_amount
    };

    let content = CycleContent {
        cycle_number: existing.cycle_number,
        start_date: body.start_date.unwrap_or(existing.start_date),
        end_date: body.end_date.unwrap_or(existing.end_date),
        contribution_per_member: contribution,
        total_amount,
        recipient_member_id: body.recipient_member_id.unwrap_or(existing.recipient_member_id),
        status: body.status.unwrap_or(existing.status),
        group_id: existing.group_id,
        notes: body.notes.or(existing.notes),
        created_at: existing.created_at,
        updated_at: now_iso(),
        version: existing.version + 1,
    };

    let updated: Option<DbCycle> = db.upsert(("cycle", id)).content(content).await?;
    let db_cycle = updated.ok_or_else(|| AppError::Internal("cycle update failed".into()))?;

    Ok(Json(Cycle::try_from(db_cycle)?))
}

pub async fn delete_cycle(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<i64>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbCycle> = db.select(("cycle", id)).await?;
    if existing.is_none() {
        return Err(AppError::NotFound(format!("cycle {id} does not exist")));
    }

    // Check if cycle has payments.
    let payments: Vec<DbPayment> = db
        .query("SELECT * FROM payment WHERE cycle_id = $cid AND deleted_at IS NONE")
        .bind(("cid", id))
        .await?
        .take(0)?;

    if !payments.is_empty() {
        return Err(AppError::Conflict(
            "cannot delete cycle that has payments".into(),
        ));
    }

    // Hard delete for cycles (no soft delete per data model).
    db.delete::<Option<DbCycle>>(("cycle", id)).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Payment handlers ─────────────────────────────────────────────────────────

pub async fn create_payment(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Json(body): Json<CreatePaymentRequest>,
) -> Result<(StatusCode, Json<Payment>), AppError> {
    body.validate()?;

    let member: Option<DbMember> = db.select(("member", body.member_id)).await?;
    let member = member.ok_or_else(|| {
        AppError::NotFound(format!("member {} does not exist", body.member_id))
    })?;
    if member.deleted_at.is_some() {
        return Err(AppError::BadRequest(format!(
            "member {} has been deleted",
            body.member_id
        )));
    }
    let cycle: Option<DbCycle> = db.select(("cycle", body.cycle_id)).await?;
    let cycle = cycle.ok_or_else(|| {
        AppError::NotFound(format!("cycle {} does not exist", body.cycle_id))
    })?;

    if member.group_id != cycle.group_id {
        return Err(AppError::BadRequest(
            "member and cycle must belong to the same group".into(),
        ));
    }

    let id = chrono::Utc::now().timestamp_millis();
    let now = now_iso();
    let content = PaymentContent {
        member_id: body.member_id,
        cycle_id: body.cycle_id,
        amount: body.amount,
        currency: body.currency.clone(),
        payment_date: body.payment_date.clone(),
        payment_method: None,
        reference: None,
        confirmed_at: None,
        confirmed_by: None,
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
    };

    let created: Option<DbPayment> = db.upsert(("payment", id)).content(content).await?;
    let db_payment = created.ok_or_else(|| {
        error!(id, "Upsert returned None — payment may not have been persisted");
        AppError::Internal("payment was not created".into())
    })?;

    Ok((StatusCode::CREATED, Json(Payment::try_from(db_payment)?)))
}

pub async fn delete_payment(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path((member_id, cycle_id)): Path<(i64, i64)>,
) -> Result<StatusCode, AppError> {
    let rows: Vec<DbPayment> = db
        .query("SELECT * FROM payment WHERE member_id = $mid AND cycle_id = $cid AND deleted_at IS NONE")
        .bind(("mid", member_id))
        .bind(("cid", cycle_id))
        .await?
        .take(0)?;

    if rows.is_empty() {
        return Err(AppError::NotFound(format!(
            "no payment found for member {member_id} in cycle {cycle_id}"
        )));
    }

    let now = now_iso();
    for row in rows {
        let id = record_id_to_i64(row.id.clone())?;
        let content = PaymentContent {
            member_id: row.member_id,
            cycle_id: row.cycle_id,
            amount: row.amount,
            currency: row.currency,
            payment_date: row.payment_date,
            payment_method: row.payment_method,
            reference: row.reference,
            confirmed_at: row.confirmed_at,
            confirmed_by: row.confirmed_by,
            created_at: row.created_at,
            updated_at: now.clone(),
            deleted_at: Some(now.clone()),
        };
        let _: Option<DbPayment> = db.upsert(("payment", id)).content(content).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Dev-only reset handler ───────────────────────────────────────────────────

pub async fn reset_db(State(db): State<DbConn>) -> Result<StatusCode, AppError> {
    reseed(&db).await?;
    Ok(StatusCode::OK)
}
