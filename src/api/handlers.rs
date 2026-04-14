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
    CreateWhatsappLinkRequest, Cycle, CycleContent, DbCycle, DbGroup, DbGroupLink, DbMember,
    DbPayment, DbReceipt, EntityId, Group, GroupContent, GroupLink, GroupLinkContent, Member,
    MemberContent, Payment, PaymentContent, Receipt, ReceiptContent, ReceiptStatus,
    UpdateCycleRequest, UpdateGroupRequest, UpdateMemberRequest, now_iso, record_id_to_string,
};
use crate::db::{DbConn, reseed};

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GroupIdQuery {
    #[serde(rename = "groupId")]
    pub group_id: Option<EntityId>,
}

#[derive(Debug, Deserialize)]
pub struct PaymentsQuery {
    #[serde(rename = "cycleId")]
    pub cycle_id: Option<EntityId>,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptsQuery {
    #[serde(rename = "groupId")]
    pub group_id: Option<EntityId>,
    pub status: Option<String>,
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
        .filter(|m| params.group_id.as_ref().map_or(true, |gid| m.group_id == *gid))
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
        .filter(|c| params.group_id.as_ref().map_or(true, |gid| c.group_id == *gid))
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
        .filter(|p| params.cycle_id.as_ref().map_or(true, |cid| p.cycle_id == *cid))
        .collect();

    Ok(Json(filtered))
}

pub async fn get_receipts(
    State(db): State<DbConn>,
    Query(params): Query<ReceiptsQuery>,
) -> Result<Json<Vec<Receipt>>, AppError> {
    // Validate status filter up-front so an unknown value returns 400 rather
    // than silently producing an empty list.
    let status_filter: Option<ReceiptStatus> = match params.status.as_deref() {
        None => None,
        Some(s) => Some(s.parse::<ReceiptStatus>().map_err(AppError::BadRequest)?),
    };

    let rows: Vec<DbReceipt> = db.select("receipt").await?;
    let receipts: Result<Vec<Receipt>, AppError> =
        rows.into_iter().map(Receipt::try_from).collect();
    let receipts = receipts?;

    let filtered: Vec<Receipt> = receipts
        .into_iter()
        .filter(|r| r.deleted_at.is_none())
        .filter(|r| params.group_id.as_ref().is_none_or(|gid| r.group_id == *gid))
        .filter(|r| status_filter.as_ref().is_none_or(|s| r.status == *s))
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

    let db_group: Option<DbGroup> = db.create("group").content(content).await?;
    let db_group = db_group.ok_or_else(|| AppError::Internal("group was not created".into()))?;

    Ok((StatusCode::CREATED, Json(Group::try_from(db_group)?)))
}

pub async fn update_group(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
    Json(body): Json<UpdateGroupRequest>,
) -> Result<Json<Group>, AppError> {
    body.validate()?;

    let existing: Option<DbGroup> = db.select(("group", id.as_str())).await?;
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

    let updated: Option<DbGroup> = db.upsert(("group", id.as_str())).content(content).await?;
    let db_group = updated.ok_or_else(|| AppError::Internal("group update failed".into()))?;

    Ok(Json(Group::try_from(db_group)?))
}

pub async fn delete_group(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbGroup> = db.select(("group", id.as_str())).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("group {id} does not exist")))?;

    // Check for members in this group.
    let members: Vec<DbMember> = db
        .query("SELECT * FROM member WHERE group_id = $gid AND deleted_at IS NONE")
        .bind(("gid", id.clone()))
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
        .bind(("gid", id.clone()))
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
    let _: Option<DbGroup> = db.upsert(("group", id.as_str())).content(content).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Admin Member handlers ────────────────────────────────────────────────────

pub async fn create_member(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(group_id): Path<EntityId>,
    Json(body): Json<CreateMemberRequest>,
) -> Result<(StatusCode, Json<Member>), AppError> {
    body.validate()?;

    // Verify group exists and is not soft-deleted.
    let group: Option<DbGroup> = db.select(("group", group_id.as_str())).await?;
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
        .bind(("gid", group_id.clone()))
        .bind(("phone", phone_trimmed))
        .await?
        .take(0)?;

    if !dupes.is_empty() {
        return Err(AppError::Conflict(
            "a member with this phone number already exists in this group".into(),
        ));
    }

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

    let db_member: Option<DbMember> = db.create("member").content(content).await?;
    let db_member = db_member.ok_or_else(|| AppError::Internal("member was not created".into()))?;

    Ok((StatusCode::CREATED, Json(Member::try_from(db_member)?)))
}

pub async fn update_member(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
    Json(body): Json<UpdateMemberRequest>,
) -> Result<Json<Member>, AppError> {
    body.validate()?;

    let existing: Option<DbMember> = db.select(("member", id.as_str())).await?;
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
            .bind(("gid", existing.group_id.clone()))
            .bind(("phone", new_phone.trim().to_string()))
            .bind(("mid", surrealdb::types::RecordId::new("member", id.clone())))
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

    let updated: Option<DbMember> = db.upsert(("member", id.as_str())).content(content).await?;
    let db_member = updated.ok_or_else(|| AppError::Internal("member update failed".into()))?;

    Ok(Json(Member::try_from(db_member)?))
}

pub async fn delete_member(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbMember> = db.select(("member", id.as_str())).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("member {id} does not exist")))?;

    // Check if member is a recipient of any active cycle.
    let active_cycles: Vec<DbCycle> = db
        .query("SELECT * FROM cycle WHERE recipient_member_id = $mid AND status = 'active'")
        .bind(("mid", id.clone()))
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
    let _: Option<DbMember> = db.upsert(("member", id.as_str())).content(content).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Admin Cycle handlers ─────────────────────────────────────────────────────

pub async fn create_cycle(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(group_id): Path<EntityId>,
    Json(body): Json<CreateCycleRequest>,
) -> Result<(StatusCode, Json<Cycle>), AppError> {
    body.validate()?;

    // Verify group exists and is not soft-deleted.
    let group: Option<DbGroup> = db.select(("group", group_id.as_str())).await?;
    match &group {
        None => return Err(AppError::NotFound(format!("group {group_id} does not exist"))),
        Some(g) if g.deleted_at.is_some() => {
            return Err(AppError::NotFound(format!("group {group_id} does not exist")));
        }
        _ => {}
    }

    // Verify recipient is in the same group and is not soft-deleted.
    let recipient: Option<DbMember> = db.select(("member", body.recipient_member_id.as_str())).await?;
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
        .bind(("gid", group_id.clone()))
        .await?
        .take(0)?;

    let total_amount = body.contribution_per_member * active_members.len() as i64;

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

    let db_cycle: Option<DbCycle> = db.create("cycle").content(content).await?;
    let db_cycle = db_cycle.ok_or_else(|| AppError::Internal("cycle was not created".into()))?;

    Ok((StatusCode::CREATED, Json(Cycle::try_from(db_cycle)?)))
}

pub async fn update_cycle(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
    Json(body): Json<UpdateCycleRequest>,
) -> Result<Json<Cycle>, AppError> {
    body.validate()?;

    let existing: Option<DbCycle> = db.select(("cycle", id.as_str())).await?;
    let existing = existing.ok_or_else(|| AppError::NotFound(format!("cycle {id} does not exist")))?;

    if existing.version != body.version {
        return Err(AppError::Conflict(
            "version mismatch — record was modified by another request".into(),
        ));
    }

    // Validate new recipient belongs to the same group and is not soft-deleted.
    if let Some(ref new_rid) = body.recipient_member_id {
        let recipient: Option<DbMember> = db.select(("member", new_rid.as_str())).await?;
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
            .bind(("gid", existing.group_id.clone()))
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
        recipient_member_id: body.recipient_member_id.clone().unwrap_or(existing.recipient_member_id),
        status: body.status.unwrap_or(existing.status),
        group_id: existing.group_id,
        notes: body.notes.or(existing.notes),
        created_at: existing.created_at,
        updated_at: now_iso(),
        version: existing.version + 1,
    };

    let updated: Option<DbCycle> = db.upsert(("cycle", id.as_str())).content(content).await?;
    let db_cycle = updated.ok_or_else(|| AppError::Internal("cycle update failed".into()))?;

    Ok(Json(Cycle::try_from(db_cycle)?))
}

pub async fn delete_cycle(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbCycle> = db.select(("cycle", id.as_str())).await?;
    if existing.is_none() {
        return Err(AppError::NotFound(format!("cycle {id} does not exist")));
    }

    // Check if cycle has payments.
    let payments: Vec<DbPayment> = db
        .query("SELECT * FROM payment WHERE cycle_id = $cid AND deleted_at IS NONE")
        .bind(("cid", id.clone()))
        .await?
        .take(0)?;

    if !payments.is_empty() {
        return Err(AppError::Conflict(
            "cannot delete cycle that has payments".into(),
        ));
    }

    // Hard delete for cycles (no soft delete per data model).
    db.delete::<Option<DbCycle>>(("cycle", id.as_str())).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Payment handlers ─────────────────────────────────────────────────────────

pub async fn create_payment(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Json(body): Json<CreatePaymentRequest>,
) -> Result<(StatusCode, Json<Payment>), AppError> {
    body.validate()?;

    let member: Option<DbMember> = db.select(("member", body.member_id.as_str())).await?;
    let member = member.ok_or_else(|| {
        AppError::NotFound(format!("member {} does not exist", body.member_id))
    })?;
    if member.deleted_at.is_some() {
        return Err(AppError::BadRequest(format!(
            "member {} has been deleted",
            body.member_id
        )));
    }
    let cycle: Option<DbCycle> = db.select(("cycle", body.cycle_id.as_str())).await?;
    let cycle = cycle.ok_or_else(|| {
        AppError::NotFound(format!("cycle {} does not exist", body.cycle_id))
    })?;

    if member.group_id != cycle.group_id {
        return Err(AppError::BadRequest(
            "member and cycle must belong to the same group".into(),
        ));
    }

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

    let db_payment: Option<DbPayment> = db.create("payment").content(content).await?;
    let db_payment = db_payment.ok_or_else(|| {
        error!("Create returned empty — payment may not have been persisted");
        AppError::Internal("payment was not created".into())
    })?;

    Ok((StatusCode::CREATED, Json(Payment::try_from(db_payment)?)))
}

pub async fn delete_payment(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path((member_id, cycle_id)): Path<(EntityId, EntityId)>,
) -> Result<StatusCode, AppError> {
    let rows: Vec<DbPayment> = db
        .query("SELECT * FROM payment WHERE member_id = $mid AND cycle_id = $cid AND deleted_at IS NONE")
        .bind(("mid", member_id.clone()))
        .bind(("cid", cycle_id.clone()))
        .await?
        .take(0)?;

    if rows.is_empty() {
        return Err(AppError::NotFound(format!(
            "no payment found for member {member_id} in cycle {cycle_id}"
        )));
    }

    let now = now_iso();
    for row in rows {
        let id = record_id_to_string(row.id.clone());
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
        let _: Option<DbPayment> = db.upsert(("payment", id.as_str())).content(content).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Admin Receipt handlers ───────────────────────────────────────────────────

/// Load a receipt by id, rejecting soft-deleted rows as 404.
async fn load_active_receipt(db: &DbConn, id: &str) -> Result<DbReceipt, AppError> {
    let row: Option<DbReceipt> = db.select(("receipt", id)).await?;
    let row = row.ok_or_else(|| AppError::NotFound(format!("receipt {id} does not exist")))?;
    if row.deleted_at.is_some() {
        return Err(AppError::NotFound(format!("receipt {id} does not exist")));
    }
    Ok(row)
}

fn receipt_content_from(row: &DbReceipt, status: &str, updated_at: String) -> ReceiptContent {
    ReceiptContent {
        whatsapp_message_id: row.whatsapp_message_id.clone(),
        group_id: row.group_id.clone(),
        chat_id: row.chat_id.clone(),
        sender_phone: row.sender_phone.clone(),
        member_id: row.member_id.clone(),
        cycle_id: row.cycle_id.clone(),
        extracted_amount: row.extracted_amount,
        expected_amount: row.expected_amount,
        amount_matches: row.amount_matches,
        status: status.into(),
        ocr_text: row.ocr_text.clone(),
        sender_label: row.sender_label.clone(),
        bank_label: row.bank_label.clone(),
        received_at: row.received_at.clone(),
        created_at: row.created_at.clone(),
        updated_at,
        deleted_at: row.deleted_at.clone(),
    }
}

pub async fn confirm_receipt(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<Json<Receipt>, AppError> {
    let receipt = load_active_receipt(&db, id.as_str()).await?;

    if receipt.status != "pending" {
        return Err(AppError::Conflict(format!(
            "receipt {id} is already {}",
            receipt.status
        )));
    }

    let member_id = receipt
        .member_id
        .clone()
        .ok_or_else(|| AppError::Conflict("receipt has no linked member".into()))?;
    let cycle_id = receipt
        .cycle_id
        .clone()
        .ok_or_else(|| AppError::Conflict("receipt has no linked cycle".into()))?;
    let amount = receipt
        .extracted_amount
        .ok_or_else(|| AppError::Conflict("receipt has no extracted amount".into()))?;

    // Verify member and cycle still exist and belong to the same group.
    let member: Option<DbMember> = db.select(("member", member_id.as_str())).await?;
    let member = member
        .ok_or_else(|| AppError::Conflict(format!("linked member {member_id} no longer exists")))?;
    if member.deleted_at.is_some() {
        return Err(AppError::Conflict(format!(
            "linked member {member_id} has been deleted"
        )));
    }
    let cycle: Option<DbCycle> = db.select(("cycle", cycle_id.as_str())).await?;
    let cycle = cycle
        .ok_or_else(|| AppError::Conflict(format!("linked cycle {cycle_id} no longer exists")))?;
    if member.group_id != cycle.group_id {
        return Err(AppError::Conflict(
            "linked member and cycle belong to different groups".into(),
        ));
    }

    // Reject duplicate confirmations for the same member+cycle.
    let existing: Vec<DbPayment> = db
        .query("SELECT * FROM payment WHERE member_id = $mid AND cycle_id = $cid AND deleted_at IS NONE")
        .bind(("mid", member_id.clone()))
        .bind(("cid", cycle_id.clone()))
        .await?
        .take(0)?;
    if !existing.is_empty() {
        return Err(AppError::Conflict(
            "a payment already exists for this member and cycle".into(),
        ));
    }

    let now = now_iso();
    let payment_date = receipt
        .received_at
        .get(..10)
        .unwrap_or(&receipt.received_at)
        .to_string();

    let payment_content = PaymentContent {
        member_id: member_id.clone(),
        cycle_id: cycle_id.clone(),
        amount,
        currency: "NGN".into(),
        payment_date,
        payment_method: Some("whatsapp_receipt".into()),
        reference: Some(receipt.whatsapp_message_id.clone()),
        confirmed_at: Some(now.clone()),
        confirmed_by: None,
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
    };

    let created: Option<DbPayment> = db.create("payment").content(payment_content).await?;
    created.ok_or_else(|| AppError::Internal("payment was not created".into()))?;

    let content = receipt_content_from(&receipt, "confirmed", now);
    let updated: Option<DbReceipt> = db.upsert(("receipt", id.as_str())).content(content).await?;
    let updated = updated.ok_or_else(|| AppError::Internal("receipt update failed".into()))?;

    Ok(Json(Receipt::try_from(updated)?))
}

pub async fn reject_receipt(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<Json<Receipt>, AppError> {
    let receipt = load_active_receipt(&db, id.as_str()).await?;

    if receipt.status != "pending" {
        return Err(AppError::Conflict(format!(
            "receipt {id} is already {}",
            receipt.status
        )));
    }

    let content = receipt_content_from(&receipt, "rejected", now_iso());
    let updated: Option<DbReceipt> = db.upsert(("receipt", id.as_str())).content(content).await?;
    let updated = updated.ok_or_else(|| AppError::Internal("receipt update failed".into()))?;

    Ok(Json(Receipt::try_from(updated)?))
}

// ── Admin WhatsApp link handlers ─────────────────────────────────────────────

pub async fn get_whatsapp_links(
    _auth: AdminToken,
    State(db): State<DbConn>,
) -> Result<Json<Vec<GroupLink>>, AppError> {
    let rows: Vec<DbGroupLink> = db.select("group_link").await?;
    let links: Vec<GroupLink> = rows
        .into_iter()
        .map(GroupLink::from)
        .filter(|l| l.deleted_at.is_none())
        .collect();
    Ok(Json(links))
}

pub async fn create_whatsapp_link(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Json(body): Json<CreateWhatsappLinkRequest>,
) -> Result<(StatusCode, Json<GroupLink>), AppError> {
    body.validate()?;

    let group_id = body.group_id.trim().to_string();
    let chat_id = body.chat_id.trim().to_string();

    // Verify group exists and is not soft-deleted.
    let group: Option<DbGroup> = db.select(("group", group_id.as_str())).await?;
    match &group {
        None => return Err(AppError::NotFound(format!("group {group_id} does not exist"))),
        Some(g) if g.deleted_at.is_some() => {
            return Err(AppError::NotFound(format!("group {group_id} does not exist")));
        }
        _ => {}
    }

    // Enforce 1:1 chat_id uniqueness over live (non-deleted) links.
    let dupes: Vec<DbGroupLink> = db
        .query("SELECT * FROM group_link WHERE chat_id = $cid AND deleted_at IS NONE")
        .bind(("cid", chat_id.clone()))
        .await?
        .take(0)?;
    if !dupes.is_empty() {
        return Err(AppError::Conflict(
            "a WhatsApp link already exists for this chatId".into(),
        ));
    }

    let now = now_iso();
    let content = GroupLinkContent {
        chat_id,
        group_id,
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
    };

    let created: Option<DbGroupLink> = db.create("group_link").content(content).await?;
    let created = created.ok_or_else(|| AppError::Internal("whatsapp link was not created".into()))?;

    Ok((StatusCode::CREATED, Json(GroupLink::from(created))))
}

pub async fn delete_whatsapp_link(
    _auth: AdminToken,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbGroupLink> = db.select(("group_link", id.as_str())).await?;
    let existing =
        existing.ok_or_else(|| AppError::NotFound(format!("whatsapp link {id} does not exist")))?;

    // Idempotent: if already soft-deleted, return 204 without mutating.
    // Matches the semantics of `delete_group` / `delete_member`.
    if existing.deleted_at.is_some() {
        return Ok(StatusCode::NO_CONTENT);
    }

    let now = now_iso();
    let content = GroupLinkContent {
        chat_id: existing.chat_id,
        group_id: existing.group_id,
        created_at: existing.created_at,
        updated_at: now.clone(),
        deleted_at: Some(now),
    };
    let _: Option<DbGroupLink> = db.upsert(("group_link", id.as_str())).content(content).await?;

    Ok(StatusCode::NO_CONTENT)
}

// ── Dev-only reset handler ───────────────────────────────────────────────────

pub async fn reset_db(State(db): State<DbConn>) -> Result<StatusCode, AppError> {
    reseed(&db).await?;
    Ok(StatusCode::OK)
}
