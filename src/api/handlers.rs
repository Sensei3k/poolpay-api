use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use surrealdb_types::SurrealValue;
use tracing::error;

use crate::auth::audit::record_auth_event;
use crate::auth::extractors::{AuthenticatedUser, GroupScopedAdmin, SuperAdminUser};
use crate::api::models::{
    AppError, CreateCycleRequest, CreateGroupRequest, CreateMemberRequest, CreatePaymentRequest,
    CreateWhatsappLinkRequest, Cycle, CycleContent, DbCycle, DbGroup, DbGroupLink, DbInboxItem,
    DbMember, DbPayment, DbReceipt, EntityId, Group, GroupContent, GroupLink, GroupLinkContent,
    InboxItemContent, InboxItemKind, Member, MemberContent, Payment, PaymentContent, Receipt,
    ReceiptContent, ReceiptStatus, UpdateCycleRequest, UpdateGroupRequest, UpdateMemberRequest,
    now_iso, record_id_to_string,
};
use crate::api::pagination::{
    header_u32, Pagination, PaginationParams, HEADER_LIMIT, HEADER_OFFSET, HEADER_TOTAL_COUNT,
};
use crate::db::{DbConn, reseed};

// ── Query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GroupsQuery {
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Debug, Deserialize)]
pub struct GroupIdQuery {
    #[serde(rename = "groupId")]
    pub group_id: Option<EntityId>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Debug, Deserialize)]
pub struct PaymentsQuery {
    #[serde(rename = "cycleId")]
    pub cycle_id: Option<EntityId>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

#[derive(Debug, Deserialize)]
pub struct ReceiptsQuery {
    #[serde(rename = "groupId")]
    pub group_id: Option<EntityId>,
    pub status: Option<String>,
    #[serde(flatten)]
    pub pagination: PaginationParams,
}

/// Build the standard `X-Total-Count` / `X-Limit` / `X-Offset` header
/// trio for a paginated list response. Centralised so every handler
/// emits the exact same casing.
fn pagination_headers(total: u32, page: Pagination) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(HEADER_TOTAL_COUNT, header_u32(total));
    headers.insert(HEADER_LIMIT, header_u32(page.limit));
    headers.insert(HEADER_OFFSET, header_u32(page.offset));
    headers
}

/// Wrapper used by handlers that need to bind a `count()` aggregate's
/// `count` column out of a SurrealDB response. Lives here (rather than
/// in `models`) because it's a query-shape concern, not a domain type.
#[derive(Debug, Deserialize, SurrealValue)]
struct CountRow {
    count: i64,
}

/// Pull the first `count()` aggregate out of a freshly-resolved query
/// response. Returns 0 when the aggregate yielded no rows (which is
/// what SurrealDB does for an empty `GROUP ALL`).
fn take_count(resp: &mut surrealdb::IndexedResults, idx: usize) -> Result<u32, AppError> {
    let rows: Vec<CountRow> = resp.take(idx)?;
    let total = rows.first().map(|r| r.count).unwrap_or(0);
    // Counts are non-negative by construction; clamp the impossible
    // negative branch to zero rather than over-reporting via wrap.
    Ok(u32::try_from(total.max(0)).unwrap_or(u32::MAX))
}

// ── Public GET handlers ──────────────────────────────────────────────────────

pub async fn get_groups(
    State(db): State<DbConn>,
    Query(params): Query<GroupsQuery>,
) -> Result<(HeaderMap, Json<Vec<Group>>), AppError> {
    let page = Pagination::from_params(&params.pagination)?;

    // One round-trip: count() + page query, indexed in declaration order.
    // The page query uses an explicit ORDER BY so offset pagination is
    // stable — without it the DB is free to reorder rows between calls,
    // which would make `?offset=` produce duplicate/missing items.
    let mut resp = db
        .query(
            "SELECT count() FROM group WHERE deleted_at IS NONE GROUP ALL; \
             SELECT * FROM group WHERE deleted_at IS NONE \
             ORDER BY created_at ASC, id ASC LIMIT $limit START $offset",
        )
        .bind(("limit", page.limit as i64))
        .bind(("offset", page.offset as i64))
        .await?;

    let total = take_count(&mut resp, 0)?;
    let rows: Vec<DbGroup> = resp.take(1)?;
    let groups: Result<Vec<Group>, AppError> = rows.into_iter().map(Group::try_from).collect();
    Ok((pagination_headers(total, page), Json(groups?)))
}

pub async fn get_members(
    State(db): State<DbConn>,
    Query(params): Query<GroupIdQuery>,
) -> Result<(HeaderMap, Json<Vec<Member>>), AppError> {
    let page = Pagination::from_params(&params.pagination)?;

    // The `WHERE` is shared between count and page so the X-Total-Count
    // reflects the total *matching* rows, not the table-wide total.
    let where_clause = match params.group_id {
        Some(_) => "deleted_at IS NONE AND group_id = $gid",
        None => "deleted_at IS NONE",
    };
    let sql = format!(
        "SELECT count() FROM member WHERE {where_clause} GROUP ALL; \
         SELECT * FROM member WHERE {where_clause} \
         ORDER BY created_at ASC, id ASC LIMIT $limit START $offset"
    );

    let mut q = db
        .query(sql)
        .bind(("limit", page.limit as i64))
        .bind(("offset", page.offset as i64));
    if let Some(gid) = params.group_id {
        q = q.bind(("gid", gid));
    }
    let mut resp = q.await?;
    let total = take_count(&mut resp, 0)?;
    let rows: Vec<DbMember> = resp.take(1)?;
    let members: Result<Vec<Member>, AppError> = rows.into_iter().map(Member::try_from).collect();
    Ok((pagination_headers(total, page), Json(members?)))
}

pub async fn get_cycles(
    State(db): State<DbConn>,
    Query(params): Query<GroupIdQuery>,
) -> Result<(HeaderMap, Json<Vec<Cycle>>), AppError> {
    let page = Pagination::from_params(&params.pagination)?;

    // Cycles are hard-deleted (no `deleted_at`), so the only optional
    // predicate is `group_id`. The two-statement `count() + select`
    // shape mirrors the other handlers for uniformity.
    let (count_sql, page_sql) = match params.group_id.as_ref() {
        Some(_) => (
            "SELECT count() FROM cycle WHERE group_id = $gid GROUP ALL".to_string(),
            "SELECT * FROM cycle WHERE group_id = $gid \
             ORDER BY created_at ASC, id ASC LIMIT $limit START $offset"
                .to_string(),
        ),
        None => (
            "SELECT count() FROM cycle GROUP ALL".to_string(),
            "SELECT * FROM cycle ORDER BY created_at ASC, id ASC LIMIT $limit START $offset"
                .to_string(),
        ),
    };
    let sql = format!("{count_sql}; {page_sql}");

    let mut q = db
        .query(sql)
        .bind(("limit", page.limit as i64))
        .bind(("offset", page.offset as i64));
    if let Some(gid) = params.group_id {
        q = q.bind(("gid", gid));
    }
    let mut resp = q.await?;
    let total = take_count(&mut resp, 0)?;
    let rows: Vec<DbCycle> = resp.take(1)?;
    let cycles: Result<Vec<Cycle>, AppError> = rows.into_iter().map(Cycle::try_from).collect();
    Ok((pagination_headers(total, page), Json(cycles?)))
}

pub async fn get_payments(
    State(db): State<DbConn>,
    Query(params): Query<PaymentsQuery>,
) -> Result<(HeaderMap, Json<Vec<Payment>>), AppError> {
    let page = Pagination::from_params(&params.pagination)?;

    let where_clause = match params.cycle_id {
        Some(_) => "deleted_at IS NONE AND cycle_id = $cid",
        None => "deleted_at IS NONE",
    };
    let sql = format!(
        "SELECT count() FROM payment WHERE {where_clause} GROUP ALL; \
         SELECT * FROM payment WHERE {where_clause} \
         ORDER BY created_at ASC, id ASC LIMIT $limit START $offset"
    );

    let mut q = db
        .query(sql)
        .bind(("limit", page.limit as i64))
        .bind(("offset", page.offset as i64));
    if let Some(cid) = params.cycle_id {
        q = q.bind(("cid", cid));
    }
    let mut resp = q.await?;
    let total = take_count(&mut resp, 0)?;
    let rows: Vec<DbPayment> = resp.take(1)?;
    let payments: Result<Vec<Payment>, AppError> =
        rows.into_iter().map(Payment::try_from).collect();
    Ok((pagination_headers(total, page), Json(payments?)))
}

pub async fn get_receipts(
    State(db): State<DbConn>,
    Query(params): Query<ReceiptsQuery>,
) -> Result<(HeaderMap, Json<Vec<Receipt>>), AppError> {
    // Validate status filter up-front so an unknown value returns 400
    // rather than silently producing an empty list.
    let status_filter: Option<ReceiptStatus> = match params.status.as_deref() {
        None => None,
        Some(s) => Some(s.parse::<ReceiptStatus>().map_err(AppError::BadRequest)?),
    };

    let page = Pagination::from_params(&params.pagination)?;

    // Build the WHERE clause dynamically based on which optional
    // filters are present. The base predicate (`deleted_at IS NONE`) is
    // always applied; `group_id` and `status` join with AND when
    // supplied. The same WHERE drives both the count and the page so
    // X-Total-Count reflects the filtered total.
    let mut where_clause = String::from("deleted_at IS NONE");
    if params.group_id.is_some() {
        where_clause.push_str(" AND group_id = $gid");
    }
    if status_filter.is_some() {
        where_clause.push_str(" AND status = $status");
    }
    let sql = format!(
        "SELECT count() FROM receipt WHERE {where_clause} GROUP ALL; \
         SELECT * FROM receipt WHERE {where_clause} \
         ORDER BY received_at ASC, id ASC LIMIT $limit START $offset"
    );

    let mut q = db
        .query(sql)
        .bind(("limit", page.limit as i64))
        .bind(("offset", page.offset as i64));
    if let Some(gid) = params.group_id {
        q = q.bind(("gid", gid));
    }
    if let Some(s) = status_filter {
        // Persist the canonical lowercase form so the WHERE matches the
        // stored value (`status: "pending" | "confirmed" | "rejected"`).
        let stored = match s {
            ReceiptStatus::Pending => "pending",
            ReceiptStatus::Confirmed => "confirmed",
            ReceiptStatus::Rejected => "rejected",
            ReceiptStatus::Flagged => "flagged",
        };
        q = q.bind(("status", stored.to_string()));
    }
    let mut resp = q.await?;
    let total = take_count(&mut resp, 0)?;
    let rows: Vec<DbReceipt> = resp.take(1)?;
    let receipts: Result<Vec<Receipt>, AppError> =
        rows.into_iter().map(Receipt::try_from).collect();
    Ok((pagination_headers(total, page), Json(receipts?)))
}

// ── Admin Group handlers ─────────────────────────────────────────────────────

pub async fn create_group(
    _auth: SuperAdminUser,
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
    _auth: SuperAdminUser,
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
    _auth: SuperAdminUser,
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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(group_id): Path<EntityId>,
    Json(body): Json<CreateMemberRequest>,
) -> Result<(StatusCode, Json<Member>), AppError> {
    let _auth = GroupScopedAdmin::ensure(user, group_id.as_str(), &db).await?;
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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
    Json(body): Json<UpdateMemberRequest>,
) -> Result<Json<Member>, AppError> {
    body.validate()?;

    let existing: Option<DbMember> = db.select(("member", id.as_str())).await?;
    let _auth = GroupScopedAdmin::ensure_or_deny(
        user,
        existing.as_ref().map(|m| m.group_id.as_str()),
        &db,
        AppError::NotFound(format!("member {id} does not exist")),
    )
    .await?;
    let existing = existing.expect("ensure_or_deny returns missing_err when None");

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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbMember> = db.select(("member", id.as_str())).await?;
    let _auth = GroupScopedAdmin::ensure_or_deny(
        user,
        existing.as_ref().map(|m| m.group_id.as_str()),
        &db,
        AppError::NotFound(format!("member {id} does not exist")),
    )
    .await?;
    let existing = existing.expect("ensure_or_deny returns missing_err when None");

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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(group_id): Path<EntityId>,
    Json(body): Json<CreateCycleRequest>,
) -> Result<(StatusCode, Json<Cycle>), AppError> {
    let _auth = GroupScopedAdmin::ensure(user, group_id.as_str(), &db).await?;
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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
    Json(body): Json<UpdateCycleRequest>,
) -> Result<Json<Cycle>, AppError> {
    body.validate()?;

    let existing: Option<DbCycle> = db.select(("cycle", id.as_str())).await?;
    let _auth = GroupScopedAdmin::ensure_or_deny(
        user,
        existing.as_ref().map(|c| c.group_id.as_str()),
        &db,
        AppError::NotFound(format!("cycle {id} does not exist")),
    )
    .await?;
    let existing = existing.expect("ensure_or_deny returns missing_err when None");

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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<StatusCode, AppError> {
    let existing: Option<DbCycle> = db.select(("cycle", id.as_str())).await?;
    let _auth = GroupScopedAdmin::ensure_or_deny(
        user,
        existing.as_ref().map(|c| c.group_id.as_str()),
        &db,
        AppError::NotFound(format!("cycle {id} does not exist")),
    )
    .await?;

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
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Json(body): Json<CreatePaymentRequest>,
) -> Result<(StatusCode, Json<Payment>), AppError> {
    body.validate()?;

    // Load the member first, then gate on its group *before* any other
    // existence/state checks. Any earlier ordering lets a non-scoped
    // admin enumerate members, soft-delete state, cycles, and cross-group
    // combinations across every tenant by flipping ids in the body.
    let member: Option<DbMember> = db.select(("member", body.member_id.as_str())).await?;
    let _auth = GroupScopedAdmin::ensure_or_deny(
        user,
        member.as_ref().map(|m| m.group_id.as_str()),
        &db,
        AppError::NotFound(format!("member {} does not exist", body.member_id)),
    )
    .await?;
    let member = member.expect("ensure_or_deny returns missing_err when None");

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
        rejected_by: None,
        deleted_by: None,
    };

    let db_payment: Option<DbPayment> = db.create("payment").content(content).await?;
    let db_payment = db_payment.ok_or_else(|| {
        error!("Create returned empty — payment may not have been persisted");
        AppError::Internal("payment was not created".into())
    })?;

    Ok((StatusCode::CREATED, Json(Payment::try_from(db_payment)?)))
}

pub async fn delete_payment(
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path((member_id, cycle_id)): Path<(EntityId, EntityId)>,
) -> Result<StatusCode, AppError> {
    // Resolve the group through the cycle so `GroupScopedAdmin` can gate
    // the delete before any mutation or existence response. Missing cycles
    // return an opaque 403 to non-super-admins to avoid leaking which
    // cycle ids exist across groups.
    let cycle: Option<DbCycle> = db.select(("cycle", cycle_id.as_str())).await?;
    let auth = GroupScopedAdmin::ensure_or_deny(
        user,
        cycle.as_ref().map(|c| c.group_id.as_str()),
        &db,
        AppError::NotFound(format!("cycle {cycle_id} does not exist")),
    )
    .await?;

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
            rejected_by: row.rejected_by,
            deleted_by: Some(auth.0.user_id.clone()),
        };
        let _: Option<DbPayment> = db.upsert(("payment", id.as_str())).content(content).await?;
    }

    Ok(StatusCode::NO_CONTENT)
}

// ── Admin Receipt handlers ───────────────────────────────────────────────────

/// Load a receipt by id, treating soft-deleted rows as absent.
async fn load_active_receipt_opt(db: &DbConn, id: &str) -> Result<Option<DbReceipt>, AppError> {
    let row: Option<DbReceipt> = db.select(("receipt", id)).await?;
    Ok(row.filter(|r| r.deleted_at.is_none()))
}

/// Optional new fields to set on the receipt row when transitioning state.
/// Used by the slice 5 PATCH endpoint to attach a `rejection_reason`
/// without disturbing any other column.
#[derive(Default)]
struct ReceiptPatchFields {
    rejection_reason: Option<String>,
}

fn receipt_content_from(
    row: &DbReceipt,
    status: &str,
    updated_at: String,
    confirmed_by: Option<String>,
    rejected_by: Option<String>,
    patch: ReceiptPatchFields,
) -> ReceiptContent {
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
        raw_image_url: row.raw_image_url.clone(),
        // `None` on the patch means "keep prior value"; a `Some` overrides it.
        rejection_reason: patch.rejection_reason.or_else(|| row.rejection_reason.clone()),
        received_at: row.received_at.clone(),
        created_at: row.created_at.clone(),
        updated_at,
        deleted_at: row.deleted_at.clone(),
        confirmed_by,
        rejected_by,
        deleted_by: row.deleted_by.clone(),
    }
}

// Slice 5 PATCH dispatch ------------------------------------------------------

/// Body for the unified `PATCH /api/receipts/{id}` action endpoint.
///
/// The discriminator lives in `action` rather than the URL so the FE can
/// queue a single optimistic mutation per row regardless of which
/// terminal state the admin chose. `reason` is meaningful only for
/// reject/flag and must NEVER carry PII (no phone, no member name, no
/// OCR text) — the audit row writes a short non-PII tag derived from it.
#[derive(Debug, Deserialize)]
pub struct PatchReceiptRequest {
    pub action: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

/// Cap on the size of an admin-supplied reject/flag reason. The DB column
/// has no constraint (legacy rows are open-ended), so the cap lives here
/// at the API boundary to keep a runaway string from bloating audit
/// queries.
const MAX_RECEIPT_REASON_LEN: usize = 280;

/// Audit event slugs for receipt actions. Centralised so spelling drift
/// across handler + tests cannot mask a coverage gap.
const EVT_RECEIPT_CONFIRMED: &str = "receipt_confirmed";
const EVT_RECEIPT_REJECTED: &str = "receipt_rejected";
const EVT_RECEIPT_FLAGGED: &str = "receipt_flagged";

/// Trim and length-cap the admin-supplied reason. Returns `None` when the
/// input is empty, white-space only, or absent. An over-long reason is a
/// hard 400 so the FE does not silently truncate a justification.
fn sanitise_reason(reason: Option<String>) -> Result<Option<String>, AppError> {
    match reason {
        None => Ok(None),
        Some(s) => {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                return Ok(None);
            }
            if trimmed.len() > MAX_RECEIPT_REASON_LEN {
                return Err(AppError::BadRequest(format!(
                    "reason must be {MAX_RECEIPT_REASON_LEN} characters or fewer"
                )));
            }
            Ok(Some(trimmed.to_string()))
        }
    }
}

/// Unified action dispatcher. The legacy POST `/api/admin/receipts/{id}/{confirm,reject}`
/// routes stay alive and delegate to the same `_inner` helpers, so this
/// endpoint and the legacy routes cannot diverge.
pub async fn patch_receipt(
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
    Json(body): Json<PatchReceiptRequest>,
) -> Result<Json<Receipt>, AppError> {
    let action = body
        .action
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::BadRequest("action is required".into()))?;
    let reason = sanitise_reason(body.reason)?;

    match action {
        "confirm" => {
            // `confirm` does not record a reason. Rejecting non-empty reason
            // up front catches FE bugs that mis-route a reject body.
            if reason.is_some() {
                return Err(AppError::BadRequest(
                    "reason is not allowed for the 'confirm' action".into(),
                ));
            }
            confirm_receipt_inner(user, &db, &id).await
        }
        "reject" => reject_receipt_inner(user, &db, &id, reason).await,
        "flag" => flag_receipt_inner(user, &db, &id, reason).await,
        other => Err(AppError::BadRequest(format!(
            "unknown action '{other}'; must be one of confirm, reject, flag"
        ))),
    }
}

// Legacy POST routes ----------------------------------------------------------

pub async fn confirm_receipt(
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<Json<Receipt>, AppError> {
    confirm_receipt_inner(user, &db, &id).await
}

pub async fn reject_receipt(
    user: AuthenticatedUser,
    State(db): State<DbConn>,
    Path(id): Path<EntityId>,
) -> Result<Json<Receipt>, AppError> {
    reject_receipt_inner(user, &db, &id, None).await
}

// Action handlers -------------------------------------------------------------
//
// Each `_inner` function performs:
//   1. opaque auth via `GroupScopedAdmin::ensure_or_deny` (so a non-scoped
//      admin cannot distinguish "no such id" from "wrong group");
//   2. the state transition (`pending -> confirmed/rejected/flagged`);
//   3. any side effects (confirm creates a Payment, then an inbox item);
//   4. an `auth_event` audit row attributing the change to the actor.
//
// Explicit post-auth validation branches (wrong status, missing member,
// missing cycle, duplicate payment) emit
// `record_auth_event(..., success=false, reason=Some(tag))` before
// returning, so those rejection branches are traceable. Pre-auth
// failures from `GroupScopedAdmin::ensure_or_deny` and any
// `?`-propagated DB errors return without an audit row — the auth
// extractor and DB layers own their own observability.

async fn confirm_receipt_inner(
    user: AuthenticatedUser,
    db: &DbConn,
    id: &EntityId,
) -> Result<Json<Receipt>, AppError> {
    let receipt = load_active_receipt_opt(db, id.as_str()).await?;
    let auth = GroupScopedAdmin::ensure_or_deny(
        user,
        receipt.as_ref().map(|r| r.group_id.as_str()),
        db,
        AppError::NotFound(format!("receipt {id} does not exist")),
    )
    .await?;
    let receipt = receipt.expect("ensure_or_deny returns missing_err when None");
    let actor_id = auth.0.user_id.clone();

    if receipt.status != "pending" {
        record_auth_event(
            db,
            None,
            Some(actor_id.clone()),
            EVT_RECEIPT_CONFIRMED,
            false,
            Some("not_pending"),
            None,
        )
        .await;
        return Err(AppError::Conflict(format!(
            "receipt {id} is already {}",
            receipt.status
        )));
    }

    let member_id = match receipt.member_id.clone() {
        Some(m) => m,
        None => {
            record_auth_event(
                db,
                None,
                Some(actor_id),
                EVT_RECEIPT_CONFIRMED,
                false,
                Some("no_member"),
                None,
            )
            .await;
            return Err(AppError::Conflict("receipt has no linked member".into()));
        }
    };
    let cycle_id = match receipt.cycle_id.clone() {
        Some(c) => c,
        None => {
            record_auth_event(
                db,
                None,
                Some(actor_id),
                EVT_RECEIPT_CONFIRMED,
                false,
                Some("no_cycle"),
                None,
            )
            .await;
            return Err(AppError::Conflict("receipt has no linked cycle".into()));
        }
    };
    let amount = match receipt.extracted_amount {
        Some(a) => a,
        None => {
            record_auth_event(
                db,
                None,
                Some(actor_id),
                EVT_RECEIPT_CONFIRMED,
                false,
                Some("no_amount"),
                None,
            )
            .await;
            return Err(AppError::Conflict("receipt has no extracted amount".into()));
        }
    };

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
    #[derive(Debug, Deserialize, SurrealValue)]
    struct ExistingPaymentId {
        #[allow(dead_code)]
        id: surrealdb::types::RecordId,
    }
    let existing: Vec<ExistingPaymentId> = db
        .query(
            "SELECT id FROM payment WHERE member_id = $mid AND cycle_id = $cid AND deleted_at IS NONE LIMIT 1",
        )
        .bind(("mid", member_id.clone()))
        .bind(("cid", cycle_id.clone()))
        .await?
        .take(0)?;
    if !existing.is_empty() {
        record_auth_event(
            db,
            None,
            Some(actor_id),
            EVT_RECEIPT_CONFIRMED,
            false,
            Some("duplicate_payment"),
            None,
        )
        .await;
        return Err(AppError::Conflict(
            "a payment already exists for this member and cycle".into(),
        ));
    }

    let now = now_iso();
    let payment_date = chrono::DateTime::parse_from_rfc3339(&receipt.received_at)
        .map(|dt| dt.format("%Y-%m-%d").to_string())
        .map_err(|_| {
            AppError::Conflict(format!(
                "receipt {id} has an invalid received_at timestamp"
            ))
        })?;

    let payment_content = PaymentContent {
        member_id: member_id.clone(),
        cycle_id: cycle_id.clone(),
        amount,
        currency: "NGN".into(),
        payment_date,
        payment_method: Some("whatsapp_receipt".into()),
        reference: Some(receipt.whatsapp_message_id.clone()),
        confirmed_at: Some(now.clone()),
        confirmed_by: Some(actor_id.clone()),
        created_at: now.clone(),
        updated_at: now.clone(),
        deleted_at: None,
        rejected_by: None,
        deleted_by: None,
    };

    let created: Option<DbPayment> = db.create("payment").content(payment_content).await?;
    created.ok_or_else(|| AppError::Internal("payment was not created".into()))?;

    let content = receipt_content_from(
        &receipt,
        "confirmed",
        now.clone(),
        Some(actor_id.clone()),
        receipt.rejected_by.clone(),
        ReceiptPatchFields::default(),
    );
    let updated: Option<DbReceipt> = db.upsert(("receipt", id.as_str())).content(content).await?;
    let updated = updated.ok_or_else(|| AppError::Internal("receipt update failed".into()))?;

    // HANDOFF §5.1: matched member gets a `receipt_confirmed` inbox item.
    // The inbox row sources from the `member.user_id` link when available;
    // until BE auth and membership are joined (separate ticket), the
    // recipient `user_id` is the matched member id itself so the FE has
    // something to render and tests can assert the row's presence.
    //
    // SECURITY: `user_id` here is the matched member id from the receipt,
    // not an authenticated session id. Future endpoints listing inbox items
    // by `user_id` MUST NOT treat this column as an authenticated user
    // identity. The auth and membership join lands in a follow-up; do not
    // consume this column as a session principal until it does.
    let receipt_id_str = record_id_to_string(updated.id.clone());
    write_inbox_item(
        db,
        &member_id,
        InboxItemKind::ReceiptConfirmed,
        "Receipt confirmed",
        "Your payment was confirmed by an admin.",
        Some(&updated.group_id),
        updated.cycle_id.as_deref(),
        Some(&receipt_id_str),
        &now,
    )
    .await;

    record_auth_event(
        db,
        None,
        Some(actor_id),
        EVT_RECEIPT_CONFIRMED,
        true,
        None,
        None,
    )
    .await;

    Ok(Json(Receipt::try_from(updated)?))
}

async fn reject_receipt_inner(
    user: AuthenticatedUser,
    db: &DbConn,
    id: &EntityId,
    reason: Option<String>,
) -> Result<Json<Receipt>, AppError> {
    transition_receipt(user, db, id, "rejected", EVT_RECEIPT_REJECTED, reason).await
}

async fn flag_receipt_inner(
    user: AuthenticatedUser,
    db: &DbConn,
    id: &EntityId,
    reason: Option<String>,
) -> Result<Json<Receipt>, AppError> {
    transition_receipt(user, db, id, "flagged", EVT_RECEIPT_FLAGGED, reason).await
}

/// Shared body for the two non-confirming actions. Reject and flag share
/// every step (auth, state check, reason persist, inbox item, audit), so
/// only the stored status and audit slug differ — extracting the common
/// shape keeps the two from drifting apart.
async fn transition_receipt(
    user: AuthenticatedUser,
    db: &DbConn,
    id: &EntityId,
    new_status: &str,
    audit_event: &'static str,
    reason: Option<String>,
) -> Result<Json<Receipt>, AppError> {
    let receipt = load_active_receipt_opt(db, id.as_str()).await?;
    let auth = GroupScopedAdmin::ensure_or_deny(
        user,
        receipt.as_ref().map(|r| r.group_id.as_str()),
        db,
        AppError::NotFound(format!("receipt {id} does not exist")),
    )
    .await?;
    let receipt = receipt.expect("ensure_or_deny returns missing_err when None");
    let actor_id = auth.0.user_id.clone();

    if receipt.status != "pending" {
        record_auth_event(
            db,
            None,
            Some(actor_id.clone()),
            audit_event,
            false,
            Some("not_pending"),
            None,
        )
        .await;
        return Err(AppError::Conflict(format!(
            "receipt {id} is already {}",
            receipt.status
        )));
    }

    let content = receipt_content_from(
        &receipt,
        new_status,
        now_iso(),
        receipt.confirmed_by.clone(),
        Some(actor_id.clone()),
        ReceiptPatchFields {
            rejection_reason: reason.clone(),
        },
    );
    let updated: Option<DbReceipt> = db.upsert(("receipt", id.as_str())).content(content).await?;
    let updated = updated.ok_or_else(|| AppError::Internal("receipt update failed".into()))?;

    // Notify the matched member (if any) so they know the admin took
    // action against their receipt. Reject and flag both yield an
    // `admin_message` since the FE renders both as "needs your
    // attention" rather than a payment confirmation.
    if let Some(matched_member_id) = updated.member_id.as_ref() {
        let title = if new_status == "flagged" {
            "Receipt flagged for review"
        } else {
            "Receipt rejected"
        };
        let body = match reason.as_deref() {
            Some(r) => format!("An admin marked this receipt as {new_status}: {r}"),
            None => format!("An admin marked this receipt as {new_status}."),
        };
        let receipt_id_str = record_id_to_string(updated.id.clone());
        write_inbox_item(
            db,
            matched_member_id,
            InboxItemKind::AdminMessage,
            title,
            &body,
            Some(&updated.group_id),
            updated.cycle_id.as_deref(),
            Some(&receipt_id_str),
            &updated.updated_at,
        )
        .await;
    }

    record_auth_event(
        db,
        None,
        Some(actor_id),
        audit_event,
        true,
        None,
        None,
    )
    .await;

    Ok(Json(Receipt::try_from(updated)?))
}

/// Best-effort inbox row writer. Failures are logged and swallowed:
/// surfacing a 500 to the admin after the state transition has already
/// committed would corrupt the user-visible audit story. The FE polls
/// the inbox, so a missed write is recoverable; the audit row is the
/// load-bearing record.
#[allow(clippy::too_many_arguments)]
async fn write_inbox_item(
    db: &DbConn,
    user_id: &str,
    kind: InboxItemKind,
    title: &str,
    body: &str,
    pool_id: Option<&str>,
    cycle_id: Option<&str>,
    receipt_id: Option<&str>,
    created_at: &str,
) {
    // SECURITY: `user_id` here is the matched member id from the receipt,
    // not an authenticated session id. Future endpoints listing inbox items
    // by `user_id` MUST NOT treat this column as an authenticated user
    // identity. The auth and membership join lands in a follow-up; do not
    // consume this column as a session principal until it does.
    let content = InboxItemContent {
        user_id: user_id.to_string(),
        kind: kind.as_str().to_string(),
        title: title.to_string(),
        body: body.to_string(),
        pool_id: pool_id.map(str::to_string),
        cycle_id: cycle_id.map(str::to_string),
        receipt_id: receipt_id.map(str::to_string),
        read_at: None,
        created_at: created_at.to_string(),
    };
    if let Err(e) = db
        .create::<Option<DbInboxItem>>("inbox_item")
        .content(content)
        .await
    {
        tracing::warn!(error = %e, user_id, "inbox_item insert failed");
    }
}

// ── Admin WhatsApp link handlers ─────────────────────────────────────────────

pub async fn get_whatsapp_links(
    _auth: SuperAdminUser,
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
    _auth: SuperAdminUser,
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
    _auth: SuperAdminUser,
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
