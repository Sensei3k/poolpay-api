//! Receipt-routing helpers used by the WhatsApp ingestion pipeline.
//!
//! These functions translate facts about an incoming WhatsApp message
//! (chat id, sender phone, message id) into the PoolPay entities the
//! pipeline needs (group, member, active cycle, prior receipt). They are
//! pure DB lookups — no Green API or HTTP dependencies — so the pipeline
//! can be assembled and tested in isolation.

use crate::api::models::{AppError, DbCycle, DbGroup, DbGroupLink, DbMember, DbReceipt, EntityId};
use crate::db::DbConn;

/// Resolve an incoming WhatsApp `chat_id` to its linked PoolPay group.
///
/// Returns `None` when no live link exists for the chat, the link points
/// at a non-existent group, or the linked group has been soft-deleted.
pub async fn find_group_by_chat_id(
    db: &DbConn,
    chat_id: &str,
) -> Result<Option<DbGroup>, AppError> {
    let links: Vec<DbGroupLink> = db
        .query("SELECT * FROM group_link WHERE chat_id = $cid AND deleted_at IS NONE LIMIT 1")
        .bind(("cid", chat_id.to_string()))
        .await?
        .take(0)?;

    let Some(link) = links.into_iter().next() else {
        return Ok(None);
    };

    let group: Option<DbGroup> = db.select(("group", link.group_id.as_str())).await?;
    Ok(group.filter(|g| g.deleted_at.is_none()))
}

/// Find the active member in `group_id` whose stored phone matches `phone`.
///
/// Phone comparison is exact; canonicalisation is the caller's job, since
/// WhatsApp delivers numbers as raw E.164-style digits and admin input is
/// already trimmed when stored.
pub async fn find_member_by_phone(
    db: &DbConn,
    group_id: &EntityId,
    phone: &str,
) -> Result<Option<DbMember>, AppError> {
    let rows: Vec<DbMember> = db
        .query(
            "SELECT * FROM member \
             WHERE group_id = $gid AND phone = $phone AND deleted_at IS NONE LIMIT 1",
        )
        .bind(("gid", group_id.clone()))
        .bind(("phone", phone.to_string()))
        .await?
        .take(0)?;

    Ok(rows.into_iter().next())
}

/// Return the single active cycle for `group_id`, if one exists.
///
/// Cycles do not carry `deleted_at`, but only one cycle per group should
/// hold `status = 'active'` at a time. If the invariant is violated this
/// returns the first row deterministically — the caller is expected to
/// surface the inconsistency separately.
pub async fn find_active_cycle(
    db: &DbConn,
    group_id: &EntityId,
) -> Result<Option<DbCycle>, AppError> {
    let rows: Vec<DbCycle> = db
        .query(
            "SELECT * FROM cycle \
             WHERE group_id = $gid AND status = 'active' LIMIT 1",
        )
        .bind(("gid", group_id.clone()))
        .await?
        .take(0)?;

    Ok(rows.into_iter().next())
}

/// Look up a previously ingested receipt by its WhatsApp message id.
///
/// Soft-deleted rows are excluded so a re-ingestion after admin cleanup
/// is not blocked by a tombstone. Confirmed and rejected rows still
/// count as duplicates: the pipeline should refuse to re-process them.
pub async fn find_receipt_by_message_id(
    db: &DbConn,
    whatsapp_message_id: &str,
) -> Result<Option<DbReceipt>, AppError> {
    let rows: Vec<DbReceipt> = db
        .query(
            "SELECT * FROM receipt \
             WHERE whatsapp_message_id = $mid AND deleted_at IS NONE LIMIT 1",
        )
        .bind(("mid", whatsapp_message_id.to_string()))
        .await?
        .take(0)?;

    Ok(rows.into_iter().next())
}
