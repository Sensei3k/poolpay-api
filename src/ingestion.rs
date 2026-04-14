//! Receipt ingestion pipeline.
//!
//! Takes the facts from a processed WhatsApp message (chat, sender phone,
//! message id, OCR text, parsed fields) and produces either a persisted
//! `receipt` row or a reason the message was dropped. This module owns the
//! routing decisions; Green API polling and quoted-reply formatting live
//! elsewhere so the pipeline can be exercised without network I/O.

use tracing::info;

use crate::api::models::{AppError, EntityId, ReceiptContent, now_iso};
use crate::db::DbConn;
use crate::models::ParsedReceipt;
use crate::parser;
use crate::routing;

/// Tolerance applied when comparing an extracted amount to the cycle's
/// expected contribution. OCR frequently drops a naira or two on noisy
/// images, so a 1 NGN (100 kobo) window protects against false rejects
/// without hiding genuine underpayments.
const AMOUNT_MATCH_TOLERANCE_KOBO: i64 = 100;

/// Inputs gathered by the polling loop for a single incoming receipt.
pub struct IngestionInput<'a> {
    pub chat_id: &'a str,
    pub sender_phone: &'a str,
    pub message_id: &'a str,
    pub ocr_text: &'a str,
    pub parsed: &'a ParsedReceipt,
    pub received_at: String,
}

/// What happened with the ingestion attempt. Carries everything the reply
/// layer (PR-next) needs to decide which quoted response to send.
#[derive(Debug, Clone)]
pub enum IngestionOutcome {
    /// No group is linked to this chat — nothing to attach the receipt to.
    NotLinked,
    /// The same WhatsApp message id was already ingested; treated as a
    /// duplicate regardless of the prior receipt's status.
    DuplicateMessage,
    /// The receipt was persisted. Member, cycle, and amount fields may all
    /// be absent depending on how much context was resolvable.
    Ingested(IngestedReceipt),
}

#[derive(Debug, Clone)]
pub struct IngestedReceipt {
    pub receipt_id: String,
    pub group_id: EntityId,
    pub member_matched: bool,
    pub cycle_matched: bool,
    pub extracted_amount: Option<i64>,
    pub expected_amount: Option<i64>,
    pub amount_matches: Option<bool>,
}

/// Run the ingestion pipeline. Returns an outcome the caller can log or
/// translate into a WhatsApp reply.
pub async fn ingest_receipt(
    db: &DbConn,
    input: IngestionInput<'_>,
) -> Result<IngestionOutcome, AppError> {
    let Some(group) = routing::find_group_by_chat_id(db, input.chat_id).await? else {
        info!(chat_id = input.chat_id, "Ingestion skipped: chat not linked to a group");
        return Ok(IngestionOutcome::NotLinked);
    };
    let group_id = crate::api::models::record_id_to_string(group.id);

    if routing::find_receipt_by_message_id(db, input.message_id)
        .await?
        .is_some()
    {
        info!(message_id = input.message_id, "Ingestion skipped: duplicate message id");
        return Ok(IngestionOutcome::DuplicateMessage);
    }

    let sender_phone = strip_jid(input.sender_phone).to_string();

    let member_id = routing::find_member_by_phone(db, &group_id, &sender_phone)
        .await?
        .map(|m| crate::api::models::record_id_to_string(m.id));

    let cycle = routing::find_active_cycle(db, &group_id).await?;
    let expected_amount = cycle.as_ref().map(|c| c.contribution_per_member);
    let cycle_id = cycle.map(|c| crate::api::models::record_id_to_string(c.id));

    let extracted_amount = input
        .parsed
        .amount
        .as_deref()
        .and_then(parser::parse_amount_to_kobo);

    let amount_matches = match (extracted_amount, expected_amount) {
        (Some(got), Some(want)) => Some((got - want).abs() <= AMOUNT_MATCH_TOLERANCE_KOBO),
        _ => None,
    };

    let now = now_iso();
    let content = ReceiptContent {
        whatsapp_message_id: input.message_id.to_string(),
        group_id: group_id.clone(),
        chat_id: input.chat_id.to_string(),
        sender_phone,
        member_id: member_id.clone(),
        cycle_id: cycle_id.clone(),
        extracted_amount,
        expected_amount,
        amount_matches,
        status: "pending".to_string(),
        ocr_text: Some(input.ocr_text.to_string()),
        sender_label: input.parsed.sender.clone(),
        bank_label: input.parsed.bank.clone(),
        received_at: input.received_at,
        created_at: now.clone(),
        updated_at: now,
        deleted_at: None,
    };

    // `create` returns the inserted row(s) so we can surface the generated id.
    let created: Option<crate::api::models::DbReceipt> =
        db.create("receipt").content(content).await?;
    let receipt_id = created
        .map(|r| crate::api::models::record_id_to_string(r.id))
        .ok_or_else(|| AppError::Internal("Failed to persist receipt".to_string()))?;

    info!(
        receipt_id = %receipt_id,
        group_id = %group_id,
        member_matched = member_id.is_some(),
        cycle_matched = cycle_id.is_some(),
        "Receipt ingested"
    );

    Ok(IngestionOutcome::Ingested(IngestedReceipt {
        receipt_id,
        group_id,
        member_matched: member_id.is_some(),
        cycle_matched: cycle_id.is_some(),
        extracted_amount,
        expected_amount,
        amount_matches,
    }))
}

/// WhatsApp delivers sender/chat ids as JIDs like `2348012345678@c.us`.
/// Member records store only the digits, so strip everything from `@` onward
/// before comparing. Inputs without `@` pass through unchanged.
fn strip_jid(jid: &str) -> &str {
    jid.split_once('@').map(|(head, _)| head).unwrap_or(jid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_jid_removes_suffix() {
        assert_eq!(strip_jid("2348012345678@c.us"), "2348012345678");
        assert_eq!(strip_jid("2348012345678@s.whatsapp.net"), "2348012345678");
    }

    #[test]
    fn strip_jid_passes_through_raw_digits() {
        assert_eq!(strip_jid("2348012345678"), "2348012345678");
    }
}
