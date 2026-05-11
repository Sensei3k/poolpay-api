//! Inbound webhook endpoints.
//!
//! Slice 5 adds `POST /api/webhooks/whatsapp`. The bot signs the payload
//! with `WA_WEBHOOK_SECRET` (HMAC-SHA256 over `timestamp + "." + body`,
//! same scheme as the NextAuth backend channel) and posts a flat JSON
//! payload describing one receipt message. This handler converts the
//! payload into an [`IngestionInput`] and delegates to the existing
//! `ingestion::ingest_receipt` pipeline — so the matcher logic, duplicate
//! detection, and `IngestionOutcome` shape are unchanged.
//!
//! Authentication is fail-closed at the extractor: the secret env var must
//! be set and non-empty, the timestamp must be within ±60 s of server
//! time, and the signature must verify constant-time. Any deviation
//! collapses to 401, so a probing caller cannot tell which gate failed.

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::api::models::AppError;
use crate::auth::hmac::WebhookVerifiedJson;
use crate::db::DbConn;
use crate::ingestion::{self, IngestionInput, IngestionOutcome};
use crate::models::ParsedReceipt;

/// JSON shape posted by the WhatsApp bot for a single receipt event.
///
/// camelCase across the wire to match the bot's existing Node code, with
/// snake_case Rust field names mapped via `serde(rename_all)`. Every field
/// has a single, narrow purpose — see the inline comments. Optional
/// fields default to `None` so a slimmer payload from a future bot
/// version still deserialises (the matcher gracefully degrades when
/// optional context is missing).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookPayload {
    /// WhatsApp group chat id (`<digits>@g.us`). Routes to the linked pool.
    pub chat_id: String,
    /// Sender JID or raw digits. The ingestion pipeline strips any `@…`
    /// suffix before phone matching.
    pub sender_phone: String,
    /// Unique WhatsApp message id. Used by the duplicate-detection gate.
    pub message_id: String,
    /// Raw text or caption — the OCR/parse layer ran upstream in the bot.
    #[serde(default)]
    pub ocr_text: String,
    /// Bot-parsed fields (sender label, bank label, amount string).
    /// All optional; the matcher falls back to phone-only when missing.
    #[serde(default)]
    pub parsed: WebhookParsedFields,
    /// ISO 8601 timestamp the bot stamped when it observed the message.
    /// Stored on the receipt as `received_at`.
    pub received_at: String,
    /// Direct URL to the WhatsApp screenshot (HANDOFF §4). Persisted on
    /// the receipt so admins can review the artefact in the FE modal.
    #[serde(default)]
    pub raw_image_url: Option<String>,
}

/// Parsed fields the bot supplies alongside the raw OCR text. Mirrors the
/// internal `ParsedReceipt` so we do not perform any extra parsing on the
/// API side — the bot owns OCR/regex extraction, the API owns persistence
/// and matching.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookParsedFields {
    #[serde(default)]
    pub sender: Option<String>,
    #[serde(default)]
    pub bank: Option<String>,
    #[serde(default)]
    pub amount: Option<String>,
}

/// Wire shape of the success response. The bot uses `outcome` to decide
/// whether to post a quoted acknowledgement reply, and `receiptId` (when
/// the outcome is `ingested`) to link future updates back to the row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WebhookResponse {
    /// Canonical outcome slug — one of `"not_linked"`, `"duplicate"`,
    /// `"ingested"`. Stable for the bot to switch on.
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    /// Whether the matcher resolved the sender phone to a member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member_matched: Option<bool>,
}

/// Handler: verifies the HMAC, dispatches to the shared ingestion pipeline,
/// and projects the outcome to the bot-facing response shape.
///
/// All ingestion outcomes (linked / unlinked / duplicate) return 200 with
/// a body the bot can switch on — only auth or storage failures bubble up
/// as error statuses. That mirrors the contract the bot already expects
/// from the existing Green API polling code path.
pub async fn whatsapp_webhook(
    State(db): State<DbConn>,
    WebhookVerifiedJson(payload): WebhookVerifiedJson<WebhookPayload>,
) -> Result<(StatusCode, Json<WebhookResponse>), AppError> {
    // Required identifier fields. The module-level contract is that every
    // verification/validation failure on the webhook path collapses to 401
    // so a probing caller cannot distinguish "valid signature, bad payload"
    // from "bad signature" (avoiding a signature/probing oracle). These
    // checks therefore return `Unauthorized`, not `BadRequest`.
    //
    // `message_id` is also the duplicate-detection key — refusing an empty
    // value here keeps a malformed bot post from silently coalescing every
    // unrelated message under "" in the index.
    if payload.message_id.trim().is_empty()
        || payload.chat_id.trim().is_empty()
        || payload.sender_phone.trim().is_empty()
    {
        return Err(AppError::Unauthorized);
    }

    let parsed = ParsedReceipt {
        sender: payload.parsed.sender,
        bank: payload.parsed.bank,
        amount: payload.parsed.amount,
    };

    let input = IngestionInput {
        chat_id: &payload.chat_id,
        sender_phone: &payload.sender_phone,
        message_id: &payload.message_id,
        ocr_text: &payload.ocr_text,
        parsed: &parsed,
        received_at: payload.received_at,
        raw_image_url: payload.raw_image_url,
    };

    let outcome = ingestion::ingest_receipt(&db, input).await?;
    info!(
        chat_id = %payload.chat_id,
        message_id = %payload.message_id,
        ?outcome,
        "Webhook ingest outcome"
    );

    let resp = match outcome {
        IngestionOutcome::NotLinked => WebhookResponse {
            outcome: "not_linked",
            receipt_id: None,
            member_matched: None,
        },
        IngestionOutcome::DuplicateMessage => WebhookResponse {
            outcome: "duplicate",
            receipt_id: None,
            member_matched: None,
        },
        IngestionOutcome::Ingested(r) => WebhookResponse {
            outcome: "ingested",
            receipt_id: Some(r.receipt_id),
            member_matched: Some(r.member_matched),
        },
    };
    Ok((StatusCode::OK, Json(resp)))
}
