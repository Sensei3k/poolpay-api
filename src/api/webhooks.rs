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

    // `received_at` is parsed downstream during confirm (`confirm_receipt_inner`
    // derives `payment_date` via `DateTime::parse_from_rfc3339`). A non-RFC3339
    // value would ingest as `pending` then become impossible to confirm (409),
    // poisoning the queue with rows the admin can neither act on nor purge.
    // Validate at the boundary and collapse the failure to 401, consistent
    // with the opaque-failure rule above.
    //
    // We also normalise the timestamp to a canonical UTC RFC3339 string before
    // persisting. The DB stores `received_at` as a string and `/api/receipts`
    // orders by it (`ORDER BY received_at ASC`), so a mix of offsets like
    // `…+01:00` and `…+00:00` would sort lexicographically — breaking
    // absolute-time ordering of the admin queue. Converting to UTC makes the
    // lexicographic sort equivalent to a chronological sort.
    let parsed_received_at =
        chrono::DateTime::parse_from_rfc3339(&payload.received_at)
            .map_err(|_| AppError::Unauthorized)?
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // `raw_image_url` is persisted verbatim and surfaced to admins in the FE
    // review modal. Reject anything that is not an absolute http(s) URL so a
    // bot post can't smuggle a `javascript:` / `data:` / `file:` URI or a
    // relative path into an admin-rendered link. Collapse to the same opaque
    // 401 the other payload gates use — a probing caller must not learn
    // which validation step rejected the request.
    //
    // `None` is permitted: the field is documented as optional and a bot
    // running ahead of OCR may legitimately omit the screenshot URL.
    if let Some(url) = payload.raw_image_url.as_deref() {
        if !is_http_or_https_url(url) {
            return Err(AppError::Unauthorized);
        }
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
        received_at: parsed_received_at,
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

/// True when `url` is a syntactically absolute `http://` or `https://` URL
/// with a non-empty host segment. Deliberately minimal — we don't pull in
/// a URL crate just to gate this one optional field, and the property we
/// care about (no `javascript:` / `data:` / `file:` / relative paths) is
/// fully captured by checking the scheme prefix plus a non-empty authority.
///
/// Lower-cased before comparison so `HTTPS://…` (legal per RFC 3986) is
/// still accepted. Whitespace at either end is rejected — we trim before
/// the prefix check so a leading space can't sneak a different scheme past
/// the gate.
fn is_http_or_https_url(url: &str) -> bool {
    let trimmed = url.trim();
    let lower = trimmed.to_ascii_lowercase();
    let rest = if let Some(r) = lower.strip_prefix("https://") {
        r
    } else if let Some(r) = lower.strip_prefix("http://") {
        r
    } else {
        return false;
    };
    // Authority must be non-empty and must not start with `/` (which would
    // mean `http:///path` — no host).
    let host_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..host_end];
    !authority.is_empty()
}

#[cfg(test)]
mod tests {
    use super::is_http_or_https_url;

    #[test]
    fn accepts_http_and_https() {
        assert!(is_http_or_https_url("https://example.com/x.jpg"));
        assert!(is_http_or_https_url("http://example.com/x.jpg"));
        assert!(is_http_or_https_url("HTTPS://example.com/x.jpg"));
    }

    #[test]
    fn rejects_dangerous_or_relative_urls() {
        assert!(!is_http_or_https_url("javascript:alert(1)"));
        assert!(!is_http_or_https_url("data:image/png;base64,AAA"));
        assert!(!is_http_or_https_url("file:///etc/passwd"));
        assert!(!is_http_or_https_url("/foo.png"));
        assert!(!is_http_or_https_url("example.com/x.jpg"));
        assert!(!is_http_or_https_url(""));
        assert!(!is_http_or_https_url("https://"));
        assert!(!is_http_or_https_url("http:///path"));
    }
}
