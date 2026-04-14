//! Formats the WhatsApp reply that follows an ingestion attempt.
//!
//! Pure text formatting — no DB, no network. Given an `IngestionOutcome`
//! (and, for the successful path, the parsed receipt fields) it returns
//! the exact message body the poller should quote-reply with. A `None`
//! return means the caller should stay silent (e.g. duplicates — the
//! sender already received a reply on the first ingestion).

use crate::ingestion::{IngestedReceipt, IngestionOutcome};
use crate::models::ParsedReceipt;

/// Produce the WhatsApp reply for an ingestion outcome.
///
/// Returns `None` for outcomes where a reply would be noise — currently
/// only `DuplicateMessage`.
pub fn format_reply(outcome: &IngestionOutcome, parsed: &ParsedReceipt) -> Option<String> {
    match outcome {
        IngestionOutcome::DuplicateMessage => None,
        IngestionOutcome::NotLinked => Some(not_linked()),
        IngestionOutcome::Ingested(r) => Some(format_ingested(r, parsed)),
    }
}

fn not_linked() -> String {
    "⚠️ This chat isn't linked to a PoolPay group yet. Ask your group admin to link it before sending receipts.".to_string()
}

fn format_ingested(r: &IngestedReceipt, parsed: &ParsedReceipt) -> String {
    if !r.member_matched {
        return "⚠️ We couldn't match your phone number to a member of this group. Ask your admin to register you, then resend the receipt.".to_string();
    }
    if !r.cycle_matched {
        return "📬 Receipt saved. This group has no active cycle right now, so an admin will review it manually.".to_string();
    }

    let sender = parsed.sender.as_deref().unwrap_or("unknown");
    let bank = parsed.bank.as_deref().unwrap_or("unknown");
    let amount = parsed
        .amount
        .as_deref()
        .map(str::to_string)
        .unwrap_or_else(|| "unreadable".to_string());

    match r.amount_matches {
        Some(true) => format!(
            "✅ Receipt received — pending admin review.\nSender: {sender}\nBank: {bank}\nAmount: {amount}"
        ),
        Some(false) => {
            let expected = r
                .expected_amount
                .map(format_kobo)
                .unwrap_or_else(|| "unknown".to_string());
            format!(
                "⚠️ Amount mismatch — pending admin review.\nSender: {sender}\nBank: {bank}\nExtracted: {amount}\nExpected: {expected}"
            )
        }
        None => format!(
            "📬 Receipt received — we couldn't read the amount clearly, so an admin will review it.\nSender: {sender}\nBank: {bank}"
        ),
    }
}

/// Render a kobo integer as a naira string (`₦10,000.00`) for display.
fn format_kobo(kobo: i64) -> String {
    let naira = kobo / 100;
    let fraction = (kobo % 100).abs();

    let whole = naira.abs().to_string();
    let mut with_commas = String::with_capacity(whole.len() + whole.len() / 3);
    for (i, ch) in whole.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            with_commas.push(',');
        }
        with_commas.push(ch);
    }
    let whole_commas: String = with_commas.chars().rev().collect();
    let sign = if kobo < 0 { "-" } else { "" };
    format!("{sign}₦{whole_commas}.{fraction:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingestion::{IngestedReceipt, IngestionOutcome};

    fn parsed(sender: &str, bank: &str, amount: Option<&str>) -> ParsedReceipt {
        ParsedReceipt {
            sender: Some(sender.into()),
            bank: Some(bank.into()),
            amount: amount.map(str::to_string),
        }
    }

    fn receipt(member: bool, cycle: bool, matches: Option<bool>) -> IngestedReceipt {
        IngestedReceipt {
            receipt_id: "r1".into(),
            group_id: "1".into(),
            member_matched: member,
            cycle_matched: cycle,
            extracted_amount: Some(1_000_000),
            expected_amount: Some(1_000_000),
            amount_matches: matches,
        }
    }

    #[test]
    fn duplicate_has_no_reply() {
        let p = parsed("x", "y", Some("₦10,000.00"));
        assert!(format_reply(&IngestionOutcome::DuplicateMessage, &p).is_none());
    }

    #[test]
    fn not_linked_prompts_admin_link() {
        let p = parsed("x", "y", Some("₦10,000.00"));
        let reply = format_reply(&IngestionOutcome::NotLinked, &p).unwrap();
        assert!(reply.contains("isn't linked"));
        assert!(reply.contains("admin"));
    }

    #[test]
    fn unregistered_sender_prompts_registration() {
        let p = parsed("x", "y", Some("₦10,000.00"));
        let out = IngestionOutcome::Ingested(receipt(false, true, None));
        let reply = format_reply(&out, &p).unwrap();
        assert!(reply.contains("couldn't match your phone"));
    }

    #[test]
    fn no_active_cycle_acknowledges_manual_review() {
        let p = parsed("x", "y", Some("₦10,000.00"));
        let out = IngestionOutcome::Ingested(receipt(true, false, None));
        let reply = format_reply(&out, &p).unwrap();
        assert!(reply.contains("no active cycle"));
    }

    #[test]
    fn full_match_returns_success_summary() {
        let p = parsed("Adaeze Okonkwo", "GTBank", Some("₦10,000.00"));
        let out = IngestionOutcome::Ingested(receipt(true, true, Some(true)));
        let reply = format_reply(&out, &p).unwrap();
        assert!(reply.starts_with("✅"));
        assert!(reply.contains("Adaeze Okonkwo"));
        assert!(reply.contains("GTBank"));
        assert!(reply.contains("₦10,000.00"));
    }

    #[test]
    fn amount_mismatch_shows_extracted_and_expected() {
        let p = parsed("Adaeze Okonkwo", "GTBank", Some("₦500.00"));
        let mut r = receipt(true, true, Some(false));
        r.extracted_amount = Some(50_000);
        r.expected_amount = Some(1_000_000);
        let reply = format_reply(&IngestionOutcome::Ingested(r), &p).unwrap();
        assert!(reply.contains("mismatch"));
        assert!(reply.contains("₦500.00"));
        assert!(reply.contains("₦10,000.00"));
    }

    #[test]
    fn unreadable_amount_notes_admin_review() {
        let p = parsed("Adaeze Okonkwo", "GTBank", None);
        let out = IngestionOutcome::Ingested(receipt(true, true, None));
        let reply = format_reply(&out, &p).unwrap();
        assert!(reply.contains("couldn't read the amount"));
    }

    #[test]
    fn format_kobo_renders_standard_amounts() {
        assert_eq!(format_kobo(1_000_000), "₦10,000.00");
        assert_eq!(format_kobo(50), "₦0.50");
        assert_eq!(format_kobo(123_456_789), "₦1,234,567.89");
    }
}
