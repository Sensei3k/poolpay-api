use crate::models::ParsedReceipt;
use regex::Regex;
use std::sync::LazyLock;
use tracing::info;

// Compiled once at first use — compiling regexes on every call is measurably expensive.
static AMOUNT_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Tesseract often renders ₦ as # and may insert spaces within digit groups
    // (e.g. "#9 7,800.00" instead of "#97,800.00"). The pattern allows an optional
    // space or comma between digit runs; spaces are stripped in post-processing.
    // Handles: #97,800.00  #9 7,800.00  ₦97,800.00  NGN 97,800.00
    Regex::new(r"(?:[#₦]|NGN\s*)\d+(?:[ ,]\d+)*(?:\.\d{1,2})?").unwrap()
});

static SENDER_LABEL_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Primary pattern (OPay / Moniepoint style):
    //   "Sender Details  FULL NAME"  ← name on same line as label
    //   "BankName | account"         ← bank on the very next line
    //
    // Capture group restricted to [A-Za-z ] — same constraint as FALLBACK_SENDER_RE.
    // This prevents OCR garbage after the name (e.g. "#!@$", digits, symbols) from
    // being included in the captured value. The match stops at the first non-letter,
    // non-space character; trailing spaces are stripped by .trim() at call site.
    Regex::new(r"(?i)sender\s+details?\s+([A-Za-z][A-Za-z ]{2,40})").unwrap()
});

static FALLBACK_SENDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    // Use [ ] (literal space only) in the name capture group — \s would match \n
    // and cause the name to bleed onto the next line of the receipt.
    //
    // The upper bound of {2,40} is a practical limit: real names fit comfortably
    // within 40 characters after the leading letter. If OCR produces a longer run
    // of letters and spaces (e.g. a garbled paragraph), the match stops at 41 chars
    // and the excess is silently dropped. This is a known limitation — it protects
    // against runaway captures at the cost of truncating unusually long names.
    Regex::new(
        r"(?i)(?:sender(?:\s+name)?|from|originator)\s*[:\-]?\s*([A-Za-z][A-Za-z ]{2,40})",
    )
    .unwrap()
});

static KNOWN_BANKS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b(gtbank|access bank|zenith bank|first bank|uba|opay|kuda|palmpay|moniepoint|monie point|sterling|polaris|fidelity|union bank|wema|stanbic|ecobank|providus)\b",
    )
    .unwrap()
});

/// Extracts sender name, bank name, and amount from raw OCR text.
/// Returns a ParsedReceipt with whichever fields could be identified.
pub fn parse_receipt(text: &str) -> ParsedReceipt {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect();

    let amount = AMOUNT_RE.find(text).map(|m| {
        // Strip any OCR-introduced spaces within the number, then normalise the currency symbol.
        // Both "#" (Tesseract artefact) and "NGN" prefix are mapped to "₦".
        //
        // Order matters: '#' is replaced before strip_prefix("NGN") is checked.
        // A pathological string like "#NGN97,800.00" would survive as "₦NGN97,800.00"
        // because the '#' → '₦' substitution happens first, making it no longer start
        // with "NGN". This is an acceptable edge case — real receipts don't mix both
        // prefixes, and the regex would never match "#NGN..." in practice.
        let joined = m.as_str().split_whitespace().collect::<String>();
        let with_naira = joined.replace('#', "₦");
        match with_naira.strip_prefix("NGN") {
            Some(rest) => format!("₦{rest}"),
            None => with_naira,
        }
    });

    let mut sender: Option<String> = None;
    let mut bank: Option<String> = None;

    for (i, line) in lines.iter().enumerate() {
        if let Some(caps) = SENDER_LABEL_RE.captures(line) {
            sender = caps.get(1).map(|m| m.as_str().trim().to_string());

            // The bank name is on the next line, before any "|" separator.
            if let Some(next_line) = lines.get(i + 1) {
                let bank_name = next_line.split('|').next().unwrap_or(next_line).trim();
                if !bank_name.is_empty() {
                    bank = Some(bank_name.to_string());
                }
            }
            break;
        }
    }

    // Fallback: try a simpler label pattern if the primary one didn't match.
    if sender.is_none() {
        sender = FALLBACK_SENDER_RE
            .captures(text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());
    }

    // Fallback: scan for any known Nigerian bank or fintech name in the text.
    if bank.is_none() {
        bank = KNOWN_BANKS_RE
            .find(text)
            .map(|m| m.as_str().trim().to_string());
    }

    ParsedReceipt { sender, bank, amount }
}

/// Converts a normalised amount string (as produced by `parse_receipt`) into
/// an integer kobo value. Returns `None` when the input is not a recognisable
/// Naira amount.
///
/// Accepted shapes: `₦97,800.00`, `₦97,800`, `₦97800.5`. The currency prefix
/// may be `₦`, `#`, or `NGN` (with optional whitespace). Thousand separators
/// and spaces are ignored; decimals are truncated to two places of kobo.
pub fn parse_amount_to_kobo(amount: &str) -> Option<i64> {
    let trimmed = amount.trim();
    let without_prefix = trimmed
        .strip_prefix('₦')
        .or_else(|| trimmed.strip_prefix('#'))
        .or_else(|| {
            trimmed
                .strip_prefix("NGN")
                .or_else(|| trimmed.strip_prefix("ngn"))
                .map(str::trim_start)
        })?;

    let cleaned: String = without_prefix
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',')
        .collect();

    let (whole, fraction) = match cleaned.split_once('.') {
        Some((w, f)) => (w, f),
        None => (cleaned.as_str(), ""),
    };

    if whole.is_empty() || !whole.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !fraction.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let naira: i64 = whole.parse().ok()?;
    let kobo_fraction: i64 = match fraction.len() {
        0 => 0,
        1 => fraction.parse::<i64>().ok()? * 10,
        _ => fraction[..2].parse().ok()?,
    };

    naira.checked_mul(100)?.checked_add(kobo_fraction)
}

/// Logs the fields of a ParsedReceipt.
pub fn print_parsed(parsed: &ParsedReceipt) {
    info!(
        sender = parsed.sender.as_deref().unwrap_or("not found"),
        bank = parsed.bank.as_deref().unwrap_or("not found"),
        amount = parsed.amount.as_deref().unwrap_or("not found"),
        "Parsed receipt"
    );
}
