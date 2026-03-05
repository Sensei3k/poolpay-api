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
    Regex::new(r"(?i)sender\s+details?\s+(.+)").unwrap()
});

static FALLBACK_SENDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)(?:sender(?:\s+name)?|from|originator)\s*[:\-]?\s*([A-Za-z][A-Za-z\s]{2,40})",
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
        // Strip any OCR-introduced spaces within the number, then normalise the symbol.
        m.as_str()
            .split_whitespace()
            .collect::<String>()
            .replace('#', "₦")
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

/// Logs the fields of a ParsedReceipt.
pub fn print_parsed(parsed: &ParsedReceipt) {
    info!(
        sender = parsed.sender.as_deref().unwrap_or("not found"),
        bank = parsed.bank.as_deref().unwrap_or("not found"),
        amount = parsed.amount.as_deref().unwrap_or("not found"),
        "Parsed receipt"
    );
}
