use receipt_engine::parser::parse_receipt;

// ── Amount extraction ─────────────────────────────────────────────────────────

#[test]
fn amount_naira_symbol_clean() {
    let r = parse_receipt("Amount: ₦97,800.00 transfer");
    assert_eq!(r.amount.as_deref(), Some("₦97,800.00"));
}

#[test]
fn amount_hash_symbol_becomes_naira() {
    // Tesseract renders ₦ as #
    let r = parse_receipt("Amount: #97,800.00");
    assert_eq!(r.amount.as_deref(), Some("₦97,800.00"));
}

#[test]
fn amount_hash_with_mid_number_space() {
    // OCR splits digit groups: "#9 7,800.00" should become "₦97,800.00"
    let r = parse_receipt("Total #9 7,800.00 paid");
    assert_eq!(r.amount.as_deref(), Some("₦97,800.00"));
}

#[test]
fn amount_hash_with_multiple_internal_spaces() {
    // Severe OCR fragmentation: "#9 7 8 0 0.00"
    let r = parse_receipt("Amount #9 7 8 0 0.00");
    assert_eq!(r.amount.as_deref(), Some("₦97800.00"));
}

#[test]
fn amount_ngn_prefix_with_space() {
    // "NGN" prefix without ₦ symbol — should be normalised to ₦
    let r = parse_receipt("NGN 97,800.00 transferred");
    assert_eq!(r.amount.as_deref(), Some("₦97,800.00"));
}

#[test]
fn amount_ngn_prefix_no_space() {
    let r = parse_receipt("NGN97,800.00");
    assert_eq!(r.amount.as_deref(), Some("₦97,800.00"));
}

#[test]
fn amount_trailing_zeros_two_decimal_places() {
    let r = parse_receipt("₦100.00");
    assert_eq!(r.amount.as_deref(), Some("₦100.00"));
}

#[test]
fn amount_trailing_zeros_three_decimal_places_truncated() {
    // Regex captures at most 2 decimal digits — third is silently dropped
    let r = parse_receipt("₦100.000");
    assert_eq!(r.amount.as_deref(), Some("₦100.00"));
}

#[test]
fn amount_no_decimal_part() {
    let r = parse_receipt("₦50,000 transfer complete");
    assert_eq!(r.amount.as_deref(), Some("₦50,000"));
}

#[test]
fn amount_none_when_absent() {
    let r = parse_receipt("Transfer receipt\nSender: John Doe");
    assert_eq!(r.amount, None);
}

#[test]
fn amount_hash_no_comma_grouping() {
    // Some receipts omit comma separators: "#97800.00"
    let r = parse_receipt("#97800.00");
    assert_eq!(r.amount.as_deref(), Some("₦97800.00"));
}

// ── Sender extraction ─────────────────────────────────────────────────────────

#[test]
fn sender_primary_label_same_line() {
    // OPay / Moniepoint style: "Sender Details  FULL NAME"
    let r = parse_receipt("Sender Details  Jane Okonkwo\nOPay | 8012345678");
    assert_eq!(r.sender.as_deref(), Some("Jane Okonkwo"));
}

#[test]
fn sender_primary_label_case_insensitive() {
    let r = parse_receipt("SENDER DETAILS John Adeyemi\nKuda | 8098765432");
    assert_eq!(r.sender.as_deref(), Some("John Adeyemi"));
}

#[test]
fn sender_fallback_colon_label() {
    let r = parse_receipt("Sender: Emeka Nwosu\n₦5,000.00");
    assert_eq!(r.sender.as_deref(), Some("Emeka Nwosu"));
}

#[test]
fn sender_fallback_from_label() {
    let r = parse_receipt("From: Ngozi Eze\nAmount: ₦10,000.00");
    assert_eq!(r.sender.as_deref(), Some("Ngozi Eze"));
}

#[test]
fn sender_fallback_originator_label() {
    let r = parse_receipt("Originator: Bola Tinubu\nBank: GTBank");
    assert_eq!(r.sender.as_deref(), Some("Bola Tinubu"));
}

#[test]
fn sender_none_when_absent() {
    let r = parse_receipt("Transaction receipt\nAmount: ₦1,000.00\nGTBank");
    assert_eq!(r.sender, None);
}

#[test]
fn sender_trimmed_no_leading_trailing_whitespace() {
    let r = parse_receipt("Sender Details   Ada Obi   \nZenith Bank | 1234567890");
    let name = r.sender.as_deref().unwrap_or("");
    assert!(!name.starts_with(' '), "sender has leading space: {name:?}");
    assert!(!name.ends_with(' '), "sender has trailing space: {name:?}");
}

// ── Bank extraction ───────────────────────────────────────────────────────────

#[test]
fn bank_from_next_line_after_sender_details() {
    // Bank name is on the line immediately following "Sender Details ..."
    let r = parse_receipt("Sender Details  Chidi Obi\nOPay | 08011112222");
    assert_eq!(r.bank.as_deref(), Some("OPay"));
}

#[test]
fn bank_strip_account_number_after_pipe() {
    // Everything after "|" is an account number, not the bank name
    let r = parse_receipt("Sender Details  Amaka Eze\nZenith Bank | 2012345678\n₦20,000.00");
    assert_eq!(r.bank.as_deref(), Some("Zenith Bank"));
}

#[test]
fn bank_fallback_known_bank_in_text() {
    // No "Sender Details" label, but a known bank name appears in the body
    let r = parse_receipt("Receipt\nFrom: Tunde Bakare\nGTBank\n₦3,000.00");
    assert_eq!(r.bank.as_deref(), Some("GTBank"));
}

#[test]
fn bank_fallback_access_bank() {
    let r = parse_receipt("Sent via Access Bank\nAmount: ₦7,500.00");
    assert_eq!(r.bank.as_deref(), Some("Access Bank"));
}

#[test]
fn bank_fallback_case_insensitive() {
    let r = parse_receipt("processed by ZENITH BANK\n₦500.00");
    assert_eq!(
        r.bank.as_deref().map(|s| s.to_lowercase()),
        Some("zenith bank".to_string())
    );
}

#[test]
fn bank_none_when_absent() {
    let r = parse_receipt("Sender: Unknown Person\nAmount: ₦100.00");
    assert_eq!(r.bank, None);
}

#[test]
fn bank_trimmed_when_next_line_has_leading_space() {
    let r = parse_receipt("Sender Details  Kemi Bello\n  Kuda | 8099887766");
    let bank = r.bank.as_deref().unwrap_or("");
    assert!(!bank.starts_with(' '), "bank has leading space: {bank:?}");
}

// ── Combined / realistic receipts ─────────────────────────────────────────────

#[test]
fn full_opay_receipt_all_fields_extracted() {
    let ocr = "\
        OPay Receipt\n\
        Sender Details  Chioma Okafor\n\
        OPay | 8031234567\n\
        Amount: ₦15,000.00\n\
        Ref: TXN20240101";
    let r = parse_receipt(ocr);
    assert_eq!(r.sender.as_deref(), Some("Chioma Okafor"));
    assert_eq!(r.bank.as_deref(), Some("OPay"));
    assert_eq!(r.amount.as_deref(), Some("₦15,000.00"));
}

#[test]
fn full_receipt_with_ocr_hash_and_space_noise() {
    // Simulates heavy OCR artefacts: # for ₦ and space inside number
    let ocr = "\
        Transfer Receipt\n\
        Sender Details  Musa Ibrahim\n\
        GTBank | 0123456789\n\
        Total #1 5,000.00";
    let r = parse_receipt(ocr);
    assert_eq!(r.sender.as_deref(), Some("Musa Ibrahim"));
    assert_eq!(r.bank.as_deref(), Some("GTBank"));
    assert_eq!(r.amount.as_deref(), Some("₦15,000.00"));
}
