use crate::models::ReceiptRow;
use reqwest::Client;
use std::time::{Duration, Instant};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::Mutex;
use tracing::{info, warn};
use yup_oauth2::ServiceAccountKey;

/// OAuth2 scope required for reading and writing Google Sheets.
const SHEETS_SCOPE: &str = "https://www.googleapis.com/auth/spreadsheets";

/// Google Sheets REST API v4 base URL.
const SHEETS_BASE: &str = "https://sheets.googleapis.com/v4/spreadsheets";

/// Target range for append operations — columns A through G on the first sheet.
/// The Sheets API appends after the last populated row within this range.
const APPEND_RANGE: &str = "A:G";

/// Cached OAuth2 access token and when it stops being valid.
struct CachedToken {
    value: String,
    valid_until: Instant,
}

/// A sheet row that has been confirmed by the user but not yet acknowledged
/// by the engine. Returned by `fetch_unacknowledged_confirmed`.
pub struct PendingRow {
    /// 1-based sheet row number — used to write the AcknowledgedAt timestamp
    /// back to column F of exactly this row via `mark_acknowledged`.
    pub row_index: usize,
    /// WhatsApp message ID (column E) — used to quote the original receipt
    /// message in the acknowledgement reply.
    pub message_id: String,
    /// WhatsApp chat ID (column G) — used to send the acknowledgement reply
    /// to the correct chat.
    pub chat_id: String,
}

/// Client for the Google Sheets v4 REST API, authenticated via a service account.
///
/// The `ServiceAccountKey` is stored so a fresh `Authenticator` can be built
/// whenever the cached token expires. Tokens are cached for 55 minutes —
/// Google issues them for 60, leaving a 5-minute buffer for clock skew.
///
/// Wrap in `Arc` to share between the receipt intake task and any future
/// confirmation-polling task.
pub struct SheetsClient {
    http: Client,
    spreadsheet_id: String,
    key: ServiceAccountKey,
    cached_token: Mutex<Option<CachedToken>>,
}

impl SheetsClient {
    /// Reads the service account key file at `key_path` and constructs a client
    /// targeting `spreadsheet_id`. Fails fast if the key file is missing or malformed.
    ///
    /// `spreadsheet_id` accepts either a bare ID or a full Google Sheets URL —
    /// both forms appear in the browser address bar and user configuration:
    ///   - Bare ID:  `1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms`
    ///   - Full URL: `https://docs.google.com/spreadsheets/d/<ID>/edit`
    /// The ID is extracted automatically when a URL is supplied.
    pub async fn new(
        key_path: &str,
        spreadsheet_id: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key = yup_oauth2::read_service_account_key(key_path).await?;
        Ok(Self {
            http: Client::new(),
            spreadsheet_id: extract_spreadsheet_id(&spreadsheet_id).to_string(),
            key,
            cached_token: Mutex::new(None),
        })
    }

    /// Appends one receipt row to the sheet.
    ///
    /// Column layout written (A–G):
    ///   A: Sender  B: Bank  C: Amount  D: ""(Confirmed — user fills)
    ///   E: MessageID  F: ""(AcknowledgedAt — engine writes later)  G: ChatID
    ///
    /// Uses `USER_ENTERED` so Google parses values the same way a human would
    /// when typing into the sheet (e.g. currency strings stay as strings).
    /// `INSERT_ROWS` ensures each call always adds a new row rather than
    /// overwriting any existing data in the range.
    pub async fn append_row(
        &self,
        row: &ReceiptRow,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token = self.access_token().await?;

        // Google's custom-method URL format: /values/{range}:append
        let url = format!(
            "{}/{}/values/{}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS",
            SHEETS_BASE, self.spreadsheet_id, APPEND_RANGE,
        );

        let body = serde_json::json!({
            "values": [[
                &row.sender,      // A
                &row.bank,        // B
                &row.amount,      // C
                "",               // D — Confirmed checkbox, user fills
                &row.message_id,  // E
                "",               // F — AcknowledgedAt, engine writes on confirmation
                &row.chat_id,     // G
            ]]
        });

        let resp = self.http
            .post(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            return Err(format!("Sheets API {status}: {text}").into());
        }

        info!(
            sender = %row.sender,
            amount = %row.amount,
            "Receipt row appended to sheet"
        );
        Ok(())
    }

    /// Reads all rows in the sheet and returns those where the user has ticked
    /// Confirmed (column D = "TRUE") but the engine has not yet written an
    /// AcknowledgedAt timestamp (column F is empty).
    ///
    /// The Sheets API returns checkboxes as the strings "TRUE" or "FALSE" when
    /// using the default FORMATTED_VALUE render option.
    ///
    /// Row indices are 1-based sheet row numbers (row 1 = header). A row at
    /// position `i` in the returned values array (0-based, skipping the header)
    /// corresponds to sheet row `i + 2`.
    ///
    /// Returns an empty Vec if the sheet has no data rows or no pending rows,
    /// rather than an error.
    pub async fn fetch_unacknowledged_confirmed(
        &self,
    ) -> Result<Vec<PendingRow>, Box<dyn std::error::Error>> {
        let token = self.access_token().await?;

        let url = format!("{}/{}/values/A:G", SHEETS_BASE, self.spreadsheet_id);

        let resp = self.http
            .get(&url)
            .bearer_auth(&token)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            return Err(format!("Sheets API {status}: {text}").into());
        }

        let body: serde_json::Value = resp.json().await?;

        // The "values" key is absent entirely when the sheet has no data rows.
        let rows = match body["values"].as_array() {
            Some(r) => r,
            None => return Ok(Vec::new()),
        };

        let pending = pending_from_rows(rows);
        info!(count = pending.len(), "Pending confirmed rows fetched");
        Ok(pending)
    }

    /// Writes an RFC 3339 UTC timestamp to column F of the given sheet row,
    /// marking it as acknowledged so it is not reprocessed on the next poll.
    ///
    /// Uses `valueInputOption=USER_ENTERED` so Google stores it as a plain
    /// string rather than attempting date parsing (dates behave unpredictably
    /// across locale settings).
    ///
    /// Idempotent: calling this twice on the same row overwrites F with a new
    /// timestamp — harmless since the row is already acknowledged after the
    /// first call.
    pub async fn mark_acknowledged(
        &self,
        row_index: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let token = self.access_token().await?;

        let cell = format!("F{}", row_index);
        let url = format!(
            "{}/{}/values/{}?valueInputOption=USER_ENTERED",
            SHEETS_BASE, self.spreadsheet_id, cell,
        );

        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|e| {
                warn!(error = %e, row_index, "RFC 3339 timestamp format failed — writing \"unknown\" to AcknowledgedAt");
                "unknown".to_string()
            });

        let body = serde_json::json!({
            "range": &cell,
            "majorDimension": "ROWS",
            "values": [[timestamp]],
        });

        let resp = self.http
            .put(&url)
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await?;
            return Err(format!("Sheets API {status}: {text}").into());
        }

        info!(row_index, "Row marked as acknowledged");
        Ok(())
    }

    /// Returns a valid access token, refreshing from Google if the cached one
    /// has expired or was never fetched.
    ///
    /// Note: a new `Authenticator` is built on each refresh rather than stored,
    /// which avoids exposing yup-oauth2's generic connector type in our struct.
    /// The authenticator construction is fast (no network call); only `token()`
    /// hits the network, and that result is cached for 55 minutes.
    async fn access_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut guard = self.cached_token.lock().await;

        if let Some(ref ct) = *guard {
            if ct.valid_until > Instant::now() {
                return Ok(ct.value.clone());
            }
        }

        // Build a fresh authenticator — the builder owns the key so we clone.
        // The authenticator itself is transient; only the token string is cached.
        let auth = yup_oauth2::ServiceAccountAuthenticator::builder(self.key.clone())
            .build()
            .await?;

        let tok = auth.token(&[SHEETS_SCOPE]).await?;

        let value = tok
            .token()
            .ok_or("Google OAuth2 returned an access token response with no token value")?
            .to_string();

        *guard = Some(CachedToken {
            value: value.clone(),
            valid_until: Instant::now() + Duration::from_secs(55 * 60),
        });

        info!("Google OAuth2 token refreshed");
        Ok(value)
    }
}

/// Returns the string value of a cell at `index` within a row's column array.
///
/// Returns `""` for any of these cases — all treated as "empty" by the callers:
///   - Index is beyond the end of the row (Google omits trailing empty cells)
///   - Value is JSON null
///   - Value is not a JSON string (e.g. a boolean from an un-formatted checkbox)
fn col_str(cols: &[serde_json::Value], index: usize) -> &str {
    cols.get(index)
        .and_then(|v| v.as_str())
        .unwrap_or("")
}

/// Scans a slice of raw JSON row values (as returned by the Sheets API `values` array)
/// and returns a `PendingRow` for every data row where:
///   - Column D (index 3) equals "TRUE"  — user has ticked the Confirmed checkbox
///   - Column F (index 5) is empty       — engine has not yet written AcknowledgedAt
///
/// Row index 0 is treated as the header and is always skipped.
/// The returned `row_index` is 1-based (matching sheet row numbers):
///   array index 1 → sheet row 2, array index n → sheet row n+1.
fn pending_from_rows(rows: &[serde_json::Value]) -> Vec<PendingRow> {
    let mut pending = Vec::new();
    // Skip index 0 (header row). For a row at array index i, the sheet row
    // number is i + 1 (the header occupies sheet row 1, so data starts at 2,
    // meaning array index 1 → sheet row 2, i.e. i + 1).
    for (i, entry) in rows.iter().enumerate().skip(1) {
        let cols = match entry.as_array() {
            Some(c) => c,
            None => continue,
        };

        // D = index 3 (Confirmed), F = index 5 (AcknowledgedAt)
        if col_str(cols, 3) == "TRUE" && col_str(cols, 5).is_empty() {
            pending.push(PendingRow {
                row_index: i + 1,
                message_id: col_str(cols, 4).to_string(), // E
                chat_id:    col_str(cols, 6).to_string(), // G
            });
        }
    }
    pending
}

/// Extracts the bare spreadsheet ID from either a raw ID or a full Google Sheets URL.
///
/// Handles the two forms users typically copy from their browser:
///   - `https://docs.google.com/spreadsheets/d/{ID}/edit`
///   - `https://docs.google.com/spreadsheets/d/{ID}/edit#gid=0`
///
/// If the input doesn't contain `/d/`, it is returned unchanged (already a bare ID).
fn extract_spreadsheet_id(input: &str) -> &str {
    // Split on "/d/" and take the segment that follows.
    // Then trim everything from the first '/', '?', or '#' onwards.
    match input.split("/d/").nth(1) {
        Some(after_d) => after_d
            .split(|c| c == '/' || c == '?' || c == '#')
            .next()
            .unwrap_or(after_d),
        None => input,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── extract_spreadsheet_id ────────────────────────────────────────────────

    #[test]
    fn id_bare_passthrough() {
        assert_eq!(
            extract_spreadsheet_id("1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"),
            "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms"
        );
    }

    #[test]
    fn id_full_url_edit_suffix() {
        assert_eq!(
            extract_spreadsheet_id(
                "https://docs.google.com/spreadsheets/d/SHEET_ID/edit"
            ),
            "SHEET_ID"
        );
    }

    #[test]
    fn id_full_url_gid_anchor() {
        assert_eq!(
            extract_spreadsheet_id(
                "https://docs.google.com/spreadsheets/d/SHEET_ID/edit#gid=0"
            ),
            "SHEET_ID"
        );
    }

    #[test]
    fn id_full_url_query_param() {
        assert_eq!(
            extract_spreadsheet_id(
                "https://docs.google.com/spreadsheets/d/SHEET_ID?usp=sharing"
            ),
            "SHEET_ID"
        );
    }

    #[test]
    fn id_full_url_edit_and_anchor() {
        assert_eq!(
            extract_spreadsheet_id(
                "https://docs.google.com/spreadsheets/d/SHEET_ID/edit?usp=sharing#gid=123"
            ),
            "SHEET_ID"
        );
    }

    // ── col_str ───────────────────────────────────────────────────────────────

    #[test]
    fn col_str_valid_string_first_col() {
        let cols = vec![json!("hello"), json!("world")];
        assert_eq!(col_str(&cols, 0), "hello");
    }

    #[test]
    fn col_str_valid_string_later_col() {
        let cols = vec![json!("a"), json!("b"), json!("c")];
        assert_eq!(col_str(&cols, 2), "c");
    }

    #[test]
    fn col_str_index_out_of_bounds_returns_empty() {
        let cols = vec![json!("only")];
        assert_eq!(col_str(&cols, 5), "");
    }

    #[test]
    fn col_str_json_null_returns_empty() {
        let cols = vec![json!(null)];
        assert_eq!(col_str(&cols, 0), "");
    }

    #[test]
    fn col_str_json_boolean_returns_empty() {
        // Google may send raw booleans for unformatted checkboxes.
        let cols = vec![json!(true)];
        assert_eq!(col_str(&cols, 0), "");
    }

    #[test]
    fn col_str_json_number_returns_empty() {
        let cols = vec![json!(42)];
        assert_eq!(col_str(&cols, 0), "");
    }

    // ── pending_from_rows ─────────────────────────────────────────────────────

    /// Build a full A–G row as the Sheets API would return it.
    fn make_row(sender: &str, bank: &str, amount: &str, confirmed: &str, msg_id: &str, ack: &str, chat_id: &str) -> serde_json::Value {
        json!([sender, bank, amount, confirmed, msg_id, ack, chat_id])
    }

    fn header() -> serde_json::Value {
        json!(["Sender", "Bank", "Amount", "Confirmed", "MessageID", "AcknowledgedAt", "ChatID"])
    }

    #[test]
    fn pending_empty_array_returns_empty() {
        assert!(pending_from_rows(&[]).is_empty());
    }

    #[test]
    fn pending_header_only_returns_empty() {
        // Array index 0 is always skipped as the header row.
        let rows = vec![header()];
        assert!(pending_from_rows(&rows).is_empty());
    }

    #[test]
    fn pending_confirmed_unacknowledged_is_included() {
        let rows = vec![
            header(),
            make_row("Ada Obi", "GTBank", "₦5,000.00", "TRUE", "MSG001", "", "2349000000001@c.us"),
        ];
        let pending = pending_from_rows(&rows);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message_id, "MSG001");
        assert_eq!(pending[0].chat_id, "2349000000001@c.us");
    }

    #[test]
    fn pending_confirmed_already_acknowledged_is_excluded() {
        let rows = vec![
            header(),
            make_row("Ada Obi", "GTBank", "₦5,000.00", "TRUE", "MSG001", "2024-01-01T00:00:00Z", "chat@c.us"),
        ];
        assert!(pending_from_rows(&rows).is_empty());
    }

    #[test]
    fn pending_not_confirmed_is_excluded() {
        let rows = vec![
            header(),
            make_row("Ada Obi", "GTBank", "₦5,000.00", "FALSE", "MSG001", "", "chat@c.us"),
        ];
        assert!(pending_from_rows(&rows).is_empty());
    }

    #[test]
    fn pending_row_index_is_one_based_sheet_row() {
        // Array index 1 → sheet row 2, array index 2 → sheet row 3.
        let rows = vec![
            header(),
            make_row("Sender A", "BankA", "₦1.00", "TRUE", "M1", "", "c1@c.us"),
            make_row("Sender B", "BankB", "₦2.00", "TRUE", "M2", "", "c2@c.us"),
        ];
        let pending = pending_from_rows(&rows);
        assert_eq!(pending[0].row_index, 2);
        assert_eq!(pending[1].row_index, 3);
    }

    #[test]
    fn pending_mixed_rows_only_returns_unacknowledged_confirmed() {
        let rows = vec![
            header(),
            make_row("A", "BankA", "₦1.00", "TRUE",  "M1", "",                    "c1@c.us"), // included
            make_row("B", "BankB", "₦2.00", "FALSE", "M2", "",                    "c2@c.us"), // excluded — not confirmed
            make_row("C", "BankC", "₦3.00", "TRUE",  "M3", "2024-01-01T00:00:00Z","c3@c.us"), // excluded — already ack'd
            make_row("D", "BankD", "₦4.00", "TRUE",  "M4", "",                    "c4@c.us"), // included
        ];
        let pending = pending_from_rows(&rows);
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].message_id, "M1");
        assert_eq!(pending[1].message_id, "M4");
        assert_eq!(pending[0].row_index, 2);
        assert_eq!(pending[1].row_index, 5);
    }

    #[test]
    fn pending_short_row_missing_message_id_and_chat_id() {
        // Google omits trailing empty cells — a row may have fewer than 7 columns.
        // Columns E and G will be absent; col_str returns "" for those.
        let rows = vec![
            header(),
            json!(["Sender", "Bank", "Amount", "TRUE"]), // only 4 cols
        ];
        let pending = pending_from_rows(&rows);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].message_id, "");
        assert_eq!(pending[0].chat_id, "");
        assert_eq!(pending[0].row_index, 2);
    }

    #[test]
    fn pending_non_array_entry_is_skipped() {
        // Defensive: if a row is not a JSON array, skip it silently.
        let rows = vec![
            header(),
            json!("not an array"),
            make_row("Ada", "GTBank", "₦1.00", "TRUE", "M1", "", "c@c.us"),
        ];
        let pending = pending_from_rows(&rows);
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].row_index, 3); // array index 2 → sheet row 3
    }
}
