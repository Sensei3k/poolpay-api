use crate::models::ReceiptRow;
use reqwest::Client;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::info;
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
    pub async fn new(
        key_path: &str,
        spreadsheet_id: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let key = yup_oauth2::read_service_account_key(key_path).await?;
        Ok(Self {
            http: Client::new(),
            spreadsheet_id,
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

    /// Returns a valid access token, refreshing from Google if the cached one
    /// has expired or was never fetched.
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
