use crate::models::{FileMessageData, Notification};
use reqwest::Client;
use std::path::PathBuf;
use tokio::fs;
use tracing::info;

/// Returns the directory where downloaded receipt files are saved.
/// Reads `RECEIPT_DOWNLOAD_DIR` from the environment; falls back to the
/// OS temp directory so the code works on macOS, Linux, and Windows.
fn download_dir() -> PathBuf {
    std::env::var("RECEIPT_DOWNLOAD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir().join("receipt_engine"))
}

/// Maximum file size accepted for download — protects against memory exhaustion.
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB

/// Builds a Green API endpoint URL.
///
/// # Security note
/// Green API embeds the API token in the URL path — this is their required authentication
/// scheme and cannot be changed to a header. Never log or print these URLs; doing so would
/// expose the token in stdout, log files, and any intermediate proxy access logs.
fn api_url(instance_id: &str, path: &str, api_token: &str) -> String {
    format!(
        "https://api.green-api.com/waInstance{}/{}/{}",
        instance_id, path, api_token
    )
}

/// Fetches the oldest pending notification from the Green API queue.
/// Returns None when the queue is empty (Green API responds with "null").
pub async fn receive_notification(
    client: &Client,
    instance_id: &str,
    api_token: &str,
) -> Result<Option<Notification>, Box<dyn std::error::Error>> {
    let url = api_url(instance_id, "receiveNotification", api_token);

    let body = client.get(&url).send().await?.text().await?;

    if body.trim() == "null" {
        return Ok(None);
    }

    let notification: Notification = serde_json::from_str(&body)?;
    Ok(Some(notification))
}

/// Acknowledges a notification so Green API removes it from the queue and won't resend it.
pub async fn delete_notification(
    client: &Client,
    instance_id: &str,
    api_token: &str,
    receipt_id: u64,
) -> Result<(), reqwest::Error> {
    let url = format!(
        "{}/{}",
        api_url(instance_id, "deleteNotification", api_token),
        receipt_id
    );

    client.delete(&url).send().await?.error_for_status()?;
    Ok(())
}

/// Sends a text message to a WhatsApp chat via Green API.
/// Returns an error if the API responds with a non-success status code.
pub async fn send_message(
    client: &Client,
    instance_id: &str,
    api_token: &str,
    chat_id: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = api_url(instance_id, "sendMessage", api_token);

    let body = serde_json::json!({
        "chatId": chat_id,
        "message": message,
    });

    let response = client.post(&url).json(&body).send().await?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await?;
        return Err(format!("Green API error {}: {}", status, text).into());
    }
    Ok(())
}

/// Sends a text message to a WhatsApp chat, optionally quoting a previous message.
///
/// When `quoted_message_id` is non-empty, the API request includes a `"quotedMessageId"` field
/// so the reply appears as a quote in WhatsApp. When it is empty, the message is sent without
/// a quote — identical behaviour to `send_message`.
pub async fn send_quoted_message(
    client: &Client,
    instance_id: &str,
    api_token: &str,
    chat_id: &str,
    message: &str,
    quoted_message_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = api_url(instance_id, "sendMessage", api_token);

    let body = if quoted_message_id.is_empty() {
        serde_json::json!({
            "chatId": chat_id,
            "message": message,
        })
    } else {
        serde_json::json!({
            "chatId": chat_id,
            "message": message,
            "quotedMessageId": quoted_message_id,
        })
    };

    let response = client.post(&url).json(&body).send().await?;
    let status = response.status();
    if !status.is_success() {
        let text = response.text().await?;
        return Err(format!("Green API error {}: {}", status, text).into());
    }
    Ok(())
}

/// Downloads a file from the URL in the given FileMessageData and saves it to DOWNLOAD_DIR.
/// The filename is derived from the receipt ID to ensure uniqueness across messages.
pub async fn download_file(
    client: &Client,
    file_data: &FileMessageData,
    receipt_id: u64,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let extension = match file_data.mime_type.as_deref() {
        Some("image/png") => "png",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        Some("application/pdf") => "pdf",
        _ => "jpg",
    };

    let dir = download_dir();
    fs::create_dir_all(&dir).await?;

    let filename = format!("receipt_{}.{}", receipt_id, extension);
    let dest = dir.join(filename);

    let response = client.get(&file_data.download_url).send().await?;

    // Reject before downloading if the server advertises a size over the limit.
    if let Some(len) = response.content_length() {
        if len > MAX_FILE_BYTES {
            return Err(format!(
                "File too large: {} bytes (limit {} bytes)",
                len, MAX_FILE_BYTES
            )
            .into());
        }
    }

    let bytes = response.bytes().await?;

    // Enforce the limit on the actual payload in case Content-Length was absent or wrong.
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "File too large: {} bytes (limit {} bytes)",
            bytes.len(),
            MAX_FILE_BYTES
        )
        .into());
    }

    fs::write(&dest, &bytes).await?;

    Ok(dest)
}

/// Logs a human-readable summary of a notification.
pub fn print_notification(n: &Notification) {
    let body = &n.body;
    let webhook_type = &body.type_webhook;

    let (sender_name, sender) = body.sender_data.as_ref().map_or(
        ("unknown", "unknown"),
        |s| (
            s.sender_name.as_deref().unwrap_or("unknown"),
            s.sender.as_deref().unwrap_or("unknown"),
        ),
    );

    let msg_type = body
        .message_data
        .as_ref()
        .map(|m| m.type_message.as_str())
        .unwrap_or("none");

    info!(
        webhook_type,
        sender_name,
        sender,
        msg_type,
        "Notification received"
    );

    if let Some(msg) = &body.message_data {
        if let Some(text) = msg.text() {
            info!(text, "Text message");
        }
        if let Some(file) = &msg.file_message_data {
            if let Some(caption) = &file.caption {
                if !caption.is_empty() {
                    info!(caption, "File caption");
                }
            }
        }
    }
}
