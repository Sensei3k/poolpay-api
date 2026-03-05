// Phase 2 — Detect image attachments, download them to a temp folder,
// and confirm receipt in the terminal.
//
// Green API "receive & delete" poll model (same as Phase 1):
//   1. Call /receiveNotification  → get the oldest queued notification
//   2. Call /deleteNotification   → acknowledge it so it doesn't repeat

use dotenv::dotenv;
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::path::PathBuf;
use tokio::fs;
use tokio::time::{sleep, Duration};

// --------------------------------------------------------------------------
// Data structures
// --------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Notification {
    #[serde(rename = "receiptId")]
    receipt_id: u64,
    body: NotificationBody,
}

#[derive(Debug, Deserialize)]
struct NotificationBody {
    #[serde(rename = "typeWebhook")]
    type_webhook: String,

    #[serde(rename = "senderData")]
    sender_data: Option<SenderData>,

    #[serde(rename = "messageData")]
    message_data: Option<MessageData>,
}

#[derive(Debug, Deserialize)]
struct SenderData {
    #[serde(rename = "senderName")]
    sender_name: Option<String>,

    #[serde(rename = "sender")]
    sender: Option<String>,
}

// Green API message types we handle:
//   "textMessage"         → textMessageData.textMessage
//   "extendedTextMessage" → extendedTextMessageData.text
//   "imageMessage"        → imageMessageData.downloadUrl  (Phase 2)
#[derive(Debug, Deserialize)]
struct MessageData {
    #[serde(rename = "typeMessage")]
    type_message: String,

    #[serde(rename = "textMessageData")]
    text_message_data: Option<TextMessageData>,

    #[serde(rename = "extendedTextMessageData")]
    extended_text_message_data: Option<ExtendedTextMessageData>,

    // Present when typeMessage == "imageMessage"
    #[serde(rename = "fileMessageData")]
    image_message_data: Option<ImageMessageData>,
}

#[derive(Debug, Deserialize)]
struct TextMessageData {
    #[serde(rename = "textMessage")]
    text_message: String,
}

#[derive(Debug, Deserialize)]
struct ExtendedTextMessageData {
    text: String,
}

// Metadata for an incoming image attachment.
#[derive(Debug, Deserialize)]
struct ImageMessageData {
    // The URL we fetch to download the actual image bytes
    #[serde(rename = "downloadUrl")]
    download_url: String,

    // File extension hint, e.g. "image/jpeg" — used to pick a file extension
    #[serde(rename = "mimeType")]
    mime_type: Option<String>,

    // Optional text the sender typed alongside the image
    caption: Option<String>,
}

impl MessageData {
    /// Return the message text regardless of which sub-type carried it.
    fn text(&self) -> Option<&str> {
        if let Some(t) = &self.text_message_data {
            return Some(&t.text_message);
        }
        if let Some(e) = &self.extended_text_message_data {
            return Some(&e.text);
        }
        None
    }
}

// --------------------------------------------------------------------------
// Image download
// --------------------------------------------------------------------------

/// Download an image from `url` and save it to the system temp directory.
/// Returns the full path of the saved file on success.
///
/// The filename is built from the receipt_id so it's unique per message,
/// e.g. /tmp/receipt_engine/image_3.jpg
async fn download_image(
    client: &Client,
    url: &str,
    mime_type: Option<&str>,
    receipt_id: u64,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    // Pick a file extension from the mime type, defaulting to .jpg
    let extension = match mime_type {
        Some("image/png") => "png",
        Some("image/gif") => "gif",
        Some("image/webp") => "webp",
        _ => "jpg",
    };

    // Build the destination folder and create it if it doesn't exist
    let dir = PathBuf::from("/private/tmp/receipt_engine");
    fs::create_dir_all(&dir).await?;

    let filename = format!("image_{}.{}", receipt_id, extension);
    let dest = dir.join(filename);

    // Fetch the image bytes
    let bytes = client.get(url).send().await?.bytes().await?;

    // Write to disk
    fs::write(&dest, &bytes).await?;

    Ok(dest)
}

// --------------------------------------------------------------------------
// OCR
// --------------------------------------------------------------------------

/// Run Tesseract OCR on the image at `path` and return the extracted text.
fn ocr_image(path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let text = tesseract::ocr(path.to_str().unwrap(), "eng")?;
    Ok(text)
}

// --------------------------------------------------------------------------
// API helpers
// --------------------------------------------------------------------------

/// Fetch the oldest pending notification from Green API.
/// Returns None when the queue is empty (Green API returns the literal "null").
async fn receive_notification(
    client: &Client,
    instance_id: &str,
    api_token: &str,
) -> Result<Option<Notification>, Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.green-api.com/waInstance{}/receiveNotification/{}",
        instance_id, api_token
    );

    let body = client.get(&url).send().await?.text().await?;

    if body.trim() == "null" {
        return Ok(None);
    }

    let notification: Notification = serde_json::from_str(&body)?;
    Ok(Some(notification))
}

/// Acknowledge a notification so Green API removes it from the queue.
async fn delete_notification(
    client: &Client,
    instance_id: &str,
    api_token: &str,
    receipt_id: u64,
) -> Result<(), reqwest::Error> {
    let url = format!(
        "https://api.green-api.com/waInstance{}/deleteNotification/{}/{}",
        instance_id, api_token, receipt_id
    );

    client.delete(&url).send().await?;
    Ok(())
}

/// Print a notification summary to the terminal.
fn print_notification(n: &Notification) {
    let body = &n.body;
    println!("---");
    println!("Type   : {}", body.type_webhook);

    if let Some(s) = &body.sender_data {
        println!(
            "From   : {} ({})",
            s.sender_name.as_deref().unwrap_or("unknown"),
            s.sender.as_deref().unwrap_or("unknown")
        );
    }

    if let Some(msg) = &body.message_data {
        println!("MsgType: {}", msg.type_message);

        if let Some(text) = msg.text() {
            println!("Text   : {}", text);
        }

        if let Some(img) = &msg.image_message_data {
            if let Some(caption) = &img.caption {
                if !caption.is_empty() {
                    println!("Caption: {}", caption);
                }
            }
        }
    }

    println!("---");
}

// --------------------------------------------------------------------------
// Main
// --------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    dotenv().ok();

    let instance_id = env::var("GREEN_API_INSTANCE_ID")
        .expect("GREEN_API_INSTANCE_ID must be set in .env");

    let api_token = env::var("GREEN_API_TOKEN")
        .expect("GREEN_API_TOKEN must be set in .env");

    let client = Client::new();

    println!("Receipt engine started. Polling for messages every 5 seconds...");

    loop {
        match receive_notification(&client, &instance_id, &api_token).await {
            Ok(Some(notification)) => {
                print_notification(&notification);

                // If this message contains an image, download it now
                if let Some(msg) = &notification.body.message_data {
                    if let Some(img) = &msg.image_message_data {
                        println!("Image detected — downloading...");

                        match download_image(
                            &client,
                            &img.download_url,
                            img.mime_type.as_deref(),
                            notification.receipt_id,
                        )
                        .await
                        {
                            Ok(path) => {
                                println!("Image saved to: {}", path.display());
                                println!("Running OCR...");
                                match ocr_image(&path) {
                                    Ok(text) => println!("OCR result:\n{}", text),
                                    Err(e) => eprintln!("OCR failed: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Failed to download image: {}", e),
                        }
                    }
                }

                if let Err(e) = delete_notification(
                    &client,
                    &instance_id,
                    &api_token,
                    notification.receipt_id,
                )
                .await
                {
                    eprintln!("Warning: failed to delete notification: {}", e);
                }
            }

            Ok(None) => {
                println!("[tick] No new messages.");
            }

            Err(e) => {
                eprintln!("Error polling Green API: {}", e);
            }
        }

        sleep(Duration::from_secs(5)).await;
    }
}
