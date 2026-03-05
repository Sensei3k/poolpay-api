// Phase 2 — Detect image attachments, download them to a temp folder,
// and confirm receipt in the terminal.
//
// Green API "receive & delete" poll model (same as Phase 1):
//   1. Call /receiveNotification  → get the oldest queued notification
//   2. Call /deleteNotification   → acknowledge it so it doesn't repeat

use dotenv::dotenv;
use regex::Regex;
use reqwest::Client;
use serde::Deserialize;
use std::env;
use std::path::PathBuf;
use std::process::Command;
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

    #[serde(rename = "chatId")]
    chat_id: Option<String>,
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
        Some("application/pdf") => "pdf",
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

/// Convert each page of a PDF to a JPEG using pdftoppm, then OCR each page.
/// Returns all pages' text concatenated.
fn ocr_pdf(pdf_path: &std::path::Path) -> Result<String, Box<dyn std::error::Error>> {
    let dir = pdf_path.parent().unwrap();
    let stem = pdf_path.file_stem().unwrap().to_str().unwrap();
    let prefix = dir.join(stem);

    // pdftoppm -jpeg <pdf> <output_prefix>  →  <prefix>-1.jpg, <prefix>-2.jpg, …
    let status = Command::new("pdftoppm")
        .args(["-jpeg", pdf_path.to_str().unwrap(), prefix.to_str().unwrap()])
        .status()?;

    if !status.success() {
        return Err("pdftoppm failed".into());
    }

    // Collect and OCR each generated page image
    let mut all_text = String::new();
    let mut page = 1;
    loop {
        // pdftoppm zero-pads page numbers, e.g. -01, -001 depending on count.
        // Glob both patterns to find the right file.
        let candidates = [
            dir.join(format!("{}-{}.jpg", stem, page)),
            dir.join(format!("{}-{:02}.jpg", stem, page)),
            dir.join(format!("{}-{:03}.jpg", stem, page)),
        ];

        let page_path = candidates.iter().find(|p| p.exists());
        match page_path {
            None => break,
            Some(p) => {
                println!("  OCR page {}...", page);
                match ocr_image(p) {
                    Ok(text) => all_text.push_str(&text),
                    Err(e) => eprintln!("  OCR failed on page {}: {}", page, e),
                }
                page += 1;
            }
        }
    }

    Ok(all_text)
}

// --------------------------------------------------------------------------
// Receipt parsing
// --------------------------------------------------------------------------

#[derive(Debug)]
struct ParsedReceipt {
    sender: Option<String>,
    bank: Option<String>,
    amount: Option<String>,
}

/// Extract sender name, bank name, and amount from raw OCR text.
fn parse_receipt(text: &str) -> ParsedReceipt {
    let lines: Vec<&str> = text.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();

    // --- Amount ---
    // Tesseract often renders ₦ as #, so match both.
    // Patterns: #97,800.00  ₦97,800.00  NGN 97,800.00
    let amount_re = Regex::new(r"(?:[#₦]|NGN\s*)[\d,]+(?:\.\d{1,2})?").unwrap();
    let amount = amount_re.find(text).map(|m| {
        m.as_str().trim().replace('#', "₦")
    });

    // --- Sender + Bank ---
    // Receipt layout (OPay / Moniepoint style):
    //   "Sender Details  FULL NAME"   ← name on same line as label
    //   "BankName | account"          ← bank on the very next line
    let sender_label_re = Regex::new(r"(?i)sender\s+details?\s+(.+)").unwrap();
    let fallback_sender_re = Regex::new(
        r"(?i)(?:sender(?:\s+name)?|from|originator)\s*[:\-]?\s*([A-Za-z][A-Za-z\s]{2,40})"
    ).unwrap();

    let mut sender: Option<String> = None;
    let mut bank: Option<String> = None;

    for (i, line) in lines.iter().enumerate() {
        // Try "Sender Details NAME" pattern first
        if let Some(caps) = sender_label_re.captures(line) {
            sender = caps.get(1).map(|m| m.as_str().trim().to_string());
            // Bank is on the next non-empty line, before any "|"
            if let Some(next) = lines.get(i + 1) {
                let bank_name = next.split('|').next().unwrap_or(next).trim();
                if !bank_name.is_empty() {
                    bank = Some(bank_name.to_string());
                }
            }
            break;
        }
    }

    // Fallback sender if the label style was different
    if sender.is_none() {
        sender = fallback_sender_re
            .captures(text)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim().to_string());
    }

    // Fallback bank: scan for known Nigerian bank / fintech names
    if bank.is_none() {
        let known_banks_re = Regex::new(
            r"(?i)\b(gtbank|access bank|zenith bank|first bank|uba|opay|kuda|palmpay|moniepoint|monie point|sterling|polaris|fidelity|union bank|wema|stanbic|ecobank|providus)\b"
        ).unwrap();
        bank = known_banks_re.find(text).map(|m| m.as_str().trim().to_string());
    }

    ParsedReceipt { sender, bank, amount }
}

/// Print a ParsedReceipt to the terminal.
fn print_parsed(parsed: &ParsedReceipt) {
    println!("--- Parsed Receipt ---");
    println!("Sender : {}", parsed.sender.as_deref().unwrap_or("not found"));
    println!("Bank   : {}", parsed.bank.as_deref().unwrap_or("not found"));
    println!("Amount : {}", parsed.amount.as_deref().unwrap_or("not found"));
    println!("----------------------");
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

/// Send a text message to a WhatsApp chat via Green API.
async fn send_message(
    client: &Client,
    instance_id: &str,
    api_token: &str,
    chat_id: &str,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!(
        "https://api.green-api.com/waInstance{}/sendMessage/{}",
        instance_id, api_token
    );

    let body = serde_json::json!({
        "chatId": chat_id,
        "message": message,
    });

    client.post(&url).json(&body).send().await?;
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

                // If this message contains an image or document, download and OCR it
                if let Some(msg) = &notification.body.message_data {
                    if let Some(img) = &msg.image_message_data {
                        let is_pdf = img.mime_type.as_deref() == Some("application/pdf");
                        println!("{} detected — downloading...", if is_pdf { "PDF" } else { "Image" });

                        match download_image(
                            &client,
                            &img.download_url,
                            img.mime_type.as_deref(),
                            notification.receipt_id,
                        )
                        .await
                        {
                            Ok(path) => {
                                println!("File saved to: {}", path.display());
                                println!("Running OCR...");
                                let result = if is_pdf {
                                    ocr_pdf(&path)
                                } else {
                                    ocr_image(&path)
                                };
                                match result {
                                    Ok(text) => {
                                        println!("OCR result:\n{}", text);
                                        let parsed = parse_receipt(&text);
                                        print_parsed(&parsed);

                                        // Send the extracted data back to the chat
                                        let chat_id = notification
                                            .body
                                            .sender_data
                                            .as_ref()
                                            .and_then(|s| s.chat_id.as_deref());

                                        if let Some(chat_id) = chat_id {
                                            let reply = format!(
                                                "✅ Sender: {} | Bank: {} | Amount: {}",
                                                parsed.sender.as_deref().unwrap_or("unknown"),
                                                parsed.bank.as_deref().unwrap_or("unknown"),
                                                parsed.amount.as_deref().unwrap_or("unknown"),
                                            );
                                            match send_message(&client, &instance_id, &api_token, chat_id, &reply).await {
                                                Ok(_) => println!("Reply sent to {}", chat_id),
                                                Err(e) => eprintln!("Failed to send reply: {}", e),
                                            }
                                        } else {
                                            eprintln!("No chat_id found — cannot send reply");
                                        }
                                    }
                                    Err(e) => eprintln!("OCR failed: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Failed to download file: {}", e),
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
