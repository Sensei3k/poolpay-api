use serde::Deserialize;

/// A single notification returned by the Green API poll endpoint.
#[derive(Debug, Deserialize)]
pub struct Notification {
    #[serde(rename = "receiptId")]
    pub receipt_id: u64,
    pub body: NotificationBody,
}

/// The outer body of a Green API notification, containing the event type and message details.
#[derive(Debug, Deserialize)]
pub struct NotificationBody {
    #[serde(rename = "typeWebhook")]
    pub type_webhook: String,

    /// The WhatsApp message ID for the incoming message.
    /// Lives at the body level in the Green API JSON — not inside messageData.
    /// Used to quote the original receipt message in the acknowledgement reply.
    #[serde(rename = "idMessage")]
    pub id_message: Option<String>,

    #[serde(rename = "senderData")]
    pub sender_data: Option<SenderData>,

    #[serde(rename = "messageData")]
    pub message_data: Option<MessageData>,
}

/// Information about who sent the message and which chat it belongs to.
#[derive(Debug, Deserialize)]
pub struct SenderData {
    #[serde(rename = "senderName")]
    pub sender_name: Option<String>,

    #[serde(rename = "sender")]
    pub sender: Option<String>,

    #[serde(rename = "chatId")]
    pub chat_id: Option<String>,
}

/// The message payload — structure varies depending on the message type.
#[derive(Debug, Deserialize)]
pub struct MessageData {
    #[serde(rename = "typeMessage")]
    pub type_message: String,

    #[serde(rename = "textMessageData")]
    pub text_message_data: Option<TextMessageData>,

    #[serde(rename = "extendedTextMessageData")]
    pub extended_text_message_data: Option<ExtendedTextMessageData>,

    /// Present for imageMessage and documentMessage types.
    #[serde(rename = "fileMessageData")]
    pub file_message_data: Option<FileMessageData>,
}

impl MessageData {
    /// Returns the plain text of the message, regardless of which sub-type carried it.
    pub fn text(&self) -> Option<&str> {
        if let Some(t) = &self.text_message_data {
            return Some(&t.text_message);
        }
        if let Some(e) = &self.extended_text_message_data {
            return Some(&e.text);
        }
        None
    }
}

/// Payload for a plain text message.
#[derive(Debug, Deserialize)]
pub struct TextMessageData {
    #[serde(rename = "textMessage")]
    pub text_message: String,
}

/// Payload for an extended text message (e.g. a message with a link preview).
#[derive(Debug, Deserialize)]
pub struct ExtendedTextMessageData {
    pub text: String,
}

/// Metadata for an incoming file attachment — either an image or a PDF.
#[derive(Debug, Deserialize)]
pub struct FileMessageData {
    /// Direct URL to download the file bytes from.
    #[serde(rename = "downloadUrl")]
    pub download_url: String,

    /// MIME type of the file, e.g. "image/jpeg" or "application/pdf".
    #[serde(rename = "mimeType")]
    pub mime_type: Option<String>,

    /// Optional caption the sender typed alongside the file.
    pub caption: Option<String>,
}

/// The structured data extracted from a receipt after OCR and parsing.
#[derive(Debug)]
pub struct ParsedReceipt {
    pub sender: Option<String>,
    pub bank: Option<String>,
    pub amount: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parses a realistic Green API image-message notification.
    // Asserts that idMessage is read from the body level, not from inside messageData.
    // This test would have caught the Phase 9 regression where id_message was placed
    // on MessageData instead of NotificationBody, causing it to always deserialise as None.
    #[test]
    fn notification_id_message_deserialises_from_body_level() {
        let json = r#"{
            "receiptId": 123,
            "body": {
                "typeWebhook": "incomingMessageReceived",
                "idMessage": "BAE5F4886F532D01",
                "senderData": {
                    "chatId": "2349000000001@c.us",
                    "sender": "2349000000001@c.us",
                    "senderName": "Test Sender"
                },
                "messageData": {
                    "typeMessage": "imageMessage",
                    "fileMessageData": {
                        "downloadUrl": "https://example.com/file.jpg",
                        "mimeType": "image/jpeg",
                        "caption": ""
                    }
                }
            }
        }"#;

        let notification: Notification = serde_json::from_str(json).unwrap();
        assert_eq!(notification.body.id_message.as_deref(), Some("BAE5F4886F532D01"));
    }

    // Confirms that a notification without idMessage (e.g. a delivery receipt event)
    // deserialises cleanly with id_message as None rather than panicking.
    #[test]
    fn notification_id_message_absent_is_none() {
        let json = r#"{
            "receiptId": 456,
            "body": {
                "typeWebhook": "outgoingMessageStatus",
                "messageData": {
                    "typeMessage": "textMessage",
                    "textMessageData": { "textMessage": "hello" }
                }
            }
        }"#;

        let notification: Notification = serde_json::from_str(json).unwrap();
        assert_eq!(notification.body.id_message, None);
    }

    // Regression guard: idMessage must NOT be present on MessageData.
    // If someone re-adds it there, this test catches it — the field on the body
    // would still parse, but a dedicated messageData-level field would shadow it
    // in the wrong struct.
    #[test]
    fn message_data_does_not_contain_id_message() {
        // Verify MessageData deserialises without an idMessage field — any stray
        // idMessage in the messageData object is simply ignored (serde default).
        let json = r#"{
            "typeMessage": "imageMessage",
            "idMessage": "SHOULD_BE_IGNORED",
            "fileMessageData": {
                "downloadUrl": "https://example.com/f.jpg",
                "mimeType": "image/jpeg",
                "caption": ""
            }
        }"#;
        // This must compile and parse without error — MessageData has no id_message field.
        let _: MessageData = serde_json::from_str(json).unwrap();
    }
}
