use receipt_engine::{api, db, extractor, parser, whatsapp};

use dotenv::dotenv;
use std::{env, net::SocketAddr};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

/// How long to wait between polls when the Green API queue is empty.
const RECEIPT_POLL_SECS: u64 = 5;

#[tokio::main]
async fn main() {
    dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let instance_id = env::var("GREEN_API_INSTANCE_ID")
        .expect("GREEN_API_INSTANCE_ID must be set in .env");

    let api_token = env::var("GREEN_API_TOKEN")
        .expect("GREEN_API_TOKEN must be set in .env");

    // Initialise embedded SurrealDB and seed fixture data if the DB is empty.
    let surreal_db = db::init()
        .await
        .expect("Failed to initialise SurrealDB");

    // Spawn the Axum HTTP server.
    // Monitored below — if the server dies the process exits rather than
    // silently running without an API.
    let api_db = surreal_db.clone();
    let api_handle = tokio::spawn(async move {
        let bind_addr = env::var("API_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let addr: SocketAddr = bind_addr
            .parse()
            .expect("API_BIND_ADDR is not a valid socket address");
        let router = api::router(api_db);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind Axum listener");
        info!(addr = %addr, "API server listening");
        if let Err(e) = axum::serve(listener, router).await {
            error!(error = %e, "API server error");
        }
    });

    info!(receipt_poll_secs = RECEIPT_POLL_SECS, "Receipt engine started");

    // Watchdog: if the API server task dies, exit rather than silently
    // continuing with a broken API.
    tokio::spawn(async move {
        let r = api_handle.await;
        error!("API server task exited: {:?} — shutting down", r);
        std::process::exit(1);
    });

    // Receipt loop — polls Green API every 5 s, runs OCR, sends WhatsApp reply.
    //
    // Kept in the main thread: the error type (Box<dyn Error>) is not Send, so
    // the loop cannot be moved into tokio::spawn.
    let client = reqwest::Client::new();
    loop {
        match whatsapp::receive_notification(&client, &instance_id, &api_token).await {
            Ok(Some(notification)) => {
                whatsapp::print_notification(&notification);

                let mut processing_ok = true;

                if let Some(msg) = &notification.body.message_data {
                    if let Some(file_data) = &msg.file_message_data {
                        let is_pdf =
                            file_data.mime_type.as_deref() == Some("application/pdf");

                        info!(
                            file_type = if is_pdf { "PDF" } else { "Image" },
                            "File detected, downloading"
                        );

                        match whatsapp::download_file(&client, file_data, notification.receipt_id)
                            .await
                        {
                            Ok(path) => {
                                info!(path = %path.display(), "File saved, running OCR");

                                let ocr_result = if is_pdf {
                                    extractor::ocr_pdf(&path)
                                } else {
                                    extractor::ocr_image(&path)
                                };

                                // Clean up the local file now that OCR has run (or failed).
                                if let Err(e) = tokio::fs::remove_file(&path).await {
                                    warn!(path = %path.display(), error = %e, "Failed to clean up temp file");
                                }

                                match ocr_result {
                                    Ok(text) => {
                                        info!(ocr_text = %text, "OCR complete");
                                        let parsed = parser::parse_receipt(&text);
                                        parser::print_parsed(&parsed);

                                        let chat_id = notification
                                            .body
                                            .sender_data
                                            .as_ref()
                                            .and_then(|s| s.chat_id.as_deref());

                                        if let Some(chat_id) = chat_id {
                                            let sender = parsed.sender.unwrap_or_else(|| "unknown".to_string());
                                            let bank = parsed.bank.unwrap_or_else(|| "unknown".to_string());
                                            let amount = parsed.amount.unwrap_or_else(|| "unknown".to_string());

                                            let reply = format!(
                                                "✅ Sender: {}\nBank: {}\nAmount: {}",
                                                sender, bank, amount,
                                            );

                                            match whatsapp::send_message(
                                                &client,
                                                &instance_id,
                                                &api_token,
                                                chat_id,
                                                &reply,
                                            )
                                            .await
                                            {
                                                Ok(_) => info!(chat_id, "Reply sent"),
                                                Err(e) => {
                                                    error!(error = %e, "Failed to send reply");
                                                    processing_ok = false;
                                                }
                                            }
                                        } else {
                                            error!("No chat_id found — cannot send reply");
                                            processing_ok = false;
                                        }
                                    }
                                    Err(e) => {
                                        error!(error = %e, "OCR failed");
                                        processing_ok = false;
                                    }
                                }
                            }
                            Err(e) => {
                                error!(error = %e, "Failed to download file");
                                processing_ok = false;
                            }
                        }
                    }
                }

                // Always acknowledge the notification to prevent infinite reprocessing.
                // If processing failed, log a clear discard notice so nothing is silent.
                if !processing_ok {
                    warn!(
                        receipt_id = notification.receipt_id,
                        "Discarding receipt after processing failure — will not retry"
                    );
                }

                if let Err(e) = whatsapp::delete_notification(
                    &client,
                    &instance_id,
                    &api_token,
                    notification.receipt_id,
                )
                .await
                {
                    warn!(error = %e, "Failed to delete notification");
                }
            }

            Ok(None) => {
                info!("No new messages");
            }

            Err(e) => {
                error!(error = %e, "Error polling Green API");
            }
        }

        sleep(Duration::from_secs(RECEIPT_POLL_SECS)).await;
    }
}
