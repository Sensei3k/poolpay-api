use poolpay::auth::jwt::{JwtConfig, SharedVerifier, StaticKeyVerifier};
use poolpay::auth::rate_limit::RateLimitConfig;
use poolpay::{api, auth, db, extractor, ingestion, parser, replies, whatsapp};
use poolpay::api::models::now_iso;
use std::sync::Arc;

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

    // HMAC strength depends on key entropy. hmac.rs only rejects an empty
    // secret, so a 6-char value would silently pass. Fail fast on anything
    // shorter than 32 bytes (matches `openssl rand -hex 32` in .env.example).
    // Panic in production; warn elsewhere so local dev with a throwaway
    // secret stays frictionless.
    const MIN_SECRET_LEN: usize = 32;
    match env::var("NEXTAUTH_BACKEND_SECRET") {
        Ok(s) if s.len() >= MIN_SECRET_LEN => {}
        Ok(s) => {
            let msg = format!(
                "NEXTAUTH_BACKEND_SECRET must be at least {MIN_SECRET_LEN} bytes (got {})",
                s.len()
            );
            if env::var("APP_ENV").as_deref() == Ok("production") {
                panic!("{msg}");
            } else {
                warn!("{msg} — acceptable in non-production only");
            }
        }
        Err(_) => {
            if env::var("APP_ENV").as_deref() == Ok("production") {
                panic!("NEXTAUTH_BACKEND_SECRET must be set in production");
            } else {
                warn!("NEXTAUTH_BACKEND_SECRET is not set — HMAC endpoints will reject all requests");
            }
        }
    }

    // Boot-time JWT verifier. In production this panics if JWT_KEYS is unset
    // or has no active key; in dev/test an ephemeral RSA keypair is generated
    // so `cargo run` needs no extra setup.
    let verifier: SharedVerifier = Arc::new(
        StaticKeyVerifier::from_env(JwtConfig::from_env())
            .unwrap_or_else(|err| panic!("Failed to initialise JWT verifier: {err}")),
    );

    // Parse rate-limit config once at boot and reuse the same instance for
    // both the boot-time safety warning and the router. Previously main.rs
    // duplicated `TRUST_PROXY_HEADERS` parsing which drifted from
    // `parse_bool()` semantics — reusing `RateLimitConfig::from_env()` here
    // guarantees the warning fires for exactly the same inputs the limiter
    // actually trusts.
    let rate_cfg = RateLimitConfig::from_env();

    // When the per-IP limiter is configured to trust proxy headers, the
    // deployed proxy MUST strip any client-supplied X-Forwarded-For before
    // setting its own — otherwise a client can spoof their source IP and
    // bypass per-IP rate limiting. Emit a prominent warning at boot so a
    // misconfigured proxy cannot silently neutralise the limiter.
    if rate_cfg.trust_proxy_headers && env::var("APP_ENV").as_deref() == Ok("production") {
        warn!(
            "TRUST_PROXY_HEADERS=true in production — confirm the upstream proxy \
             strips client-supplied X-Forwarded-For before appending; otherwise \
             per-IP rate limiting can be bypassed by header spoofing"
        );
    }

    // Pre-warm the dummy Argon2 hash so the first unknown-email login path is
    // not measurably slower than subsequent ones (closes a timing side channel
    // around user enumeration).
    auth::password::prewarm();

    // Initialise embedded SurrealDB and, if SEED_ON_EMPTY=true and the DB is empty, seed fixture data.
    let surreal_db = db::init()
        .await
        .expect("Failed to initialise SurrealDB");

    if let Err(e) = auth::bootstrap::ensure_admin_user(&surreal_db).await {
        error!(error = %e, "Bootstrap admin seeding failed");
    }

    // Spawn the Axum HTTP server.
    // Monitored below — if the server dies the process exits rather than
    // silently running without an API.
    let api_db = surreal_db.clone();
    let api_handle = tokio::spawn(async move {
        let bind_addr = env::var("API_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
        let addr: SocketAddr = bind_addr
            .parse()
            .expect("API_BIND_ADDR is not a valid socket address");
        let router = api::router_with_config(api_db, rate_cfg, verifier);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .expect("Failed to bind Axum listener");
        info!(addr = %addr, "API server listening");
        // `into_make_service_with_connect_info` populates the `ConnectInfo`
        // extension on every request — required by the per-IP rate-limit key
        // extractor in `src/auth/rate_limit.rs`. Without it, every client
        // would share a single bucket when sitting behind the default
        // service factory.
        let service = router.into_make_service_with_connect_info::<SocketAddr>();
        if let Err(e) = axum::serve(listener, service).await {
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
                                        info!(ocr_chars = text.len(), "OCR complete");
                                        let parsed = parser::parse_receipt(&text);
                                        parser::print_parsed(&parsed);

                                        let chat_id = notification
                                            .body
                                            .sender_data
                                            .as_ref()
                                            .and_then(|s| s.chat_id.as_deref());
                                        let sender_jid = notification
                                            .body
                                            .sender_data
                                            .as_ref()
                                            .and_then(|s| s.sender.as_deref());
                                        let message_id = notification.body.id_message.as_deref();

                                        match (chat_id, sender_jid, message_id) {
                                            (Some(cid), Some(sender), Some(mid)) => {
                                                let input = ingestion::IngestionInput {
                                                    chat_id: cid,
                                                    sender_phone: sender,
                                                    message_id: mid,
                                                    ocr_text: &text,
                                                    parsed: &parsed,
                                                    received_at: now_iso(),
                                                };
                                                match ingestion::ingest_receipt(&surreal_db, input).await {
                                                    Ok(outcome) => {
                                                        info!(?outcome, "Ingestion outcome");
                                                        if let Some(reply) =
                                                            replies::format_reply(&outcome, &parsed)
                                                        {
                                                            match whatsapp::send_quoted_message(
                                                                &client,
                                                                &instance_id,
                                                                &api_token,
                                                                cid,
                                                                mid,
                                                                &reply,
                                                            )
                                                            .await
                                                            {
                                                                Ok(_) => info!(chat_id = cid, "Reply sent"),
                                                                Err(e) => {
                                                                    error!(error = %e, "Failed to send reply");
                                                                    processing_ok = false;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!(error = ?e, "Ingestion failed");
                                                        processing_ok = false;
                                                    }
                                                }
                                            }
                                            _ => warn!(
                                                has_chat_id = chat_id.is_some(),
                                                has_sender = sender_jid.is_some(),
                                                has_message_id = message_id.is_some(),
                                                "Skipping ingestion — notification missing required ids"
                                            ),
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
