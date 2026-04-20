pub mod auth_endpoints;
pub mod handlers;
pub mod models;

use axum::{
    http::{header, Method},
    routing::{delete, get, patch, post},
    Extension, Router,
};
use tower_http::cors::CorsLayer;

use crate::auth::jwt::{JwtConfig, SharedVerifier, StaticKeyVerifier};
use crate::auth::rate_limit::{self, CredentialFailureLimiter, RateLimitConfig};
use crate::db::DbConn;
use std::sync::{Arc, OnceLock};
use handlers::{
    confirm_receipt, create_cycle, create_group, create_member, create_payment,
    create_whatsapp_link, delete_cycle, delete_group, delete_member, delete_payment,
    delete_whatsapp_link, get_cycles, get_groups, get_members, get_payments, get_receipts,
    get_whatsapp_links, reject_receipt, reset_db, update_cycle, update_group, update_member,
};

/// Build the Axum router with all API routes and CORS middleware.
///
/// The verifier is built once per process and cached — rebuilding on every
/// `router()` call would re-parse `JWT_KEYS` (or, in dev/test, generate a
/// fresh RSA-2048 keypair) which is both expensive and breaks any caller
/// that holds a previously-minted token across rebuilds.
pub fn router(db: DbConn) -> Router {
    router_with_config(db, RateLimitConfig::from_env(), shared_verifier())
}

/// Process-cached verifier used by `router()`. Exposed so the BE-4
/// `mint_admin_jwt()` test helper can sign tokens with the same key the
/// running app uses to verify them — without it, tests would build a
/// fresh ephemeral keypair and the token's signature would be rejected.
pub fn shared_verifier() -> SharedVerifier {
    static VERIFIER: OnceLock<SharedVerifier> = OnceLock::new();
    VERIFIER
        .get_or_init(|| {
            Arc::new(
                StaticKeyVerifier::from_env(JwtConfig::from_env()).unwrap_or_else(|err| {
                    panic!("Failed to initialise JWT verifier: {err}")
                }),
            )
        })
        .clone()
}

/// Build the router with explicit rate-limit config and token verifier —
/// used by tests that need tuned limits and a verifier they can mint against.
pub fn router_with_config(
    db: DbConn,
    rate_cfg: RateLimitConfig,
    verifier: SharedVerifier,
) -> Router {
    let cors = build_cors();

    // Composite (ip, email) failure limiter — charged only on 401 from
    // verify_credentials. Scoped to the auth sub-router via Extension so
    // other handlers cannot accidentally consume from it.
    let credential_failure_limiter = CredentialFailureLimiter::new(&rate_cfg);

    // Per-IP limiter mounted only on the auth endpoints — public reads and
    // admin routes stay untouched. Sub-router keeps the layer scoped.
    let auth_router = Router::new()
        .route(
            "/api/auth/verify-credentials",
            post(auth_endpoints::verify_credentials),
        )
        .route("/api/auth/ensure-user", post(auth_endpoints::ensure_user))
        .route("/api/auth/issue", post(auth_endpoints::issue_token_endpoint))
        .route("/api/auth/refresh", post(auth_endpoints::refresh_token_endpoint))
        .route("/api/auth/logout", post(auth_endpoints::logout_endpoint))
        .layer(rate_limit::build_per_ip_layer(&rate_cfg))
        .layer(Extension(credential_failure_limiter))
        .layer(Extension(rate_cfg.clone()));

    let mut router = Router::new()
        // Public read endpoints
        .route("/api/groups", get(get_groups))
        .route("/api/members", get(get_members))
        .route("/api/cycles", get(get_cycles))
        .route("/api/payments", get(get_payments))
        .route("/api/payments", post(create_payment))
        .route("/api/payments/{member_id}/{cycle_id}", delete(delete_payment))
        .route("/api/receipts", get(get_receipts))
        // Admin group endpoints
        .route("/api/admin/groups", post(create_group))
        .route("/api/admin/groups/{id}", patch(update_group))
        .route("/api/admin/groups/{id}", delete(delete_group))
        // Admin member endpoints
        .route("/api/admin/groups/{gid}/members", post(create_member))
        .route("/api/admin/members/{id}", patch(update_member))
        .route("/api/admin/members/{id}", delete(delete_member))
        // Admin cycle endpoints
        .route("/api/admin/groups/{gid}/cycles", post(create_cycle))
        .route("/api/admin/cycles/{id}", patch(update_cycle))
        .route("/api/admin/cycles/{id}", delete(delete_cycle))
        // Admin Receipt endpoints
        .route("/api/admin/receipts/{id}/confirm", post(confirm_receipt))
        .route("/api/admin/receipts/{id}/reject", post(reject_receipt))
        // Admin WhatsApp link endpoints
        .route("/api/admin/whatsapp-links", get(get_whatsapp_links))
        .route("/api/admin/whatsapp-links", post(create_whatsapp_link))
        .route("/api/admin/whatsapp-links/{id}", delete(delete_whatsapp_link))
        // Bearer-authenticated auth endpoints. Change-password is gated by
        // the `AuthenticatedUser` extractor — mounting it on the unrestricted
        // router avoids double-charging tower-governor's per-IP bucket for
        // callers who already hold a valid JWT.
        .route(
            "/api/auth/change-password",
            post(auth_endpoints::change_password),
        )
        // Auth endpoints (rate-limited; verify-credentials/ensure-user are
        // HMAC-gated, refresh/logout authenticate via the refresh token itself)
        // are merged below
        .merge(auth_router);

    // Fail-closed: the destructive test reset endpoint is only mounted when
    // APP_ENV is explicitly "development" or "test". If the env var is
    // misconfigured or missing on a staging/prod deploy, the endpoint stays
    // unreachable — previously an unset APP_ENV exposed it by default.
    if matches!(std::env::var("APP_ENV").as_deref(), Ok("development" | "test")) {
        router = router.route("/api/test/reset", post(reset_db));
    }

    // The verifier is injected as a request Extension so every handler
    // (including the auth extractors landing in BE-5) can reach it without
    // forcing a state-type migration on the existing DbConn-state router.
    //
    // `RateLimitConfig` is also layered at the top level (without the
    // tower-governor layer) so the `ClientIp` extractor used by bearer-gated
    // handlers like `change_password` picks up the injected config instead of
    // falling back to `RateLimitConfig::from_env` — otherwise tests and any
    // non-env configuration would key IP resolution on the wrong flags.
    router
        .layer(cors)
        .layer(Extension(verifier))
        .layer(Extension(rate_cfg))
        .with_state(db)
}

fn build_cors() -> CorsLayer {
    if std::env::var("APP_ENV").as_deref() == Ok("production") {
        let origin = std::env::var("DASHBOARD_ORIGIN")
            .expect("DASHBOARD_ORIGIN must be set when APP_ENV=production");

        let parsed: axum::http::HeaderValue = origin
            .parse()
            .expect("DASHBOARD_ORIGIN is not a valid header value");

        CorsLayer::new()
            .allow_origin(parsed)
            .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    } else {
        CorsLayer::permissive()
    }
}
