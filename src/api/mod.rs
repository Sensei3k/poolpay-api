pub mod handlers;
pub mod models;

use axum::{
    http::{header, Method},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::db::DbConn;
use handlers::{create_payment, delete_payment, get_cycles, get_members, get_payments, reset_db};

/// Build the Axum router with all API routes and CORS middleware.
///
/// CORS policy is driven by the `APP_ENV` environment variable:
///   - `production` → restricted to `DASHBOARD_ORIGIN` (required env var)
///   - anything else → permissive (dev default)
///
/// The `/api/test/reset` route is only registered when `APP_ENV` is not
/// `production`, preventing it from ever being reachable in live deployments.
pub fn router(db: DbConn) -> Router {
    let cors = build_cors();

    let mut router = Router::new()
        .route("/api/members", get(get_members))
        .route("/api/cycles", get(get_cycles))
        .route("/api/payments", get(get_payments))
        .route("/api/payments", post(create_payment))
        .route("/api/payments/{member_id}/{cycle_id}", delete(delete_payment));

    if std::env::var("APP_ENV").as_deref() != Ok("production") {
        router = router.route("/api/test/reset", post(reset_db));
    }

    router.layer(cors).with_state(db)
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
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE])
    } else {
        CorsLayer::permissive()
    }
}
