pub mod handlers;
pub mod models;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::db::DbConn;
use handlers::{create_payment, delete_payment, get_cycles, get_members, get_payments, reset_db};

/// Build the Axum router with all API routes and CORS middleware.
///
/// CORS is permissive in development. Tighten to `CorsLayer::new().allow_origin(
/// "http://localhost:3001".parse().unwrap())` before deploying to production.
pub fn router(db: DbConn) -> Router {
    Router::new()
        .route("/api/members", get(get_members))
        .route("/api/cycles", get(get_cycles))
        .route("/api/payments", get(get_payments))
        .route("/api/payments", post(create_payment))
        .route("/api/payments/{member_id}/{cycle_id}", delete(delete_payment))
        .route("/api/test/reset", post(reset_db))
        .layer(CorsLayer::permissive())
        .with_state(db)
}
