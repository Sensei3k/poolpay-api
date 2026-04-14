pub mod auth;
pub mod handlers;
pub mod models;

use axum::{
    http::{header, Method},
    routing::{delete, get, patch, post},
    Router,
};
use tower_http::cors::CorsLayer;

use crate::db::DbConn;
use handlers::{
    create_cycle, create_group, create_member, create_payment, create_whatsapp_link, delete_cycle,
    delete_group, delete_member, delete_payment, delete_whatsapp_link, get_cycles, get_groups,
    get_members, get_payments, get_whatsapp_links, reset_db, update_cycle, update_group,
    update_member,
};

/// Build the Axum router with all API routes and CORS middleware.
pub fn router(db: DbConn) -> Router {
    let cors = build_cors();

    let mut router = Router::new()
        // Public read endpoints
        .route("/api/groups", get(get_groups))
        .route("/api/members", get(get_members))
        .route("/api/cycles", get(get_cycles))
        .route("/api/payments", get(get_payments))
        .route("/api/payments", post(create_payment))
        .route("/api/payments/{member_id}/{cycle_id}", delete(delete_payment))
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
        // Admin WhatsApp link endpoints
        .route("/api/admin/whatsapp-links", get(get_whatsapp_links))
        .route("/api/admin/whatsapp-links", post(create_whatsapp_link))
        .route("/api/admin/whatsapp-links/{id}", delete(delete_whatsapp_link));

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
            .allow_methods([Method::GET, Method::POST, Method::PATCH, Method::DELETE])
            .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
    } else {
        CorsLayer::permissive()
    }
}
