extern crate ed25519_dalek;
extern crate rand;

mod handlers;
mod models;
mod services;

use axum::{
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

use crate::{
    handlers::account_handler::generate_new_account, models::router_state::RouterState,
    services::application_service::ApplicationService,
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let application_service = ApplicationService::new();
    let application_state = RouterState {
        application_service,
    };
    let state = Arc::new(application_state);
    let cors = CorsLayer::new().allow_origin(Any);
    let app = Router::new()
        .route("/", get(root))
        .route("/account", post(generate_new_account))
        .with_state(state)
        .layer(cors);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": true,
        "name": "sorobix-api-rs",
        "author": "Hemanth Krishna <@DarthBenro008>"
    }))
}
