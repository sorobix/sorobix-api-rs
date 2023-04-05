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
    handlers::account_handler::generate_new_account,
    handlers::contract_handler::{compile_contract, deploy_contract, invoke_contract},
    models::router_state::RouterState,
    services::application_service::ApplicationService,
};

#[tokio::main]
async fn main() {
    println!("Sorobix API RS Booted");
    tracing_subscriber::fmt::init();
    let application_service = ApplicationService::new();
    let application_state = RouterState {
        application_service,
    };
    let state = Arc::new(application_state);
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);
    let app = Router::new()
        .layer(cors)
        .route("/", get(root))
        .route("/account", post(generate_new_account))
        .route("/compile", post(compile_contract))
        .route("/deploy", post(deploy_contract))
        .route("/invoke", post(invoke_contract))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
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
        "author": "Team Sorobix <sorobix@gmail.com>"
    }))
}
