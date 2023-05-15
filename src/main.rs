extern crate ed25519_dalek;
extern crate rand;

mod handlers;
mod models;
mod services;
mod utils;

use axum::{
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::{
    handlers::account_handler::generate_new_account,
    handlers::contract_handler::{compile_contract, deploy_contract, invoke_contract},
    models::router_state::RouterState,
    services::application_service::ApplicationService,
};

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "sorobix-api-rs=debug,tower_http=debug,server=debug",
        )
    }
    println!("Sorobix API RS Booted");
    tracing_subscriber::fmt::init();
    let application_service = ApplicationService::new();
    let application_state = RouterState {
        application_service,
    };
    let state = Arc::new(application_state);
    let app = Router::new()
        .route("/", get(root))
        .route("/account", post(generate_new_account))
        .route("/compile", post(compile_contract))
        .route("/deploy", post(deploy_contract))
        .route("/invoke", post(invoke_contract))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(Router::new().nest("/api", app).into_make_service())
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
