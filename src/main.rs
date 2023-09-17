extern crate ed25519_dalek;
extern crate rand;

mod handlers;
mod log;
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
    handlers::contract_handler::{deploy_contract, invoke_contract},
    models::router_state::RouterState,
    services::application_service::ApplicationService,
};

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "sorobix_api_rs=debug,tower_http=debug,server=debug",
        )
    }
    let redis = std::env::var("REDIS").unwrap_or("localhost".to_string());
    println!("Sorobix API RS Booted");
    tracing_subscriber::fmt::init();
    let client = if let Ok(cl) = redis::Client::open(format!("redis://{}", redis)) {
        cl
    } else {
        panic!("Unable to create redis client");
    };
    if let Err(err) = &client.get_connection() {
        tracing::error!("Unable to connect to redis: {:#?}", err);
    }
    let application_service = ApplicationService::new(client);
    let application_state = RouterState {
        application_service,
    };
    let state = Arc::new(application_state);
    let app = Router::new()
        .route("/", get(root))
        .route("/account", post(generate_new_account))
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
