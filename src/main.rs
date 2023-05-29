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
    handlers::contract_handler::{compile_contract, deploy_contract, invoke_contract, ws_handler},
    models::{router_state::RouterState, websocket_state::WebSocketState},
    services::{application_service::ApplicationService, channel_service::ChannelService},
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
    let rest_app = Router::new()
        .route("/", get(root))
        .route("/account", post(generate_new_account))
        .route("/compile", post(compile_contract))
        .route("/deploy", post(deploy_contract))
        .route("/invoke", post(invoke_contract))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let rest_addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    let ws_addr = SocketAddr::from(([0, 0, 0, 0], 3001));

    // let channel_service = ChannelService::new();
    // let websocket_state = WebSocketState { channel_service };
    // let ws_state = Arc::new(websocket_state);

    let ws_app = Router::new().route("/", get(ws_handler));
    // .with_state(ws_state);

    let rest_server = axum::Server::bind(&rest_addr)
        .serve(Router::new().nest("/api", rest_app).into_make_service());
    let ws_server = axum::Server::bind(&ws_addr)
        .serve(ws_app.into_make_service_with_connect_info::<SocketAddr>());

    tracing::debug!("rest server listening on {}", rest_addr);
    tracing::debug!("websocket server listening on {}", ws_addr);

    // init kafka producer and consumer conn

    tokio::select! {
        _ = rest_server => {
            println!("REST server stopped");
        }
        _ = ws_server => {
            println!("WebSocket server stopped");
        }
    };
}

async fn root() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": true,
        "name": "sorobix-api-rs",
        "author": "Team Sorobix <sorobix@gmail.com>"
    }))
}
