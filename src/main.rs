extern crate ed25519_dalek;
extern crate rand;

mod handlers;
mod models;
mod services;

use axum::{
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::{
    handlers::account_handler::generate_new_account, models::router_state::RouterState,
    services::application_service::ApplicationService,
};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();
    let application_service = ApplicationService::new();
    let application_state = RouterState {
        application_service,
    };
    let state = Arc::new(application_state);
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        // `POST /users` goes to `create_user`
        .route("/account", post(generate_new_account))
        .with_state(state);

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn root() -> &'static str {
    "Hello, World!"
}
