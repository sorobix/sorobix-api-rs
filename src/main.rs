extern crate ed25519_dalek;
extern crate rand;

mod models;

use axum::{
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use reqwest::Error;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use stellar_strkey::ed25519::{PrivateKey, PublicKey};

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    // build our application with a route
    let app = Router::new()
        // `GET /` goes to `root`
        .route("/", get(root))
        // `POST /users` goes to `create_user`
        .route("/users", post(create_user));

    // run our app with hyper
    // `axum::Server` is a re-export of `hyper::Server`
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

async fn add_funds(public: String) -> Result<serde_json::Value, reqwest::Error> {
    let body = reqwest::get(format!(
        "https://friendbot-futurenet.stellar.org?addr={}",
        public.to_string()
    ))
    .await?
    .json::<serde_json::Value>()
    .await?;
    Ok(body)
}

async fn create_user(
    // this argument tells axum to parse the request body
    // as JSON into a `CreateUser` type
    Json(payload): Json<CreateUser>,
) -> (StatusCode, Json<User>) {
    let mut cspng = OsRng {};
    let kp: Keypair = Keypair::generate(&mut cspng);
    let private = PrivateKey(kp.secret.to_bytes());
    let public = PublicKey(kp.public.to_bytes());
    let data = add_funds(public.to_string()).await;

    // insert your application logic here
    let user = User {
        id: 1337,
        res: data.expect("gg"),
        username: payload.username,
        private_key: private.to_string(),
        public_key: public.to_string(),
    };
    // this will be converted into a JSON response
    // with a status code of `201 Created`
    (StatusCode::CREATED, Json(user))
}

// the input to our `create_user` handler
#[derive(Deserialize)]
struct CreateUser {
    username: String,
}

// the output to our `create_user` handler
#[derive(Serialize)]
struct User {
    id: u64,
    username: String,
    res: serde_json::Value,
    private_key: String,
    public_key: String,
}
