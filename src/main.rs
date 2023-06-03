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
use crossbeam_channel::{unbounded, Sender};
use models::compile_contract::CompilationResult;

use rdkafka::{
    consumer::{BaseConsumer, CommitMode, Consumer},
    producer::{BaseRecord, ProducerContext, ThreadedProducer},
    ClientConfig, ClientContext, Message as KafkaMessage,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::{
    handlers::account_handler::generate_new_account,
    handlers::contract_handler::{compile_contract, deploy_contract, invoke_contract, ws_handler},
    models::{router_state::RouterState, websocket_state::WebSocketState},
    services::{
        application_service::ApplicationService, channel_service::ChannelService,
        contract_compiler::parse_kafka_message,
    },
};

pub struct InCh {
    pub id: String,
    pub result: CompilationResult,
}

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "debug,sorobix-api-rs=debug,tower_http=debug,server=debug",
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
    use std::thread::available_parallelism;
    let default_parallelism_approx = available_parallelism().unwrap().get();
    println!("defaul para: {}", default_parallelism_approx);

    // let channel_service = ChannelService::new();
    // let ws_state = Arc::new(websocket_state);
    let (s, r) = unbounded::<InCh>();
    tokio::spawn(async move {
        receive_from_kafka(s).await;
    });
    let websocket_state = WebSocketState { reciever_rec: r };
    let ws_state = Arc::new(websocket_state);

    let ws_app = Router::new()
        .route("/", get(ws_handler))
        .with_state(ws_state);

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

pub async fn receive_from_kafka(sender: Sender<InCh>) {
    let consumer: BaseConsumer = ClientConfig::new()
        .set("bootstrap.servers", "localhost:9092")
        .set("group.id", "wasm-gen-v1")
        .create()
        .expect("invalid consumer config");

    consumer
        .subscribe(&["wasm-built"])
        .expect("topic subscribe failed");

    println!("conn successfully as kafka consumer");

    // tokio::spawn(async move {
    for msg_result in consumer.iter() {
        let borrowed_msg = msg_result.unwrap();
        let key = borrowed_msg.key_view::<str>().unwrap();
        let value = borrowed_msg.payload().unwrap();
        // let (key, value) = (
        //     msg_result.unwrap().key_view::<str>().unwrap(),
        //     msg_result.unwrap().payload().unwrap(),
        // );
        println!("found key, sending to channel {:#?}", key);
        // println!("going to check who, sending to channel {}", who);
        if let Ok(mut result) = parse_kafka_message(value) {
            // println!("found data, sending to channel {}", key);
            match key {
                Ok(data) => {
                    let new_inch = InCh {
                        id: data.to_string(),
                        result,
                    };
                    let res = sender.send(new_inch);
                    match res {
                        Ok(_) => {}
                        Err(err) => {
                            println!("sending channel error {:#?}", err);
                        }
                    }
                }
                Err(err) => {
                    println!("gaand lag gayi bhai {:#?}", err);
                }
            }

            // if result.success {
            //     let trimmed_string = result.data.trim_matches('"');

            //     let written = write_wasm_file(key, trimmed_string);
            //     result.data = written.into_os_string().into_string().unwrap();

            //     // Send the result data through the channel
            //     // println!("found data, sending to channel {}", result.data);
            //     // let _ = tx.send(result.data);
            //     // return;
            // }

            // Handle other cases if needed
        } else {
            println!("yeh muts");
            println!("Error parsing Kafka message");
        }
    }

    // If no message matches the condition, send an empty string through the channel
    // let _ = tx.send(String::new());
    // });

    // Wait for the result data or keep waiting indefinitely
}
