use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use chrono::Utc;
use futures_util::stream::SplitSink;

use std::{fs, path::PathBuf};
use std::{net::SocketAddr, sync::mpsc};
use std::{
    ops::ControlFlow,
    sync::{Arc, Mutex},
};

use futures::{sink::SinkExt, stream::StreamExt};

use std::thread;

use rdkafka::{
    consumer::{BaseConsumer, Consumer},
    producer::{BaseRecord, ProducerContext, ThreadedProducer},
    ClientConfig, ClientContext, Message as KafkaMessage,
};

use axum::extract::connect_info::ConnectInfo;

use crate::models::compile_contract::{ChannelData, CompilationResult, Input};

struct ProduceCallbackLogger;

impl ClientContext for ProduceCallbackLogger {}

impl ProducerContext for ProduceCallbackLogger {
    type DeliveryOpaque = ();

    fn delivery(
        &self,
        delivery_result: &rdkafka::producer::DeliveryResult<'_>,
        _delivery_opaque: Self::DeliveryOpaque,
    ) {
        let dr = delivery_result.as_ref();

        match dr {
            Ok(msg) => {
                let key: &str = msg.key_view().unwrap().unwrap();
                println!(
                    "produced message with key {} in offset {} of partition {}",
                    key,
                    msg.offset(),
                    msg.partition()
                )
            }
            Err(producer_err) => {
                let key: &str = producer_err.1.key_view().unwrap().unwrap();

                println!(
                    "failed to produce message with key {} - {}",
                    key, producer_err.0,
                )
            }
        }
    }
}

/// Actual websocket statemachine (one will be spawned per connection)
pub async fn handle_socket(mut socket: WebSocket, who: SocketAddr) {
    let channel_data = create_channel();

    if socket.send(Message::Ping("hola".into())).await.is_ok() {
        println!("Recieved ws conn from: {}...", who);
    } else {
        println!("Client does not support websocket: {}!", who);
        return;
    }

    if let Some(msg) = socket.recv().await {
        if let Ok(msg) = msg {
            println!("inside sock recd");
            if process_message(msg, who).is_break() {
                println!("yahan aaya kya ffff in return");
                return;
            }
        } else {
            println!("Closed ws conn abruptly from: {who}");
            return;
        }
    }

    // This second task will receive messages from client and print them on server console
    let (mut sender, mut receiver) = socket.split();

    println!("lmaiii");

    tokio::spawn(async move {
        println!("atleast spwan hua");
        while let Some(Ok(msg)) = receiver.next().await {
            println!("atleast message mila");

            if message_is_for_compilation(&msg) {
                println!("og gg");
                let compilation_files = convert_compilation_msg_to_string(&msg);
                // let _resp = sender
                //     .send(Message::Text(format!(
                //         "Sending to Backend for Compiling..."
                //     )))
                //     .await;
                // println!("yes gg for compul");
                send_to_kafka(who.to_string().as_str(), &compilation_files);

                // let _resp = sender.send(Message::Text(format!("Compiling..."))).await;
                // receive_from_kafka(who, sender);

                //     sender.send(Message::Text((format!("aaajajaja")))).await;

                //     let received_message = channel_data.receiver.recv().unwrap();
                //     println!(
                //         "Received message: {} {}",
                //         received_message.success, received_message.data
                //     );

                //     let _resp = sender
                //         .send(Message::Text(format!(
                //             "Received message: {} {}",
                //             received_message.success, received_message.data
                //         )))
                //         .await;
            }
            // if process_message(msg, who).is_break() {
            //     return;
            // }
        }
        // cnt
    });
}

pub fn process_message(msg: Message, who: SocketAddr) -> ControlFlow<(), ()> {
    match msg {
        Message::Text(t) => {
            println!(">>> {} sent str: {:?}", who, t);
        }
        Message::Binary(d) => {
            println!(">>> {} sent {} bytes: {:?}", who, d.len(), d);
        }
        Message::Close(c) => {
            if let Some(cf) = c {
                println!(
                    ">>> {} sent close with code {} and reason `{}`",
                    who, cf.code, cf.reason
                );
            } else {
                println!(">>> {} somehow sent close message without CloseFrame", who);
            }
            return ControlFlow::Break(());
        }

        Message::Pong(v) => {
            println!(">>> {} responded to ping with pong of {:?}!", who, v);
        }
        Message::Ping(v) => {
            println!(">>> {} sent ping with {:?}", who, v);
        }
    }
    ControlFlow::Continue(())
}

pub fn message_is_for_compilation(msg: &Message) -> bool {
    if let Message::Text(t) = msg {
        if let Ok(()) = validate_input(&t) {
            return true;
        }
        return false;
    }
    return false;
}

pub fn convert_compilation_msg_to_string(msg: &Message) -> String {
    if let Message::Text(t) = msg {
        return t.into();
    }
    return String::new();
}

pub fn send_to_kafka(client_id: &str, lib_file: &str) {
    // optimise: shift creation when server starts
    let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
        .set("bootstrap.servers", "localhost:9092")
        .create_with_context(ProduceCallbackLogger {})
        .expect("invalid producer config");

    println!("sending message");

    producer
        .send(
            BaseRecord::to("build-wasm")
                .key(&format!("{}", client_id))
                .payload(&format!("{}", lib_file)),
        )
        .expect("failed to send message");
}

fn validate_input(input: &str) -> Result<(), &'static str> {
    let parsed_input: Result<Input, _> = serde_json::from_str(input);
    match parsed_input {
        Ok(input) => {
            if input.mainRs.is_empty() || input.cargoToml.is_empty() {
                Err("Empty values found for lib_file or cargo_toml")
            } else {
                Ok(())
            }
        }
        Err(_) => Err("Invalid input format"),
    }
}

pub fn receive_from_kafka(
    who: SocketAddr,
    sender: SplitSink<WebSocket, axum::extract::ws::Message>,
) {
    let consumer: BaseConsumer = ClientConfig::new()
        .set("bootstrap.servers", "localhost:9092")
        .set("group.id", "wasm-gen-v1")
        .create()
        .expect("invalid consumer config");

    consumer
        .subscribe(&["wasm-built"])
        .expect("topic subscribe failed");

    println!("conn successfully as kafka consumer");

    thread::spawn(move || {
        for msg_result in consumer.iter().flatten() {
            let (key, value) = (
                msg_result.key_view().unwrap().unwrap(),
                msg_result.payload().unwrap(),
            );
            if who.to_string() == key {
                if let Ok(mut result) = parse_kafka_message(value) {
                    if result.success {
                        let trimmed_string = result.data.trim_matches('"');

                        let written = write_wasm_file(key, trimmed_string);
                        result.data = written.into_os_string().into_string().unwrap();
                    }
                    // sender.send(item)
                    // let _resp = sender
                    //     .send(Message::Text(format!(
                    //         "Received message: {} {}",
                    //         result.success, result.data
                    //     )))
                        // .await;
                    ;
                    // let _ = sender.send(result);
                } else {
                    println!("Error parsing Kafka message");
                }
            }
        }
    });
}

fn parse_kafka_message(value: &[u8]) -> Result<CompilationResult, Box<dyn std::error::Error>> {
    let value_str = std::str::from_utf8(value)?;
    let result: CompilationResult =
        serde_json::from_str(value_str).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)?;
    Ok(result)
}

fn write_wasm_file(key: &str, data: &str) -> PathBuf {
    let decoded_data = base64::decode(data).expect("Error decoding data");

    let timestamp = Utc::now().format("%Y%m%d%H%M%S").to_string();
    let filename = format!("{}.wasm", timestamp);

    let output_dir = format!("./temp/{}", key);
    fs::create_dir_all(&output_dir).expect("Error creating output directory");

    let output_path = PathBuf::from(&output_dir).join(filename);
    fs::write(&output_path, &decoded_data).expect("Error writing to file");

    output_path
}

pub fn create_channel() -> ChannelData {
    println!("channel chalaaa");
    let (sender, receiver) = mpsc::channel();

    ChannelData { sender, receiver }
}
