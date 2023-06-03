use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::IntoResponse,
};
use chrono::Utc;
use futures_util::stream::SplitSink;
use tokio::runtime::{self, Runtime};

use std::{fs, path::PathBuf};
use std::{net::SocketAddr, sync::mpsc};
use std::{
    ops::ControlFlow,
    sync::{Arc, Mutex},
};

use futures::executor::block_on;
use futures::{channel::oneshot, sink::SinkExt, stream::StreamExt};

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

    // let rt = Runtime::new().unwrap();
    // let rt = runtime::Builder::new_multi_thread()
    //     .enable_all()
    //     .build()
    //     .unwrap();

    thread::spawn(move || {
        println!("atleast spwan hua");
        while let Some(Ok(msg)) = block_on(receiver.next()) {
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
                println!("sent {:#?}", thread::current().id());
                send_to_kafka(who.to_string().as_str(), &compilation_files);

                // let _resp = sender.send(Message::Text(format!("Compiling..."))).await;
                let data = block_on(receive_from_kafka(who));
                // println!("Received data: {}", data);
                println!("recd: {:#?}", thread::current().id());

                let lol = block_on(sender.send(Message::Text((format!("{}", data)))));

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

// pub async fn receive_from_kafka(who: SocketAddr) -> String {
//     let (tx, rx) = oneshot::channel();

//     let consumer: BaseConsumer = ClientConfig::new()
//         .set("bootstrap.servers", "localhost:9092")
//         .set("group.id", "wasm-gen-v1")
//         .create()
//         .expect("invalid consumer config");

//     consumer
//         .subscribe(&["wasm-built"])
//         .expect("topic subscribe failed");

//     println!("conn successfully as kafka consumer");

//     thread::spawn(move || {
//         for msg_result in consumer.iter().flatten() {
//             let (key, value) = (
//                 msg_result.key_view().unwrap().unwrap(),
//                 msg_result.payload().unwrap(),
//             );
//             if who.to_string() == key {
//                 if let Ok(mut result) = parse_kafka_message(value) {
//                     if result.success {
//                         let trimmed_string = result.data.trim_matches('"');

//                         let written = write_wasm_file(key, trimmed_string);
//                         result.data = written.into_os_string().into_string().unwrap();
//                         return result.data
//                     }
//                     // sender.send(item)
//                     // let _resp = sender
//                     //     .send(Message::Text(format!(
//                     //         "Received message: {} {}",
//                     //         result.success, result.data
//                     //     )))
//                         // .await;
//                     ;
//                     // let _ = sender.send(result);
//                 } else {
//                     println!("Error parsing Kafka message");
//                 }
//             }
//         }
//         return "consume iter ke bahar".to_string();
//     });
//     return "thread ke bahar".to_string();
// }

pub async fn receive_from_kafka(who: SocketAddr) -> String {
    let (tx, rx) = oneshot::channel();

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
    for msg_result in consumer.iter().flatten() {
        let (key, value) = (
            msg_result.key_view().unwrap().unwrap(),
            msg_result.payload().unwrap(),
        );
        println!("found key, sending to channel {}", key);
        // println!("going to check who, sending to channel {}", who);
        if who.to_string() == key {
            println!("lmai")
        }
        if let Ok(mut result) = parse_kafka_message(value) {
            println!("yeh bbhi");
            // println!("found data, sending to channel {}", key);
            let _ = tx.send(result.data);
            break;

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
    rx.await.unwrap_or_else(|_| {
        println!("Channel closed unexpectedly");
        String::new()
    })
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
