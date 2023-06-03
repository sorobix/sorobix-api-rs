use axum::extract::ws::{Message, WebSocket};
use axum::extract::{ConnectInfo, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::{extract::State, http::StatusCode, Json};
use ed25519_dalek::Keypair;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use stellar_strkey::ed25519::PrivateKey;
use uuid::Uuid;

use crate::models::compile_contract::{CompileContractRequest, CompileContractResponse};
use crate::models::deploy_contract::{DeployContractRequest, DeployContractResponse};
use crate::models::invoke_contract::{InvokeContractRequest, InvokeContractResponse};
use crate::models::response::{Response, ResponseEnum};
use crate::models::router_state::RouterState;
use crate::models::websocket_state::WebSocketState;
use crate::services::contract_compiler::{create_channel, handle_socket};

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<Arc<WebSocketState>>,
) -> impl IntoResponse {
    // let receiver = channel_provider.get_channel().receiver.lock().unwrap();
    let mut websocket_connections: HashMap<String, &mut WebSocket> = HashMap::new();

    println!("connected.");

    ws.on_upgrade(move |socket| handle_socket(socket, addr, state.clone()))
}

pub async fn compile_contract(
    State(state): State<Arc<RouterState>>,
    Json(payload): Json<CompileContractRequest>,
) -> (StatusCode, Json<Response>) {
    let data: &str = &payload.lib_file.as_str();

    let compiled_contract = state
        .application_service
        .get_contract_service()
        .compile_contract(data);

    match compiled_contract {
        Ok(data) => match data.compiler_stdcode {
            Some(0) => {
                let compilation_response = CompileContractResponse {
                    compiler_output: data.compiler_stderr,
                };
                let response = Response::success_response(
                    "compilation successful!".to_string(),
                    ResponseEnum::CompileContractResponse(compilation_response),
                );
                (StatusCode::OK, Json(response))
            }
            Some(_) => {
                let response = Response::fail_response(
                    "compilation failed: ".to_string() + &data.compiler_stderr,
                );
                (StatusCode::BAD_REQUEST, Json(response))
            }
            None => {
                let response = Response::fail_response(
                    "compilation failed: ".to_string() + &data.compiler_stderr,
                );
                (StatusCode::BAD_REQUEST, Json(response))
            }
        },
        Err(error) => {
            let response = Response::fail_response(error.to_string());
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

pub async fn deploy_contract(
    State(state): State<Arc<RouterState>>,
    Json(payload): Json<DeployContractRequest>,
) -> (StatusCode, Json<Response>) {
    let lib_file: &str = &payload.lib_file.as_str();
    let secret_key: &str = &payload.secret_key.as_str();

    // Creating the keypair from private keys
    let private_key = PrivateKey::from_string(secret_key);
    match private_key {
        Ok(pkey) => {
            let secret = ed25519_dalek::SecretKey::from_bytes(&pkey.0);
            match secret {
                Ok(secret_key) => {
                    let public = (&secret_key).into();
                    let kp = Keypair {
                        secret: secret_key,
                        public,
                    };
                    let p = std::path::PathBuf::from(lib_file);
                    let contract_deployer = state
                        .application_service
                        .get_contract_deployment_service()
                        .new_contract_deployer(p, kp);

                    match contract_deployer.run().await {
                        Ok(data) => {
                            let deploy_response = DeployContractResponse {
                                contract_hash: String::from(&data),
                                compiler_output: String::from(&data),
                            };
                            let response = Response::success_response(
                                "deployment successful!".to_string(),
                                ResponseEnum::DeployContractResponse(deploy_response),
                            );
                            (StatusCode::OK, Json(response))
                        }
                        Err(error) => {
                            let response = Response::fail_response(error.to_string());
                            (StatusCode::INTERNAL_SERVER_ERROR, Json(response))
                        }
                    }
                }
                Err(error) => {
                    let response = Response::fail_response(error.to_string());
                    (StatusCode::BAD_REQUEST, Json(response))
                }
            }
        }
        Err(error) => {
            let response = Response::fail_response(error.to_string());
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

pub async fn invoke_contract(
    State(state): State<Arc<RouterState>>,
    Json(payload): Json<InvokeContractRequest>,
) -> (StatusCode, Json<Response>) {
    let contract_id: &str = &payload.contract_id.as_str();
    let contract_function: &str = &payload.contract_function.as_str();
    let secret_key: &str = &payload.secret_key.as_str();
    let contract_args: &Vec<String> = &payload.contract_arguments;

    let invokation = state
        .application_service
        .get_contract_service()
        .invoke_contract(contract_id, contract_function, secret_key, contract_args)
        .await;

    match invokation {
        Ok(data) => {
            if data.error_message.len() == 0 {
                let invokation_response = InvokeContractResponse {
                    result: data.result,
                };
                let response = Response::success_response(
                    "contract invokation successful".to_string(),
                    ResponseEnum::InvokeContractResponse(invokation_response),
                );
                return (StatusCode::OK, Json(response));
            } else {
                let response = Response::fail_response(
                    "contract invokation failed".to_string() + &data.error_message,
                );
                return (StatusCode::BAD_REQUEST, Json(response));
            }
        }
        Err(error) => {
            let response = Response::fail_response(error.to_string());
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    }
}
