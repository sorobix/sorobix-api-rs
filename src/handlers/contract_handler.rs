use axum::{extract::State, http::StatusCode, Json};
use ed25519_dalek::Keypair;
use redis::Commands;
use std::sync::Arc;
use stellar_strkey::ed25519::PrivateKey;

use crate::models::deploy_contract::{DeployContractRequest, DeployContractResponse};
use crate::models::invoke_contract::{InvokeContractRequest, InvokeContractResponse};
use crate::models::response::{Response, ResponseEnum};
use crate::models::router_state::RouterState;
use crate::utils::helper::redis_decoder;

pub async fn deploy_contract(
    State(state): State<Arc<RouterState>>,
    Json(payload): Json<DeployContractRequest>,
) -> (StatusCode, Json<Response>) {
    let lib_file: &str = &payload.lib_file.as_str();
    let secret_key: &str = &payload.secret_key.as_str();
    let redis_client = &state.application_service.redis;
    let mut redis_conn = if let Ok(r) = redis_client.get_connection() {
        r
    } else {
        let response = Response::fail_response("Unable to find file".to_string());
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
    };

    let redis_response: String = redis_conn.get(&lib_file).unwrap_or_default();
    let wasm_file = redis_decoder(&redis_response);

    if wasm_file.clone().len() == 0 {
        let response = Response::fail_response("Unable to parse compiled file".to_string());
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(response));
    }

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
                    let contract_deployer = state
                        .application_service
                        .get_contract_deployment_service()
                        .new_contract_deployer(wasm_file, kp);

                    match contract_deployer.run().await {
                        Ok(data) => {
                            let deploy_response = DeployContractResponse {
                                contract_hash: String::from(&data),
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
    let secret_key: &str = &payload.secret_key.as_str();

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
                    let mut contract_args = payload.contract_arguments;
                    contract_args.insert(0, payload.contract_function.clone());
                    let invoker_service = state
                        .application_service
                        .contract_invoker_service
                        .new_contract_invoker(payload.contract_id.clone(), kp, contract_args);
                    match invoker_service.run_against_rpc_server().await {
                        Ok(res) => {
                            let invokation_res = InvokeContractResponse { result: res };
                            let response = Response::success_response(
                                "invokation successful".to_string(),
                                ResponseEnum::InvokeContractResponse(invokation_res),
                            );
                            return (StatusCode::OK, Json(response));
                        }
                        Err(err) => {
                            let response = Response::fail_response(err.to_string());
                            return (StatusCode::BAD_REQUEST, Json(response));
                        }
                    }
                }
                Err(error) => {
                    let response = Response::fail_response(error.to_string());
                    return (StatusCode::BAD_REQUEST, Json(response));
                }
            }
        }
        Err(error) => {
            let response = Response::fail_response(error.to_string());
            return (StatusCode::BAD_REQUEST, Json(response));
        }
    }
}
