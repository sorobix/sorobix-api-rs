use axum::{extract::State, http::StatusCode, Json};
use ed25519_dalek::Keypair;
use std::sync::Arc;
use stellar_strkey::ed25519::PrivateKey;

use crate::models::deploy_contract::{DeployContractRequest, DeployContractResponse};
use crate::models::invoke_contract::{InvokeContractRequest, InvokeContractResponse};
use crate::models::response::{Response, ResponseEnum};
use crate::models::router_state::RouterState;

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
