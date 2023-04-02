use axum::{extract::State, http::StatusCode, Json};
use std::sync::Arc;

use crate::models::compile_contract::{CompileContractRequest, CompileContractResponse};
use crate::models::deploy_contract::{DeployContractRequest, DeployContractResponse};
use crate::models::invoke_contract::{InvokeContractRequest, InvokeContractResponse};
use crate::models::response::{Response, ResponseEnum};
use crate::models::router_state::RouterState;

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
                let compilation_response = CompileContractResponse {
                    compiler_output: data.compiler_stderr,
                };
                let response = Response::success_response(
                    "compilation failed!".to_string(),
                    ResponseEnum::CompileContractResponse(compilation_response),
                );
                (StatusCode::BAD_REQUEST, Json(response))
            }
            None => {
                let response = Response::fail_response(data.compiler_stderr);
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

    let deployment = state
        .application_service
        .get_contract_service()
        .deploy_contract(lib_file, secret_key)
        .await;

    match deployment {
        Ok(data) => match data.deployment_status {
            true => {
                let compilation_response = DeployContractResponse {
                    contract_hash: data.contract_hash,
                    compiler_output: data.compiler_stderr.to_string(),
                };
                let response = Response::success_response(
                    "deployment successful!".to_string(),
                    ResponseEnum::DeployContractResponse(compilation_response),
                );
                return (StatusCode::OK, Json(response));
            }
            false => {
                let compilation_response = DeployContractResponse {
                    contract_hash: "".to_string(),
                    compiler_output: data.compiler_stderr,
                };
                let response = Response::success_response(
                    "deployment failed: ".to_string() + &data.error_message,
                    ResponseEnum::DeployContractResponse(compilation_response),
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
                let invokation_response = InvokeContractResponse {
                    result: data.error_message,
                };
                let response = Response::success_response(
                    "contract invokation failed".to_string(),
                    ResponseEnum::InvokeContractResponse(invokation_response),
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
