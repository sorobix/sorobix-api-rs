use axum::extract::Json;
use reqwest::StatusCode;
use std::borrow::Cow;
use std::path::PathBuf;
use std::process::{Command, Output};

use crate::models::contract::{
    CompileContractResponse, DeployContractRequest, DeployContractResponse,
};
use crate::models::{
    contract::CompileContractRequest,
    response::{Response, ResponseEnum},
};

use crate::services::contract_service::{fetch_error_string_during_deployment, get_to_root_dir};

pub async fn compile_contract(
    Json(payload): Json<CompileContractRequest>,
) -> (StatusCode, Json<Response>) {
    let data: &str = &payload.lib_file.as_str();

    let path: PathBuf = get_to_root_dir("utils/compile_to_wasm.sh").expect("");

    let output: Output = Command::new("sh")
        .arg(path)
        .arg(data)
        .output()
        .expect("failed to execute process");

    let compilation_output: Cow<'_, str> = String::from_utf8_lossy(&output.stderr);

    match output.status.code() {
        Some(0) => {
            let compilation_response = CompileContractResponse {
                compiler_output: compilation_output.to_string(),
            };
            let response = Response::success_response(
                "compilation successful!".to_string(),
                ResponseEnum::CompileContractResponse(compilation_response),
            );
            (StatusCode::OK, Json(response))
        }
        Some(_) => {
            let compilation_response = CompileContractResponse {
                compiler_output: compilation_output.to_string(),
            };
            let response = Response::success_response(
                "compilation failed!".to_string(),
                ResponseEnum::CompileContractResponse(compilation_response),
            );
            (StatusCode::BAD_REQUEST, Json(response))
        }
        None => {
            let response = Response::fail_response(compilation_output.to_string());
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}

pub async fn deploy_contract(
    Json(payload): Json<DeployContractRequest>,
) -> (StatusCode, Json<Response>) {
    let data: &str = &payload.lib_file.as_str();
    let secret_key: &str = &payload.secret_key.as_str();

    let path: PathBuf = get_to_root_dir("utils/deploy_contract.sh").expect("");

    let output: Output = Command::new("sh")
        .arg(path)
        .arg(data)
        .arg(secret_key)
        .output()
        .expect("failed to execute process");

    let compilation_output: Cow<'_, str> = String::from_utf8_lossy(&output.stderr);

    let mut deployed = true;

    let contract_hash: Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
    if contract_hash.len() == 0 {
        deployed = false;
    }

    match deployed {
        true => {
            let compilation_response = DeployContractResponse {
                contract_hash: contract_hash.to_string(),
                compiler_output: compilation_output.to_string(),
            };
            let response = Response::success_response(
                "deployment successful!".to_string(),
                ResponseEnum::DeployContractResponse(compilation_response),
            );
            (StatusCode::OK, Json(response))
        }
        false => {
            let error_string = fetch_error_string_during_deployment(&compilation_output);

            let compilation_response = DeployContractResponse {
                contract_hash: "".to_string(),
                compiler_output: compilation_output.to_string(),
            };
            let response = Response::success_response(
                "deployment failed: ".to_string() + error_string,
                ResponseEnum::DeployContractResponse(compilation_response),
            );
            (StatusCode::BAD_REQUEST, Json(response))
        }
    }
}
