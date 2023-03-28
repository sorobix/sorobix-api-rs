use axum::extract::Json;
use reqwest::StatusCode;
use std::borrow::Cow;
use std::path::PathBuf;
use std::process::{Command, Output};

use crate::models::contract::CompileContractResponse;
use crate::models::{
    contract::CompileContractRequest,
    response::{Response, ResponseEnum},
};

use crate::services::contract_service::get_to_root_dir;

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
