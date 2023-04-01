use serde::Serialize;

pub use super::generate_account;
use super::invoke_contract::InvokeContractResponse;
use super::{compile_contract::CompileContractResponse, deploy_contract::DeployContractResponse};
#[derive(Serialize)]
pub struct Response {
    status: bool,
    message: String,
    data: ResponseEnum,
}

#[derive(Serialize)]
pub enum ResponseEnum {
    GenerateAccountResponse(generate_account::GenerateAccountResponse),
    String(String),
    CompileContractResponse(CompileContractResponse),
    DeployContractResponse(DeployContractResponse),
    InvokeContractResponse(InvokeContractResponse),
}

impl Response {
    pub fn success_response(message: String, data: ResponseEnum) -> Response {
        Response {
            status: true,
            message,
            data,
        }
    }
    pub fn fail_response(error: String) -> Response {
        Response {
            status: false,
            message: error,
            data: ResponseEnum::String("failed request".to_string()),
        }
    }
}
