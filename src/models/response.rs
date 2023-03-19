use serde::Serialize;

pub use super::generate_account;

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
