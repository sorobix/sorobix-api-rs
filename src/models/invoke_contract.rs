use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct InvokeContractRequest {
    pub contract_id: String,
    pub contract_function: String,
    pub secret_key: String,
    pub contract_arguments: Vec<String>,
}

#[derive(Serialize)]
pub struct InvokeContractResponse {
    pub result: String,
}

pub struct InvokeContract {
    pub result: String,
    pub error_message: String,
}

impl InvokeContract {
    pub fn new(result: String, error_message: String) -> InvokeContract {
        InvokeContract {
            result,
            error_message,
        }
    }
}
