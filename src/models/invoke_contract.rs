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
