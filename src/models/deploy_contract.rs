use serde::{Deserialize, Serialize};
#[derive(Deserialize)]
pub struct DeployContractRequest {
    pub lib_file: String,
    pub secret_key: String,
}

#[derive(Serialize)]
pub struct DeployContractResponse {
    pub contract_hash: String,
}

#[derive(Deserialize, Debug)]
pub struct RedisResponse {
    #[serde(alias = "Success")]
    pub status: bool,
    #[serde(alias = "Message")]
    pub message: String,
    #[serde(alias = "Wasm")]
    pub wasm: String,
}
