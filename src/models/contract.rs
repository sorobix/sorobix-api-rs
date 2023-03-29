use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CompileContractRequest {
    pub lib_file: String,
}

#[derive(Deserialize)]
pub struct DeployContractRequest {
    pub lib_file: String,
    pub secret_key: String,
}

#[derive(Serialize)]
pub struct CompileContractResponse {
    pub compiler_output: String,
}
#[derive(Serialize)]
pub struct DeployContractResponse {
    pub contract_hash: String,
    pub compiler_output: String,
}
