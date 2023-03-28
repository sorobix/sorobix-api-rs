use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CompileContractRequest {
    pub lib_file: String,
}

#[derive(Serialize)]
pub struct CompileContractResponse {
    pub compiler_output: String,
}
