use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct DeployContractRequest {
    pub lib_file: String,
    pub secret_key: String,
}

#[derive(Serialize)]
pub struct DeployContractResponse {
    pub contract_hash: String,
    pub compiler_output: String,
}

pub struct DeployContract {
    pub compiler_stdcode: Option<i32>,
    pub compiler_stdout: String,
    pub compiler_stderr: String,
    pub contract_hash: String,
    pub deployment_status: bool,
    pub error_message: String,
}

impl DeployContract {
    pub fn new(
        compiler_stdcode: Option<i32>,
        compiler_stdout: String,
        compiler_stderr: String,
        contract_hash: String,
        deployment_status: bool,
        error_message: String,
    ) -> DeployContract {
        DeployContract {
            compiler_stdcode,
            compiler_stdout,
            compiler_stderr,
            contract_hash,
            deployment_status,
            error_message,
        }
    }
}
