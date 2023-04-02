use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct CompileContractRequest {
    pub lib_file: String,
}

#[derive(Serialize)]
pub struct CompileContractResponse {
    pub compiler_output: String,
}

pub struct CompileContract {
    pub compiler_stdcode: Option<i32>,
    pub compiler_stdout: String,
    pub compiler_stderr: String,
}

impl CompileContract {
    pub fn new(
        compiler_stdcode: Option<i32>,
        compiler_stdout: String,
        compiler_stderr: String,
    ) -> CompileContract {
        CompileContract {
            compiler_stdcode,
            compiler_stdout,
            compiler_stderr,
        }
    }
}
