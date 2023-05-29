use std::sync::{mpsc, Arc, Mutex};

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

#[derive(Debug, Deserialize, Serialize)]
pub struct Input {
    //todo: decorators
    pub cargoToml: String,
    pub mainRs: String,
}

#[derive(Debug, Deserialize)]
pub struct CompilationResult {
    pub success: bool,
    pub data: String,
}

pub struct ChannelData {
    pub sender: mpsc::Sender<CompilationResult>,
    pub receiver: mpsc::Receiver<CompilationResult>,
}
