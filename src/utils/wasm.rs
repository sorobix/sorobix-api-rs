use std::{fs, io};

use soroban_env_host::xdr;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("reading file {filepath}: {error}")]
    CannotReadContractFile {
        filepath: std::path::PathBuf,
        error: io::Error,
    },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] xdr::Error),
}

pub struct Args {
    pub wasm: std::path::PathBuf,
}

impl Args {
    /// # Errors
    /// May fail to read wasm file
    pub fn read(&self) -> Result<Vec<u8>, Error> {
        fs::read(&self.wasm).map_err(|e| Error::CannotReadContractFile {
            filepath: self.wasm.clone(),
            error: e,
        })
    }
}
