use std::borrow::Cow;
use std::env;
use std::io;
use std::path::PathBuf;
use std::process::Command;
use std::process::Output;

use crate::models::compile_contract::CompileContract;
use crate::models::deploy_contract::DeployContract;
use crate::models::invoke_contract::InvokeContract;

pub struct ContractService {}

impl ContractService {
    pub fn compile_contract(&self, lib_file: &str) -> Result<CompileContract, reqwest::Error> {
        let data: &str = &lib_file;

        let path: PathBuf = get_to_root_dir("utils/compile_to_wasm.sh").expect("");

        let output: Output = Command::new("sh")
            .arg(path)
            .arg(data)
            .output()
            .expect("failed to execute process");

        Ok(CompileContract::new(
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }

    pub async fn deploy_contract(
        &self,
        lib_file: &str,
        secret_key: &str,
    ) -> Result<DeployContract, reqwest::Error> {
        let data: &str = &lib_file;
        let secret_key: &str = &secret_key;

        let path: PathBuf = get_to_root_dir("utils/deploy_contract.sh").expect("");

        let output: Output = Command::new("sh")
            .arg(path)
            .arg(data)
            .arg(secret_key)
            .output()
            .expect("failed to execute process");

        let compilation_output: Cow<'_, str> = String::from_utf8_lossy(&output.stderr);

        let mut deployed = true;

        let contract_hash: Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
        let mut error_string = "";
        if contract_hash.len() == 0 {
            deployed = false;
            error_string = fetch_error_string_during_deployment(&compilation_output);
        }
        Ok(DeployContract::new(
            output.status.code(),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
            contract_hash.to_string(),
            deployed,
            error_string.to_string(),
        ))
    }

    pub async fn invoke_contract(
        &self,
        contract_id: &str,
        contract_function: &str,
        secret_key: &str,
        contract_args: &Vec<String>,
    ) -> Result<InvokeContract, reqwest::Error> {
        let mut soroban_cmd = Command::new("soroban");

        soroban_cmd
            .arg("contract")
            .arg("invoke")
            .arg("--id")
            .arg(contract_id)
            .arg("--source")
            .arg(secret_key)
            .arg("--rpc-url")
            .arg("https://rpc-futurenet.stellar.org:443")
            .arg("--network-passphrase")
            .arg("Test SDF Future Network ; October 2022")
            .arg("--")
            .arg(contract_function);

        for (index, arg) in contract_args.iter().enumerate() {
            if index % 2 == 0 {
                soroban_cmd.arg(format!("--{}", arg));
            } else {
                soroban_cmd.arg(arg);
            }
        }

        let output = soroban_cmd.output().expect("failed to execute process");

        let invokation_stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let mut invokation_stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if invokation_stderr == "SUCCESS\n" {
            invokation_stderr = "".to_string();
        }

        Ok(InvokeContract::new(invokation_stdout, invokation_stderr))
    }
}

pub fn get_to_root_dir(path_from_root_dir: &str) -> io::Result<PathBuf> {
    let mut dir: PathBuf = env::current_exe()?;
    loop {
        if let Some(parent) = dir.parent() {
            if let Some(name) = parent.file_name() {
                if name == "sorobix-api-rs" {
                    dir.pop();
                    break;
                }
            }
            dir.pop();
        } else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Could not find sorobix-api-rs directory",
            ));
        }
    }
    dir.push(path_from_root_dir);
    Ok(dir)
}

pub fn fetch_error_string_during_deployment(input_string: &str) -> &str {
    match input_string.find("\nerror: ") {
        Some(index) => &input_string[index + "\nerror: ".len()..],
        None => "",
    }
}
