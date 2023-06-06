use std::process::Command;

use crate::models::invoke_contract::InvokeContract;

pub struct ContractService {}

impl ContractService {
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
