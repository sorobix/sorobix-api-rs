use std::array::TryFromSliceError;
use std::num::ParseIntError;

use ed25519_dalek::Keypair;
use hex::FromHexError;
use rand::Rng;
use sha2::{Digest, Sha256};
use soroban_env_host::xdr::{
    AccountId, ContractId, CreateContractArgs, Error as XdrError, Hash, HashIdPreimage,
    HostFunction, InvokeHostFunctionOp, Memo, MuxedAccount, Operation, OperationBody,
    Preconditions, PublicKey, SequenceNumber, Transaction, TransactionExt, Uint256, VecM, WriteXdr,
};
use soroban_env_host::xdr::{
    HashIdPreimageSourceAccountContractId, HostFunctionArgs, ScContractExecutable,
    UploadContractWasmArgs,
};
use soroban_env_host::HostError;

use crate::utils::client::Client;
use crate::utils::constants::{NETWORK_PHRASE, NETWORK_URL};
use crate::utils::helper::{contract_hash, id_from_str};

pub struct ContractDepoymentService {}

impl ContractDepoymentService {
    pub fn new_contract_deployer(&self, wasm: Vec<u8>, keypair: Keypair) -> ContractDeployer {
        ContractDeployer::new(Some(wasm), keypair)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error("error parsing int: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error("internal conversion error: {0}")]
    TryFromSliceError(#[from] TryFromSliceError),
    #[error("xdr processing error: {0}")]
    Xdr(#[from] XdrError),
    #[error("jsonrpc error: {0}")]
    JsonRpc(#[from] jsonrpsee_core::Error),
    #[error("cannot parse salt: {salt}")]
    CannotParseSalt { salt: String },
    #[error("cannot parse WASM hash {wasm_hash}: {error}")]
    CannotParseWasmHash {
        wasm_hash: String,
        error: FromHexError,
    },
    #[error("Must provide either --wasm or --wash-hash")]
    WasmNotProvided,
    #[error(transparent)]
    Rpc(#[from] crate::utils::client::Error),
}

pub struct ContractDeployer {
    pub wasm: Option<Vec<u8>>,
    wasm_hash: Option<String>,
    salt: Option<String>,
    pub fee: crate::models::fee::Args,
    pub keypair: Keypair,
}

impl ContractDeployer {
    pub fn new(wasm: Option<Vec<u8>>, keypair: Keypair) -> ContractDeployer {
        ContractDeployer {
            wasm,
            wasm_hash: None,
            salt: None,
            fee: crate::models::fee::Args { fee: 100 },
            keypair,
        }
    }
    pub async fn run(&self) -> Result<String, Error> {
        let res_str = self.run_and_get_contract_id().await?;
        Ok(res_str)
    }

    pub async fn run_and_get_contract_id(&self) -> Result<String, Error> {
        let wasm_hash = if let Some(wasm) = &self.wasm {
            let hash = self.run_and_get_hash(wasm.clone()).await?;
            hex::encode(hash)
        } else {
            self.wasm_hash
                .as_ref()
                .ok_or(Error::WasmNotProvided)?
                .to_string()
        };

        let hash = Hash(
            id_from_str(&wasm_hash).map_err(|e| Error::CannotParseWasmHash {
                wasm_hash: wasm_hash.clone(),
                error: e,
            })?,
        );
        self.run_against_rpc_server(hash).await
    }

    async fn run_against_rpc_server(&self, wasm_hash: Hash) -> Result<String, Error> {
        let salt: [u8; 32] = match &self.salt {
            // Hack: re-use contract_id_from_str to parse the 32-byte salt hex.
            Some(h) => id_from_str(h).map_err(|_| Error::CannotParseSalt { salt: h.clone() })?,
            None => rand::thread_rng().gen::<[u8; 32]>(),
        };

        //todo: insert netwokr url
        let client = Client::new(NETWORK_URL)?;
        // generate new public keypair
        let key = &self.keypair;

        // Get the account sequence number
        let public_strkey = stellar_strkey::ed25519::PublicKey(key.public.to_bytes()).to_string();

        let account_details = client.get_account(&public_strkey).await?;
        let sequence: i64 = account_details.seq_num.into();
        let (tx, contract_id) = build_create_contract_tx(
            wasm_hash,
            sequence + 1,
            self.fee.fee,
            &NETWORK_PHRASE,
            salt,
            &key,
        )?;
        client
            .prepare_and_send_transaction(&tx, &key, &NETWORK_PHRASE, None)
            .await?;

        let gg = hex::encode(contract_id.0);
        Ok(gg)
    }

    pub async fn run_and_get_hash(&self, contract: Vec<u8>) -> Result<Hash, Error> {
        self.run_against_rpc_server_install(contract).await
    }

    async fn run_against_rpc_server_install(&self, contract: Vec<u8>) -> Result<Hash, Error> {
        let client = Client::new(&NETWORK_URL)?;
        // create keypair
        let key = &self.keypair;

        // Get the account sequence number
        let public_strkey = stellar_strkey::ed25519::PublicKey(key.public.to_bytes()).to_string();
        let account_details = client.get_account(&public_strkey).await?;
        let sequence: i64 = account_details.seq_num.into();

        let (tx, hash) =
            build_install_contract_code_tx(contract.clone(), sequence + 1, self.fee.fee, &key)?;
        client
            .prepare_and_send_transaction(&tx, &key, &NETWORK_PHRASE, None)
            .await?;

        Ok(hash)
    }
}

pub(crate) fn build_install_contract_code_tx(
    contract: Vec<u8>,
    sequence: i64,
    fee: u32,
    key: &ed25519_dalek::Keypair,
) -> Result<(Transaction, Hash), XdrError> {
    let hash = contract_hash(&contract)?;

    let op = Operation {
        source_account: Some(MuxedAccount::Ed25519(Uint256(key.public.to_bytes()))),
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            functions: vec![HostFunction {
                args: HostFunctionArgs::UploadContractWasm(UploadContractWasmArgs {
                    code: contract.try_into()?,
                }),
                auth: VecM::default(),
            }]
            .try_into()?,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(key.public.to_bytes())),
        fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into()?,
        ext: TransactionExt::V0,
    };

    Ok((tx, hash))
}

fn build_create_contract_tx(
    hash: Hash,
    sequence: i64,
    fee: u32,
    network_passphrase: &str,
    salt: [u8; 32],
    key: &ed25519_dalek::Keypair,
) -> Result<(Transaction, Hash), Error> {
    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());
    let preimage =
        HashIdPreimage::ContractIdFromSourceAccount(HashIdPreimageSourceAccountContractId {
            network_id,
            source_account: AccountId(PublicKey::PublicKeyTypeEd25519(
                key.public.to_bytes().into(),
            )),
            salt: Uint256(salt),
        });
    let preimage_xdr = preimage.to_xdr()?;
    let contract_id = Sha256::digest(preimage_xdr);

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            functions: vec![HostFunction {
                args: HostFunctionArgs::CreateContract(CreateContractArgs {
                    contract_id: ContractId::SourceAccount(Uint256(salt)),
                    executable: ScContractExecutable::WasmRef(hash),
                }),
                auth: VecM::default(),
            }]
            .try_into()?,
        }),
    };
    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(key.public.to_bytes())),
        fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into()?,
        ext: TransactionExt::V0,
    };

    Ok((tx, Hash(contract_id.into())))
}
