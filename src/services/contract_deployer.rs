use std::array::TryFromSliceError;
use std::num::ParseIntError;
use std::path::PathBuf;

use ed25519_dalek::Keypair;
use hex::FromHexError;
use rand::Rng;
use sha2::{Digest, Sha256};
use soroban_env_host::xdr::{
    AccountId, ContractId, CreateContractArgs, Error as XdrError, Hash, HashIdPreimage,
    HostFunction, InvokeHostFunctionOp, LedgerFootprint, LedgerKey::ContractCode,
    LedgerKey::ContractData, LedgerKeyContractCode, LedgerKeyContractData, Memo, MuxedAccount,
    Operation, OperationBody, Preconditions, PublicKey, ScVal, SequenceNumber, Transaction,
    TransactionEnvelope, TransactionExt, Uint256, VecM, WriteXdr,
};
use soroban_env_host::xdr::{
    HashIdPreimageSourceAccountContractId, InstallContractCodeArgs, ScContractExecutable,
};
use soroban_env_host::HostError;

use crate::utils::constants::{NETWORK_PHRASE, NETWORK_URL};
use crate::utils::helper::{contract_hash, id_from_str, sign_transaction};
use crate::{utils::client::Client, utils::wasm};

pub struct ContractDepoymentService {}

impl ContractDepoymentService {
    pub fn new_contract_deployer(&self, wasm_path: PathBuf, keypair: Keypair) -> ContractDeployer {
        ContractDeployer::new(Some(wasm_path), keypair)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Host(#[from] HostError),
    #[error(transparent)]
    Wasm(#[from] wasm::Error),
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
    pub wasm: Option<std::path::PathBuf>,
    wasm_hash: Option<String>,
    salt: Option<String>,
    pub fee: crate::models::fee::Args,
    pub keypair: Keypair,
}

impl ContractDeployer {
    pub fn new(wasm: Option<std::path::PathBuf>, keypair: Keypair) -> ContractDeployer {
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
            let hash = self.run_and_get_hash(wasm).await?;
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
        client.send_transaction(&tx).await?;

        let gg = hex::encode(contract_id.0);
        Ok(gg)
    }

    pub async fn run_and_get_hash(&self, path: &PathBuf) -> Result<Hash, Error> {
        let gg = wasm::Args { wasm: path.clone() };
        let contract = gg.read()?;
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

        let (tx, hash) = build_install_contract_code_tx(
            contract,
            sequence + 1,
            self.fee.fee,
            &NETWORK_PHRASE,
            &key,
        )?;
        client.send_transaction(&tx).await?;

        Ok(hash)
    }
}

pub(crate) fn build_install_contract_code_tx(
    contract: Vec<u8>,
    sequence: i64,
    fee: u32,
    network_passphrase: &str,
    key: &ed25519_dalek::Keypair,
) -> Result<(TransactionEnvelope, Hash), XdrError> {
    let hash = contract_hash(&contract)?;

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            function: HostFunction::InstallContractCode(InstallContractCodeArgs {
                code: contract.try_into()?,
            }),
            footprint: LedgerFootprint {
                read_only: VecM::default(),
                read_write: vec![ContractCode(LedgerKeyContractCode { hash: hash.clone() })]
                    .try_into()?,
            },
            auth: VecM::default(),
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

    let envelope = sign_transaction(key, &tx, network_passphrase)?;

    Ok((envelope, hash))
}

fn build_create_contract_tx(
    hash: Hash,
    sequence: i64,
    fee: u32,
    network_passphrase: &str,
    salt: [u8; 32],
    key: &ed25519_dalek::Keypair,
) -> Result<(TransactionEnvelope, Hash), Error> {
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
            function: HostFunction::CreateContract(CreateContractArgs {
                contract_id: ContractId::SourceAccount(Uint256(salt)),
                source: ScContractExecutable::WasmRef(hash.clone()),
            }),
            footprint: LedgerFootprint {
                read_only: vec![ContractCode(LedgerKeyContractCode { hash })].try_into()?,
                read_write: vec![ContractData(LedgerKeyContractData {
                    contract_id: Hash(contract_id.into()),
                    key: ScVal::LedgerKeyContractExecutable,
                })]
                .try_into()?,
            },
            auth: VecM::default(),
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

    let envelope = sign_transaction(key, &tx, network_passphrase)?;

    Ok((envelope, Hash(contract_id.into())))
}