use std::{array::TryFromSliceError, num::ParseIntError};

use ed25519_dalek::Keypair;
use hex::FromHexError;
use rand::Rng;
use sha2::{Digest, Sha256};
use soroban_env_host::{
    xdr::{
        AccountId, ContractExecutable, ContractIdPreimage, ContractIdPreimageFromAddress,
        CreateContractArgs, Error as XdrError, Hash, HashIdPreimage, HashIdPreimageContractId,
        HostFunction, InvokeHostFunctionOp, Memo, MuxedAccount, Operation, OperationBody,
        Preconditions, PublicKey, ScAddress, SequenceNumber, Transaction, TransactionExt, Uint256,
        VecM, WriteXdr,
    },
    HostError,
};

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
        error: stellar_strkey::DecodeError,
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
            crate::utils::helper::contract_id_from_str(&wasm_hash).map_err(|e| {
                Error::CannotParseWasmHash {
                    wasm_hash: wasm_hash.clone(),
                    error: e,
                }
            })?,
        );
        self.run_against_rpc_server(hash).await
    }

    async fn run_against_rpc_server(&self, wasm_hash: Hash) -> Result<String, Error> {
        let salt: [u8; 32] = match &self.salt {
            Some(h) => soroban_spec_tools::utils::padded_hex_from_str(h, 32)
                .map_err(|_| Error::CannotParseSalt { salt: h.clone() })?
                .try_into()
                .map_err(|_| Error::CannotParseSalt { salt: h.clone() })?,
            None => rand::thread_rng().gen::<[u8; 32]>(),
        };

        let client = Client::new(NETWORK_URL)?;
        // client
        //     .verify_network_passphrase(Some(NETWORK_PHRASE))
        //     .await?;
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
            .prepare_and_send_transaction(&tx, &key, &[], &NETWORK_PHRASE, None, None)
            .await?;
        Ok(stellar_strkey::Contract(contract_id.0).to_string())
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
            .prepare_and_send_transaction(&tx, &key, &[], &NETWORK_PHRASE, None, None)
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
            host_function: HostFunction::UploadContractWasm(contract.try_into()?),
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
    let source_account = AccountId(PublicKey::PublicKeyTypeEd25519(
        key.public.to_bytes().into(),
    ));

    let contract_id_preimage = ContractIdPreimage::Address(ContractIdPreimageFromAddress {
        address: ScAddress::Account(source_account),
        salt: Uint256(salt),
    });
    let contract_id = get_contract_id(contract_id_preimage.clone(), network_passphrase)?;

    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            host_function: HostFunction::CreateContract(CreateContractArgs {
                contract_id_preimage,
                executable: ContractExecutable::Wasm(hash),
            }),
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

    Ok((tx, Hash(contract_id.into())))
}

fn get_contract_id(
    contract_id_preimage: ContractIdPreimage,
    network_passphrase: &str,
) -> Result<Hash, Error> {
    let network_id = Hash(
        Sha256::digest(network_passphrase.as_bytes())
            .try_into()
            .unwrap(),
    );
    let preimage = HashIdPreimage::ContractId(HashIdPreimageContractId {
        network_id,
        contract_id_preimage,
    });
    let preimage_xdr = preimage.to_xdr()?;
    Ok(Hash(Sha256::digest(preimage_xdr).into()))
}
