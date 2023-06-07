use std::collections::HashMap;
use std::{convert::TryInto, num::ParseIntError};

use std::{fmt::Debug, io};

use ed25519_dalek::Keypair;
use heck::ToKebabCase;
use hex::FromHexError;
use soroban_env_host::{
    budget::Budget,
    events::HostEvent,
    xdr::{
        self, ContractAuth, ContractCodeEntry, ContractDataEntry, Error as XdrError, HostFunction,
        HostFunctionArgs, InvokeHostFunctionOp, InvokeHostFunctionResult, LedgerEntryData,
        LedgerFootprint, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Memo,
        MuxedAccount, Operation, OperationBody, OperationResult, OperationResultTr, Preconditions,
        ReadXdr, ScBytes, ScContractExecutable, ScSpecEntry, ScSpecFunctionV0, ScSpecTypeDef,
        ScVal, ScVec, SequenceNumber, Transaction, TransactionExt, TransactionResultResult,
        Uint256, VecM,
    },
    HostError,
};
use soroban_sdk::token;
use soroban_spec::read::FromWasmError;

use crate::models;
use crate::utils::client::Client;
use crate::utils::constants::{NETWORK_PHRASE, NETWORK_URL};
use crate::utils::strval::{self, Spec};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("parsing argument {arg}: {error}")]
    CannotParseArg { arg: String, error: strval::Error },
    #[error("cannot add contract to ledger entries: {0}")]
    CannotAddContractToLedgerEntries(XdrError),
    #[error(transparent)]
    // TODO: the Display impl of host errors is pretty user-unfriendly
    //       (it just calls Debug). I think we can do better than that
    Host(#[from] HostError),
    #[error("reading file {filepath}: {error}")]
    CannotReadContractFile {
        filepath: std::path::PathBuf,
        error: io::Error,
    },
    #[error("cannot parse contract ID {contract_id}: {error}")]
    CannotParseContractId {
        contract_id: String,
        error: FromHexError,
    },
    #[error("function {0} was not found in the contract")]
    FunctionNotFoundInContractSpec(String),
    #[error("parsing contract spec: {0}")]
    CannotParseContractSpec(FromWasmError),
    // },
    #[error("function name {0} is too long")]
    FunctionNameTooLong(String),
    #[error("argument count ({current}) surpasses maximum allowed count ({maximum})")]
    MaxNumberOfArgumentsReached { current: usize, maximum: usize },
    #[error("cannot print result {result:?}: {error}")]
    CannotPrintResult { result: ScVal, error: strval::Error },
    #[error("xdr processing error: {0}")]
    Xdr(#[from] XdrError),
    #[error("error parsing int: {0}")]
    ParseIntError(#[from] ParseIntError),
    #[error(transparent)]
    Rpc(#[from] crate::utils::client::Error),
    #[error(transparent)]
    StrVal(#[from] crate::utils::strval::Error),
    #[error("unexpected contract code data type: {0:?}")]
    UnexpectedContractCodeDataType(LedgerEntryData),
    #[error("missing operation result")]
    MissingOperationResult,
    #[error("missing result")]
    MissingResult,
    #[error("unexpected ({length}) simulate transaction result length")]
    UnexpectedSimulateTransactionResultSize { length: usize },
    #[error("Missing argument {0}")]
    MissingArgument(String),
    #[error("Contract Error\n{0}: {1}")]
    ContractInvoke(String, String),
}

pub struct ContractInvokerService {}

impl ContractInvokerService {
    pub fn new_contract_invoker(
        &self,
        contract: String,
        keypair: Keypair,
        slop: Vec<String>,
    ) -> ContractInvoker {
        ContractInvoker {
            contract,
            keypair,
            slop,
            fee: models::fee::Args::default(),
        }
    }
}

pub struct ContractInvoker {
    pub contract: String,
    pub keypair: Keypair,
    pub slop: Vec<String>,
    pub fee: crate::models::fee::Args,
}

impl ContractInvoker {
    pub fn spec_entries(&self) -> Result<Option<Vec<ScSpecEntry>>, Error> {
        self.read_wasm()?
            .map(|wasm| {
                soroban_spec::read::from_wasm(&wasm).map_err(Error::CannotParseContractSpec)
            })
            .transpose()
    }

    fn build_host_function_parameters(
        &self,
        contract_id: [u8; 32],
        spec_entries: &[ScSpecEntry],
    ) -> Result<(String, Spec, ScVec), Error> {
        let spec = Spec(Some(spec_entries.to_vec()));
        let mut cmd = clap::Command::new(self.contract.clone())
            .no_binary_name(true)
            .term_width(300)
            .max_term_width(300);

        for ScSpecFunctionV0 { name, .. } in spec.find_functions()? {
            cmd = cmd.subcommand(build_custom_cmd(&name.to_string_lossy(), &spec)?);
        }
        cmd.build();
        let mut matches_ = cmd.get_matches_from(&self.slop);
        let (function, matches_) = &matches_.remove_subcommand().unwrap_or_default();

        let func = spec.find_function(function)?;
        // create parsed_args in same order as the inputs to func
        let parsed_args = func
            .inputs
            .iter()
            .map(|i| {
                let name = i.name.to_string()?;
                if let Some(mut raw_val) = matches_.get_raw(&name) {
                    let s = raw_val
                        .next()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    // if matches!(i.type_, ScSpecTypeDef::Address) {
                    //     let cmd = crate::commands::config::identity::address::Cmd {
                    //         name: Some(s.clone()),
                    //         hd_path: Some(0),
                    //         locator: self.config.locator.clone(),
                    //     };
                    //     if let Ok(address) = cmd.public_key() {
                    //         s = address.to_string();
                    //     }
                    // }
                    spec.from_string(&s, &i.type_)
                        .map_err(|error| Error::CannotParseArg { arg: name, error })
                } else if matches!(i.type_, ScSpecTypeDef::Option(_)) {
                    Ok(ScVal::Void)
                } else {
                    Err(Error::MissingArgument(name))
                }
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Add the contract ID and the function name to the arguments
        let mut complete_args = vec![
            ScVal::Bytes(ScBytes(contract_id.try_into()?)),
            ScVal::Symbol(
                function
                    .try_into()
                    .map_err(|_| Error::FunctionNameTooLong(function.clone()))?,
            ),
        ];
        complete_args.extend_from_slice(parsed_args.as_slice());
        let complete_args_len = complete_args.len();

        Ok((
            function.clone(),
            spec,
            complete_args
                .try_into()
                .map_err(|_| Error::MaxNumberOfArgumentsReached {
                    current: complete_args_len,
                    maximum: ScVec::default().max_len(),
                })?,
        ))
    }

    pub fn read_wasm(&self) -> Result<Option<Vec<u8>>, Error> {
        Ok(None)
    }

    fn contract_id(&self) -> Result<[u8; 32], Error> {
        crate::utils::helper::id_from_str(&self.contract).map_err(|e| {
            Error::CannotParseContractId {
                contract_id: self.contract.clone(),
                error: e,
            }
        })
    }

    pub async fn run_against_rpc_server(&self) -> Result<String, Error> {
        let network = NETWORK_URL;
        let contract_id = self.contract_id()?;
        let client = Client::new(network)?;
        let key = &self.keypair;

        // Get the account sequence number
        let public_strkey = stellar_strkey::ed25519::PublicKey(key.public.to_bytes()).to_string();
        let account_details = client.get_account(&public_strkey).await?;
        let sequence: i64 = account_details.seq_num.into();

        // Get the contract
        let spec_entries = if let Some(spec) = self.spec_entries()? {
            spec
        } else {
            // async closures are not yet stable
            get_remote_contract_spec_entries(&client, &contract_id).await?
        };

        // Get the ledger footprint
        let (function, spec, host_function_params) =
            self.build_host_function_parameters(contract_id, &spec_entries)?;
        let tx = build_invoke_contract_tx(
            host_function_params.clone(),
            sequence + 1,
            self.fee.fee,
            &key,
        )?;

        let (result, events) = client
            .prepare_and_send_transaction(&tx, &key, &NETWORK_PHRASE, Some(log_events))
            .await?;

        tracing::debug!(?result);
        if !events.is_empty() {
            tracing::debug!(?events);
        }
        let res = match result.result {
            TransactionResultResult::TxSuccess(ops) => {
                if ops.is_empty() {
                    return Err(Error::MissingOperationResult);
                }
                match &ops[0] {
                    OperationResult::OpInner(OperationResultTr::InvokeHostFunction(
                        InvokeHostFunctionResult::Success(r),
                    )) => r[0].clone(),
                    _ => return Err(Error::MissingOperationResult),
                }
            }
            _ => return Err(Error::MissingOperationResult),
        };

        output_to_string(&spec, &res, &function)
    }
}

pub fn output_to_string(spec: &Spec, res: &ScVal, function: &str) -> Result<String, Error> {
    let mut res_str = String::new();
    if let Some(output) = spec.find_function(function)?.outputs.get(0) {
        res_str = spec
            .xdr_to_json(res, output)
            .map_err(|e| Error::CannotPrintResult {
                result: res.clone(),
                error: e,
            })?
            .to_string();
    }
    Ok(res_str)
}

fn build_invoke_contract_tx(
    parameters: ScVec,
    sequence: i64,
    fee: u32,
    key: &ed25519_dalek::Keypair,
) -> Result<Transaction, Error> {
    let op = Operation {
        source_account: None,
        body: OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
            functions: vec![HostFunction {
                args: HostFunctionArgs::InvokeContract(parameters),
                auth: VecM::default(),
            }]
            .try_into()?,
        }),
    };
    Ok(Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(key.public.to_bytes())),
        fee,
        seq_num: SequenceNumber(sequence),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op].try_into()?,
        ext: TransactionExt::V0,
    })
}

async fn get_remote_contract_spec_entries(
    client: &Client,
    contract_id: &[u8; 32],
) -> Result<Vec<ScSpecEntry>, Error> {
    // Get the contract from the network
    let contract_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract_id: xdr::Hash(*contract_id),
        key: ScVal::LedgerKeyContractExecutable,
    });

    let contract_ref = client.get_ledger_entries(Vec::from([contract_key])).await?;
    if contract_ref.entries.is_empty() {
        return Err(Error::MissingResult);
    }
    let contract_ref_entry = &contract_ref.entries[0];
    Ok(
        match LedgerEntryData::from_xdr_base64(&contract_ref_entry.xdr)? {
            LedgerEntryData::ContractData(ContractDataEntry {
                val: ScVal::ContractExecutable(ScContractExecutable::WasmRef(hash)),
                ..
            }) => {
                let code_key = LedgerKey::ContractCode(LedgerKeyContractCode { hash });
                let contract_data = client.get_ledger_entries(Vec::from([code_key])).await?;
                if contract_data.entries.is_empty() {
                    return Err(Error::MissingResult);
                }
                let contract_data_entry = &contract_data.entries[0];
                match LedgerEntryData::from_xdr_base64(&contract_data_entry.xdr)? {
                    LedgerEntryData::ContractCode(ContractCodeEntry { code, .. }) => {
                        let code_vec: Vec<u8> = code.into();
                        soroban_spec::read::from_wasm(&code_vec)
                            .map_err(Error::CannotParseContractSpec)?
                    }
                    scval => return Err(Error::UnexpectedContractCodeDataType(scval)),
                }
            }
            LedgerEntryData::ContractData(ContractDataEntry {
                val: ScVal::ContractExecutable(ScContractExecutable::Token),
                ..
            }) => soroban_spec::read::parse_raw(&token::Spec::spec_xdr())
                .map_err(FromWasmError::Parse)
                .map_err(Error::CannotParseContractSpec)?,
            scval => return Err(Error::UnexpectedContractCodeDataType(scval)),
        },
    )
}

fn log_events(
    footprint: &LedgerFootprint,
    auth: &Vec<VecM<ContractAuth>>,
    events: &[HostEvent],
    budget: Option<&Budget>,
) {
}

fn build_custom_cmd(name: &str, spec: &Spec) -> Result<clap::Command, Error> {
    let func = spec
        .find_function(name)
        .map_err(|_| Error::FunctionNotFoundInContractSpec(name.to_string()))?;

    // Parse the function arguments
    let inputs_map = &func
        .inputs
        .iter()
        .map(|i| (i.name.to_string().unwrap_or_default(), i.type_.clone()))
        .collect::<HashMap<String, ScSpecTypeDef>>();
    let name: &'static str = Box::leak(name.to_string().into_boxed_str());
    let mut cmd = clap::Command::new(name)
        .no_binary_name(true)
        .term_width(300)
        .max_term_width(300);
    let kebab_name = name.to_kebab_case();
    if kebab_name != name {
        cmd = cmd.alias(kebab_name);
    }
    let func = spec.find_function(name)?;
    let doc: &'static str = Box::leak(func.doc.to_string_lossy().into_boxed_str());
    cmd = cmd.about(Some(doc));
    for (name, type_) in inputs_map.iter() {
        let mut arg = clap::Arg::new(name);
        arg = arg
            .long(name)
            .alias(name.to_kebab_case())
            .num_args(1)
            .value_parser(clap::builder::NonEmptyStringValueParser::new())
            .long_help(spec.doc(name, type_)?);

        if let Some(value_name) = spec.arg_value_name(type_, 0) {
            let value_name: &'static str = Box::leak(value_name.into_boxed_str());
            arg = arg.value_name(value_name);
        }

        // Set up special-case arg rules
        arg = match type_ {
            xdr::ScSpecTypeDef::Bool => arg.num_args(0).required(false),
            xdr::ScSpecTypeDef::Option(_val) => arg.required(false),
            xdr::ScSpecTypeDef::I256
            | xdr::ScSpecTypeDef::I128
            | xdr::ScSpecTypeDef::I64
            | xdr::ScSpecTypeDef::I32 => arg.allow_hyphen_values(true),
            _ => arg,
        };

        cmd = cmd.arg(arg);
    }
    Ok(cmd)
}
