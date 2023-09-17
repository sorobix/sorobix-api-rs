use http::{uri::Authority, Uri};
use jsonrpsee_core::{self, client::ClientT, rpc_params};
use jsonrpsee_http_client::{HeaderMap, HttpClient, HttpClientBuilder};
use serde_aux::prelude::{deserialize_default_from_null, deserialize_number_from_string};
use soroban_env_host::{
    budget::Budget,
    events::HostEvent,
    xdr::{
        self, AccountEntry, AccountId, ContractDataEntry, DepthLimitedRead, DiagnosticEvent,
        Error as XdrError, LedgerEntryData, LedgerFootprint, LedgerKey, LedgerKeyAccount,
        PublicKey, ReadXdr, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanResources,
        Transaction, TransactionEnvelope, TransactionMeta, TransactionMetaV3, TransactionResult,
        TransactionV1Envelope, Uint256, VecM, WriteXdr,
    },
};
use soroban_sdk::token;
use std::{
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::time::sleep;

use crate::utils::transaction::{
    assemble, sign_soroban_authorization_entry, sign_soroban_authorizations,
};

use super::contract_spec;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

pub type LogResources = fn(resources: &SorobanResources) -> ();

pub type LogEvents = fn(
    footprint: &LedgerFootprint,
    auth: &[VecM<SorobanAuthorizationEntry>],
    events: &[HostEvent],
    budget: Option<&Budget>,
) -> ();

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
pub struct RestorePreamble {
    #[serde(rename = "transactionData")]
    pub transaction_data: String,
    #[serde(
        rename = "minResourceFee",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub min_resource_fee: u64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GetLatestLedgerResponse {
    pub id: String,
    #[serde(
        rename = "protocolVersion",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub protocol_version: u32,
    pub sequence: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GetLedgerEntriesResponse {
    pub entries: Option<Vec<LedgerEntryResult>>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
pub struct Cost {
    #[serde(
        rename = "cpuInsns",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub cpu_insns: u64,
    #[serde(
        rename = "memBytes",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub mem_bytes: u64,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct SimulateHostFunctionResult {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub auth: Vec<String>,
    pub xdr: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug, Default)]
pub struct SimulateTransactionResponse {
    #[serde(
        rename = "minResourceFee",
        deserialize_with = "deserialize_number_from_string",
        default
    )]
    pub min_resource_fee: u64,
    #[serde(default)]
    pub cost: Cost,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub results: Vec<SimulateHostFunctionResult>,
    #[serde(rename = "transactionData", default)]
    pub transaction_data: String,
    #[serde(
        deserialize_with = "deserialize_default_from_null",
        skip_serializing_if = "Vec::is_empty",
        default
    )]
    pub events: Vec<String>,
    #[serde(
        rename = "restorePreamble",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub restore_preamble: Option<RestorePreamble>,
    #[serde(
        rename = "latestLedger",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger: u32,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0} not found: {1}")]
    NotFound(String, String),
    #[error("invalid address: {0}")]
    InvalidAddress(#[from] stellar_strkey::DecodeError),
    #[error("invalid response from server")]
    InvalidResponse,
    #[error("xdr processing error: {0}")]
    Xdr(#[from] XdrError),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrl(http::uri::InvalidUri),
    #[error("invalid rpc url: {0}")]
    InvalidRpcUrlFromUriParts(http::uri::InvalidUriParts),
    #[error("jsonrpc error: {0}")]
    JsonRpc(#[from] jsonrpsee_core::Error),
    #[error("json decoding error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("transaction submission failed: {0}")]
    TransactionSubmissionFailed(String),
    #[error("expected transaction status: {0}")]
    UnexpectedTransactionStatus(String),
    #[error("transaction submission timeout")]
    TransactionSubmissionTimeout,
    #[error("transaction simulation failed: {0}")]
    TransactionSimulationFailed(String),
    #[error("Missing result in successful response")]
    MissingResult,
    #[error("Failed to read Error response from server")]
    MissingError,
    #[error("Missing signing key for account {address}")]
    MissingSignerForAddress { address: String },
    #[error("unexpected ({length}) simulate transaction result length")]
    UnexpectedSimulateTransactionResultSize { length: usize },
    #[error("unexpected ({count}) number of operations")]
    UnexpectedOperationCount { count: usize },
    #[error(
        "unsupported operation type, must be only one InvokeHostFunctionOp in the transaction."
    )]
    UnsupportedOperationType,
    #[error("unexpected contract code data type: {0:?}")]
    UnexpectedContractCodeDataType(LedgerEntryData),
    #[error(transparent)]
    CouldNotParseContractSpec(#[from] contract_spec::Error),
    #[error("Fee was too large {0}")]
    LargeFee(u64),
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GetTransactionResponse {
    pub status: String,
    #[serde(
        rename = "envelopeXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub envelope_xdr: Option<String>,
    #[serde(rename = "resultXdr", skip_serializing_if = "Option::is_none", default)]
    pub result_xdr: Option<String>,
    #[serde(
        rename = "resultMetaXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub result_meta_xdr: Option<String>,
    // TODO: add ledger info and application order
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct SendTransactionResponse {
    pub hash: String,
    pub status: String,
    #[serde(
        rename = "errorResultXdr",
        skip_serializing_if = "Option::is_none",
        default
    )]
    pub error_result_xdr: Option<String>,
    #[serde(
        rename = "latestLedger",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger: u32,
    #[serde(
        rename = "latestLedgerCloseTime",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger_close_time: u32,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct LedgerEntryResult {
    pub key: String,
    pub xdr: String,
    #[serde(rename = "lastModifiedLedgerSeq")]
    pub last_modified_ledger: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GetLedgerEntryResponse {
    pub xdr: String,
}

pub struct Client {
    base_url: String,
}

fn extract_events(tx_meta: &TransactionMeta) -> Vec<DiagnosticEvent> {
    match tx_meta {
        TransactionMeta::V3(TransactionMetaV3 {
            soroban_meta: Some(meta),
            ..
        }) => {
            // NOTE: we assume there can only be one operation, since we only send one
            if meta.diagnostic_events.len() == 1 {
                meta.diagnostic_events.clone().into()
            } else if meta.events.len() == 1 {
                meta.events
                    .iter()
                    .map(|e| DiagnosticEvent {
                        in_successful_contract_call: true,
                        event: e.clone(),
                    })
                    .collect()
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

impl Client {
    pub fn new(base_url: &str) -> Result<Self, Error> {
        // Add the port to the base URL if there is no port explicitly included
        // in the URL and the scheme allows us to infer a default port.
        // Jsonrpsee requires a port to always be present even if one can be
        // inferred. This may change: https://github.com/paritytech/jsonrpsee/issues/1048.
        let uri = base_url.parse::<Uri>().map_err(Error::InvalidRpcUrl)?;
        let mut parts = uri.into_parts();
        if let (Some(scheme), Some(authority)) = (&parts.scheme, &parts.authority) {
            if authority.port().is_none() {
                let port = match scheme.as_str() {
                    "http" => Some(80),
                    "https" => Some(443),
                    _ => None,
                };
                if let Some(port) = port {
                    let host = authority.host();
                    parts.authority = Some(
                        Authority::from_str(&format!("{host}:{port}"))
                            .map_err(Error::InvalidRpcUrl)?,
                    );
                }
            }
        }
        let uri = Uri::from_parts(parts).map_err(Error::InvalidRpcUrlFromUriParts)?;
        tracing::trace!(?uri);
        Ok(Self {
            base_url: uri.to_string(),
        })
    }

    fn client(&self) -> Result<HttpClient, Error> {
        let url = self.base_url.clone();
        let mut headers = HeaderMap::new();
        headers.insert("X-Client-Name", "soroban-cli".parse().unwrap());
        let version = VERSION.unwrap_or("devel");
        headers.insert("X-Client-Version", version.parse().unwrap());
        Ok(HttpClientBuilder::default()
            .set_headers(headers)
            .build(url)?)
    }

    pub async fn get_transaction(&self, tx_id: &str) -> Result<GetTransactionResponse, Error> {
        Ok(self
            .client()?
            .request("getTransaction", rpc_params![tx_id])
            .await?)
    }

    pub async fn get_ledger_entry(&self, key: LedgerKey) -> Result<GetLedgerEntryResponse, Error> {
        let base64_key = key.to_xdr_base64()?;
        Ok(self
            .client()?
            .request("getLedgerEntry", rpc_params![base64_key])
            .await?)
    }

    pub async fn get_account(&self, address: &str) -> Result<AccountEntry, Error> {
        tracing::trace!("Getting address {}", address);
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(address)?.0,
            ))),
        });
        let keys = Vec::from([key]);
        let response = self.get_ledger_entries(&keys).await?;
        let entries = response.entries.unwrap_or_default();
        if entries.is_empty() {
            return Err(Error::NotFound(
                "Account".to_string(),
                format!(
                    r#"{address}
Might need to fund account like:
soroban config identity fund {address} --network <name>
soroban config identity fund {address} --helper-url <url>"#
                ),
            ));
        }
        let ledger_entry = &entries[0];
        let mut depth_limit_read = DepthLimitedRead::new(ledger_entry.xdr.as_bytes(), 100);
        if let LedgerEntryData::Account(entry) =
            LedgerEntryData::read_xdr_base64(&mut depth_limit_read)?
        {
            tracing::trace!(account=?entry);
            Ok(entry)
        } else {
            Err(Error::InvalidResponse)
        }
    }

    pub async fn simulate_transaction(
        &self,
        tx: &TransactionEnvelope,
    ) -> Result<SimulateTransactionResponse, Error> {
        tracing::trace!(?tx);
        let base64_tx = tx.to_xdr_base64()?;
        let response: SimulateTransactionResponse = self
            .client()?
            .request("simulateTransaction", rpc_params![base64_tx])
            .await?;
        tracing::trace!(?response);
        match response.error {
            None => Ok(response),
            Some(e) => Err(Error::TransactionSimulationFailed(e)),
        }
    }

    // Simulate a transaction, then assemble the result of the simulation into the envelope, so it
    // is ready for sending to the network.
    pub async fn prepare_transaction(
        &self,
        tx: &Transaction,
    ) -> Result<(Transaction, Vec<DiagnosticEvent>), Error> {
        tracing::trace!(?tx);
        let sim_response = self
            .simulate_transaction(&TransactionEnvelope::Tx(TransactionV1Envelope {
                tx: tx.clone(),
                signatures: VecM::default(),
            }))
            .await?;

        let events = sim_response
            .events
            .iter()
            .map(DiagnosticEvent::from_xdr_base64)
            .collect::<Result<Vec<_>, _>>()?;

        Ok((assemble(tx, &sim_response)?, events))
    }

    pub async fn get_latest_ledger(&self) -> Result<GetLatestLedgerResponse, Error> {
        tracing::trace!("Getting latest ledger");
        Ok(self
            .client()?
            .request("getLatestLedger", rpc_params![])
            .await?)
    }

    pub async fn prepare_and_send_transaction(
        &self,
        tx_without_preflight: &Transaction,
        source_key: &ed25519_dalek::Keypair,
        signers: &[ed25519_dalek::Keypair],
        network_passphrase: &str,
        log_events: Option<LogEvents>,
        log_resources: Option<LogResources>,
    ) -> Result<(TransactionResult, TransactionMeta, Vec<DiagnosticEvent>), Error> {
        let GetLatestLedgerResponse { sequence, .. } = self.get_latest_ledger().await?;
        let (unsigned_tx, events) = self.prepare_transaction(tx_without_preflight).await?;
        let (part_signed_tx, signed_auth_entries) = sign_soroban_authorizations(
            &unsigned_tx,
            source_key,
            signers,
            sequence + 60, // ~5 minutes of ledgers
            network_passphrase,
        )?;
        let (fee_ready_txn, events) = if signed_auth_entries.is_empty()
            || (signed_auth_entries.len() == 1
                && matches!(
                    signed_auth_entries[0].root_invocation.function,
                    SorobanAuthorizedFunction::CreateContractHostFn(_)
                )) {
            (part_signed_tx, events)
        } else {
            // re-simulate to calculate the new fees
            self.prepare_transaction(&part_signed_tx).await?
        };

        // Try logging stuff if requested
        if let Transaction {
            ext: xdr::TransactionExt::V1(xdr::SorobanTransactionData { resources, .. }),
            ..
        } = fee_ready_txn.clone()
        {
            if let Some(log) = log_events {
                if let xdr::Operation {
                    body:
                        xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
                            auth, ..
                        }),
                    ..
                } = &fee_ready_txn.operations[0]
                {
                    //log(&resources.footprint, &[auth.clone()], &events);
                }
            }
            if let Some(log) = log_resources {
                log(&resources);
            }
        }

        let tx =
            crate::utils::helper::sign_transaction(source_key, &fee_ready_txn, network_passphrase)?;
        self.send_transaction(&tx).await
    }

    pub async fn get_ledger_entries(
        &self,
        keys: &[LedgerKey],
    ) -> Result<GetLedgerEntriesResponse, Error> {
        let mut base64_keys: Vec<String> = vec![];
        for k in keys {
            let base64_result = k.to_xdr_base64();
            if base64_result.is_err() {
                return Err(Error::Xdr(XdrError::Invalid));
            }
            base64_keys.push(k.to_xdr_base64().unwrap());
        }
        Ok(self
            .client()?
            .request("getLedgerEntries", rpc_params![base64_keys])
            .await?)
    }

    pub async fn send_transaction(
        &self,
        tx: &TransactionEnvelope,
    ) -> Result<(TransactionResult, TransactionMeta, Vec<DiagnosticEvent>), Error> {
        let client = self.client()?;
        tracing::trace!(?tx);
        let SendTransactionResponse {
            hash,
            error_result_xdr,
            status,
            ..
        } = client
            .request("sendTransaction", rpc_params![tx.to_xdr_base64()?])
            .await
            .map_err(|err| Error::TransactionSubmissionFailed(format!("{err:#?}")))?;

        if status == "ERROR" {
            let error = error_result_xdr
                .ok_or(Error::MissingError)
                .and_then(|x| {
                    TransactionResult::read_xdr_base64(&mut DepthLimitedRead::new(
                        x.as_bytes(),
                        100,
                    ))
                    .map_err(|_| Error::InvalidResponse)
                })
                .map(|r| r.result);
            tracing::error!(?error);
            return Err(Error::TransactionSubmissionFailed(format!("{:#?}", error?)));
        }
        // even if status == "success" we need to query the transaction status in order to get the result

        // Poll the transaction status
        let start = Instant::now();
        loop {
            let response = self.get_transaction(&hash).await?;
            match response.status.as_str() {
                "SUCCESS" => {
                    // TODO: the caller should probably be printing this
                    tracing::trace!(?response);
                    let result = TransactionResult::from_xdr_base64(
                        response.result_xdr.clone().ok_or(Error::MissingResult)?,
                    )?;
                    let meta = TransactionMeta::from_xdr_base64(
                        response
                            .result_meta_xdr
                            .clone()
                            .ok_or(Error::MissingResult)?,
                    )?;
                    let events = extract_events(&meta);
                    return Ok((result, meta, events));
                }
                "FAILED" => {
                    tracing::error!(?response);
                    // TODO: provide a more elaborate error
                    return Err(Error::TransactionSubmissionFailed(format!("{response:#?}")));
                }
                "NOT_FOUND" => (),
                _ => {
                    return Err(Error::UnexpectedTransactionStatus(response.status));
                }
            };
            let duration = start.elapsed();
            // TODO: parameterize the timeout instead of using a magic constant
            if duration.as_secs() > 10 {
                return Err(Error::TransactionSubmissionTimeout);
            }
            sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn get_contract_data(
        &self,
        contract_id: &[u8; 32],
    ) -> Result<ContractDataEntry, Error> {
        // Get the contract from the network
        let contract_key = LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: xdr::ScAddress::Contract(xdr::Hash(*contract_id)),
            key: xdr::ScVal::LedgerKeyContractInstance,
            durability: xdr::ContractDataDurability::Persistent,
        });
        let contract_ref = self.get_ledger_entries(&[contract_key]).await?;
        let entries = contract_ref.entries.unwrap_or_default();
        if entries.is_empty() {
            let contract_address = stellar_strkey::Contract(*contract_id).to_string();
            return Err(Error::NotFound("Contract".to_string(), contract_address));
        }
        let contract_ref_entry = &entries[0];
        match LedgerEntryData::from_xdr_base64(&contract_ref_entry.xdr)? {
            LedgerEntryData::ContractData(contract_data) => Ok(contract_data),
            scval => Err(Error::UnexpectedContractCodeDataType(scval)),
        }
    }

    pub async fn get_remote_wasm_from_hash(&self, hash: xdr::Hash) -> Result<Vec<u8>, Error> {
        let code_key = LedgerKey::ContractCode(xdr::LedgerKeyContractCode { hash: hash.clone() });
        let contract_data = self.get_ledger_entries(&[code_key]).await?;
        let entries = contract_data.entries.unwrap_or_default();
        if entries.is_empty() {
            return Err(Error::NotFound(
                "Contract Code".to_string(),
                hex::encode(hash),
            ));
        }
        let contract_data_entry = &entries[0];
        match LedgerEntryData::from_xdr_base64(&contract_data_entry.xdr)? {
            LedgerEntryData::ContractCode(xdr::ContractCodeEntry { code, .. }) => Ok(code.into()),
            scval => Err(Error::UnexpectedContractCodeDataType(scval)),
        }
    }

    pub async fn get_remote_contract_spec(
        &self,
        contract_id: &[u8; 32],
    ) -> Result<Vec<xdr::ScSpecEntry>, Error> {
        let contract_data = self.get_contract_data(contract_id).await?;
        match contract_data.val {
            xdr::ScVal::ContractInstance(xdr::ScContractInstance {
                executable: xdr::ContractExecutable::Wasm(hash),
                ..
            }) => Ok(contract_spec::ContractSpec::new(
                &self.get_remote_wasm_from_hash(hash).await?,
            )
            .map_err(Error::CouldNotParseContractSpec)?
            .spec),
            xdr::ScVal::ContractInstance(xdr::ScContractInstance {
                executable: xdr::ContractExecutable::Token,
                ..
            }) => Ok(soroban_spec::read::parse_raw(
                &token::StellarAssetSpec::spec_xdr(),
            )?),
            _ => Err(Error::Xdr(XdrError::Invalid)),
        }
    }
}
