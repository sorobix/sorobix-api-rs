use http::{uri::Authority, Uri};
use jsonrpsee_core::{self, client::ClientT, rpc_params};
use jsonrpsee_http_client::{HeaderMap, HttpClient, HttpClientBuilder};
use serde_aux::prelude::{deserialize_default_from_null, deserialize_number_from_string};
use soroban_env_host::{
    budget::Budget,
    events::HostEvent,
    xdr::{
        AccountEntry, AccountId, ContractAuth, DiagnosticEvent, Error as XdrError, LedgerEntryData,
        LedgerFootprint, LedgerKey, LedgerKeyAccount, PublicKey, ReadXdr, Transaction,
        TransactionEnvelope, TransactionMeta, TransactionResult, TransactionV1Envelope, Uint256,
        VecM, WriteXdr,
    },
};
use std::{
    str::FromStr,
    time::{Duration, Instant},
};
use tokio::time::sleep;

use crate::utils::transaction::assemble;

const VERSION: Option<&str> = option_env!("CARGO_PKG_VERSION");

pub type LogEvents = fn(
    footprint: &LedgerFootprint,
    auth: &Vec<VecM<ContractAuth>>,
    events: &[HostEvent],
    budget: Option<&Budget>,
) -> ();

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct GetLedgerEntriesResponse {
    pub entries: Vec<LedgerEntryResult>,
    #[serde(rename = "latestLedger")]
    pub latest_ledger: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct Cost {
    #[serde(
        rename = "cpuInsns",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub cpu_insns: String,
    #[serde(
        rename = "memBytes",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub mem_bytes: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct SimulateHostFunctionResult {
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub auth: Vec<String>,
    pub xdr: String,
}

#[derive(serde::Deserialize, serde::Serialize, Debug)]
pub struct SimulateTransactionResponse {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    #[serde(rename = "transactionData")]
    pub transaction_data: String,
    #[serde(deserialize_with = "deserialize_default_from_null")]
    pub events: Vec<String>,
    #[serde(
        rename = "minResourceFee",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub min_resource_fee: u32,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub results: Vec<SimulateHostFunctionResult>,
    pub cost: Cost,
    #[serde(
        rename = "latestLedger",
        deserialize_with = "deserialize_number_from_string"
    )]
    pub latest_ledger: u32,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
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
    #[error("unexpected ({length}) simulate transaction result length")]
    UnexpectedSimulateTransactionResultSize { length: usize },
    #[error("unexpected ({count}) number of operations")]
    UnexpectedOperationCount { count: usize },
    #[error(
        "unsupported operation type, must be only one InvokeHostFunctionOp in the transaction."
    )]
    UnsupportedOperationType,
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

fn extract_events(tx_meta: TransactionMeta) -> Vec<DiagnosticEvent> {
    match tx_meta {
        TransactionMeta::V3(v3) => {
            // NOTE: we assume there can only be one operation, since we only send one
            if v3.diagnostic_events.len() == 1 {
                v3.diagnostic_events[0].events.clone().into()
            } else if v3.events.len() == 1 {
                v3.events[0]
                    .events
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
        let key = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(
                stellar_strkey::ed25519::PublicKey::from_string(address)?.0,
            ))),
        });
        let response = self.get_ledger_entry(key).await?;
        if let LedgerEntryData::Account(entry) =
            LedgerEntryData::read_xdr_base64(&mut response.xdr.as_bytes())?
        {
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
        log_events: Option<LogEvents>,
    ) -> Result<Transaction, Error> {
        tracing::trace!(?tx);
        let sim_response = self
            .simulate_transaction(&TransactionEnvelope::Tx(TransactionV1Envelope {
                tx: tx.clone(),
                signatures: VecM::default(),
            }))
            .await?;
        assemble(tx, &sim_response, log_events)
    }

    pub async fn prepare_and_send_transaction(
        &self,
        tx_without_preflight: &Transaction,
        key: &ed25519_dalek::Keypair,
        network_passphrase: &str,
        log_events: Option<LogEvents>,
    ) -> Result<(TransactionResult, Vec<DiagnosticEvent>), Error> {
        let unsigned_tx = self
            .prepare_transaction(tx_without_preflight, log_events)
            .await?;
        let tx = crate::utils::helper::sign_transaction(key, &unsigned_tx, network_passphrase)?;
        self.send_transaction(&tx).await
    }

    pub async fn get_ledger_entries(
        &self,
        keys: Vec<LedgerKey>,
    ) -> Result<GetLedgerEntriesResponse, Error> {
        let mut base64_keys: Vec<String> = vec![];
        for k in &keys {
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
    ) -> Result<(TransactionResult, Vec<DiagnosticEvent>), Error> {
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
                    TransactionResult::read_xdr_base64(&mut x.as_bytes())
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
                    let result_xdr_b64 = response.result_xdr.ok_or(Error::MissingResult)?;
                    let result = TransactionResult::from_xdr_base64(result_xdr_b64)?;
                    let events = match response.result_meta_xdr {
                        None => Vec::new(),
                        Some(m) => extract_events(TransactionMeta::from_xdr_base64(m)?),
                    };
                    return Ok((result, events));
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
}
