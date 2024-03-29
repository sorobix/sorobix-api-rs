use ed25519_dalek::Signer;
use hex::FromHexError;
use sha2::{Digest, Sha256};
use soroban_env_host::xdr::{
    DecoratedSignature, Error as XdrError, Hash, Signature, SignatureHint, Transaction,
    TransactionEnvelope, TransactionSignaturePayload, TransactionSignaturePayloadTaggedTransaction,
    TransactionV1Envelope, WriteXdr,
};

use stellar_strkey::ed25519::PrivateKey;

use crate::models::deploy_contract::RedisResponse;

/// # Errors
///
/// Might return an error
pub fn contract_hash(contract: &[u8]) -> Result<Hash, XdrError> {
    Ok(Hash(Sha256::digest(contract).into()))
}
/// # Errors
///
/// Might return an error
pub fn padded_hex_from_str(s: &String, n: usize) -> Result<Vec<u8>, FromHexError> {
    let mut decoded = vec![0u8; n];
    let padded = format!("{s:0>width$}", width = n * 2);
    hex::decode_to_slice(padded, &mut decoded)?;
    Ok(decoded)
}

/// # Errors
///
/// Might return an error
pub fn contract_id_from_str(contract_id: &str) -> Result<[u8; 32], stellar_strkey::DecodeError> {
    stellar_strkey::Contract::from_string(contract_id)
        .map(|strkey| strkey.0)
        .or_else(|_| {
            // strkey failed, try to parse it as a hex string, for backwards compatibility.
            soroban_spec_tools::utils::padded_hex_from_str(contract_id, 32)
                .map_err(|_| stellar_strkey::DecodeError::Invalid)?
                .try_into()
                .map_err(|_| stellar_strkey::DecodeError::Invalid)
        })
        .map_err(|_| stellar_strkey::DecodeError::Invalid)
}

/// # Errors
///
/// Might return an error
pub fn transaction_hash(tx: &Transaction, network_passphrase: &str) -> Result<[u8; 32], XdrError> {
    let signature_payload = TransactionSignaturePayload {
        network_id: Hash(Sha256::digest(network_passphrase).into()),
        tagged_transaction: TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone()),
    };
    Ok(Sha256::digest(signature_payload.to_xdr()?).into())
}

/// # Errors
///
/// Might return an error
pub fn sign_transaction(
    key: &ed25519_dalek::Keypair,
    tx: &Transaction,
    network_passphrase: &str,
) -> Result<TransactionEnvelope, XdrError> {
    let tx_hash = transaction_hash(tx, network_passphrase)?;
    let tx_signature = key.sign(&tx_hash);

    let decorated_signature = DecoratedSignature {
        hint: SignatureHint(key.public.to_bytes()[28..].try_into()?),
        signature: Signature(tx_signature.to_bytes().try_into()?),
    };

    Ok(TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: tx.clone(),
        signatures: vec![decorated_signature].try_into()?,
    }))
}

/// # Errors
///
/// Might return an error
pub fn id_from_str<const N: usize>(contract_id: &String) -> Result<[u8; N], FromHexError> {
    padded_hex_from_str(contract_id, N)?
        .try_into()
        .map_err(|_| FromHexError::InvalidStringLength)
}

pub(crate) fn into_key_pair(
    key: &PrivateKey,
) -> Result<ed25519_dalek::Keypair, ed25519_dalek::SignatureError> {
    let secret = ed25519_dalek::SecretKey::from_bytes(&key.0)?;
    let public = (&secret).into();
    Ok(ed25519_dalek::Keypair { secret, public })
}

/// Used in tests
#[allow(unused)]
pub(crate) fn parse_secret_key(
    s: &str,
) -> Result<ed25519_dalek::Keypair, ed25519_dalek::SignatureError> {
    into_key_pair(&PrivateKey::from_string(s).unwrap())
}

pub fn redis_decoder(i: &str) -> Vec<u8> {
    if let Ok(res) = serde_json::from_str::<RedisResponse>(i) {
        if !res.status {
            tracing::debug!("the deployed contract is false")
        }
        match base64::decode(res.wasm) {
            Ok(d) => return d,
            Err(err) => {
                tracing::error!("decode error {}", err);
                return vec![];
            }
        }
    } else {
        tracing::error!("serde decode error");
    };
    vec![]
}
