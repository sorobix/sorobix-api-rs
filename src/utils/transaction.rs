use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};
use soroban_env_host::xdr::{
    AccountId, ExtensionPoint, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Memo,
    Operation, OperationBody, Preconditions, PublicKey, ReadXdr, RestoreFootprintOp, ScAddress,
    ScMap, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanCredentials, SorobanTransactionData, Transaction, TransactionExt, Uint256, VecM,
    WriteXdr,
};

use crate::utils::client::{Error, RestorePreamble, SimulateTransactionResponse};

// Apply the result of a simulateTransaction onto a transaction envelope, preparing it for
// submission to the network.
pub fn assemble(
    raw: &Transaction,
    simulation: &SimulateTransactionResponse,
) -> Result<Transaction, Error> {
    let mut tx = raw.clone();

    // Right now simulate.results is one-result-per-function, and assumes there is only one
    // operation in the txn, so we need to enforce that here. I (Paul) think that is a bug
    // in soroban-rpc.simulateTransaction design, and we should fix it there.
    // TODO: We should to better handling so non-soroban txns can be a passthrough here.
    if tx.operations.len() != 1 {
        return Err(Error::UnexpectedOperationCount {
            count: tx.operations.len(),
        });
    }

    let transaction_data = SorobanTransactionData::from_xdr_base64(&simulation.transaction_data)?;

    let mut op = tx.operations[0].clone();
    if let OperationBody::InvokeHostFunction(ref mut body) = &mut op.body {
        if body.auth.is_empty() {
            if simulation.results.len() != 1 {
                return Err(Error::UnexpectedSimulateTransactionResultSize {
                    length: simulation.results.len(),
                });
            }

            let auths = simulation
                .results
                .iter()
                .map(|r| {
                    VecM::try_from(
                        r.auth
                            .iter()
                            .map(SorobanAuthorizationEntry::from_xdr_base64)
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            if !auths.is_empty() {
                body.auth = auths[0].clone();
            }
        }
    }

    // update the fees of the actual transaction to meet the minimum resource fees.
    let classic_transaction_fees = crate::models::fee::Args::default().fee;
    // Pad the fees up by 15% for a bit of wiggle room.
    tx.fee = (tx.fee.max(
        classic_transaction_fees
            + u32::try_from(simulation.min_resource_fee)
                .map_err(|_| Error::LargeFee(simulation.min_resource_fee))?,
    ) * 115)
        / 100;

    tx.operations = vec![op].try_into()?;
    tx.ext = TransactionExt::V1(transaction_data);
    Ok(tx)
}

// Use the given source_key and signers, to sign all SorobanAuthorizationEntry's in the given
// transaction. If unable to sign, return an error.
pub fn sign_soroban_authorizations(
    raw: &Transaction,
    source_key: &ed25519_dalek::Keypair,
    signers: &[ed25519_dalek::Keypair],
    signature_expiration_ledger: u32,
    network_passphrase: &str,
) -> Result<(Transaction, Vec<SorobanAuthorizationEntry>), Error> {
    let mut tx = raw.clone();

    if tx.operations.len() != 1 {
        // This must not be an invokeHostFunction operation, so nothing to do
        return Ok((tx, Vec::new()));
    }

    let mut op = tx.operations[0].clone();
    let OperationBody::InvokeHostFunction(ref mut body) = &mut op.body else {
        return Ok((tx, Vec::new()));
    };

    let network_id = Hash(Sha256::digest(network_passphrase.as_bytes()).into());

    let source_address = source_key.public.as_bytes();

    let signed_auths = body
        .auth
        .iter()
        .map(|raw_auth| {
            let mut auth = raw_auth.clone();
            let SorobanAuthorizationEntry {
                credentials: SorobanCredentials::Address(ref mut credentials),
                ..
            } = auth
            else {
                // Doesn't need special signing
                return Ok(auth);
            };
            let SorobanAddressCredentials { ref address, .. } = credentials;

            // See if we have a signer for this authorizationEntry
            // If not, then we Error
            let needle = match address {
                ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(ref a)))) => a,
                ScAddress::Contract(Hash(c)) => {
                    // This address is for a contract. This means we're using a custom
                    // smart-contract account. Currently the CLI doesn't support that yet.
                    return Err(Error::MissingSignerForAddress {
                        address: stellar_strkey::Strkey::Contract(stellar_strkey::Contract(*c))
                            .to_string(),
                    });
                }
            };
            let signer = if let Some(s) = signers.iter().find(|s| needle == s.public.as_bytes()) {
                s
            } else if needle == source_address {
                // This is the source address, so we can sign it
                source_key
            } else {
                // We don't have a signer for this address
                return Err(Error::MissingSignerForAddress {
                    address: stellar_strkey::Strkey::PublicKeyEd25519(
                        stellar_strkey::ed25519::PublicKey(*needle),
                    )
                    .to_string(),
                });
            };

            sign_soroban_authorization_entry(
                raw_auth,
                signer,
                signature_expiration_ledger,
                &network_id,
            )
        })
        .collect::<Result<Vec<_>, Error>>()?;

    body.auth = signed_auths.clone().try_into()?;
    tx.operations = vec![op].try_into()?;
    Ok((tx, signed_auths))
}

pub fn sign_soroban_authorization_entry(
    raw: &SorobanAuthorizationEntry,
    signer: &ed25519_dalek::Keypair,
    signature_expiration_ledger: u32,
    network_id: &Hash,
) -> Result<SorobanAuthorizationEntry, Error> {
    let mut auth = raw.clone();
    let SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(ref mut credentials),
        ..
    } = auth
    else {
        // Doesn't need special signing
        return Ok(auth);
    };
    let SorobanAddressCredentials { nonce, .. } = credentials;

    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: network_id.clone(),
        invocation: auth.root_invocation.clone(),
        nonce: *nonce,
        signature_expiration_ledger,
    })
    .to_xdr()?;

    let payload = Sha256::digest(preimage);
    let signature = signer.sign(&payload);

    let map = ScMap::sorted_from(vec![
        (
            ScVal::Symbol(ScSymbol("public_key".try_into()?)),
            ScVal::Bytes(
                signer
                    .public
                    .to_bytes()
                    .to_vec()
                    .try_into()
                    .map_err(Error::Xdr)?,
            ),
        ),
        (
            ScVal::Symbol(ScSymbol("signature".try_into()?)),
            ScVal::Bytes(
                signature
                    .to_bytes()
                    .to_vec()
                    .try_into()
                    .map_err(Error::Xdr)?,
            ),
        ),
    ])
    .map_err(Error::Xdr)?;
    credentials.signature = ScVal::Vec(Some(
        vec![ScVal::Map(Some(map))].try_into().map_err(Error::Xdr)?,
    ));
    credentials.signature_expiration_ledger = signature_expiration_ledger;
    auth.credentials = SorobanCredentials::Address(credentials.clone());
    Ok(auth)
}

pub fn build_restore_txn(
    parent: &Transaction,
    restore: &RestorePreamble,
) -> Result<Transaction, Error> {
    let transaction_data =
        SorobanTransactionData::from_xdr_base64(restore.transaction_data.clone())?;
    let fee = u32::try_from(restore.min_resource_fee)
        .map_err(|_| Error::LargeFee(restore.min_resource_fee))?;
    Ok(Transaction {
        source_account: parent.source_account.clone(),
        fee: parent
            .fee
            .checked_add(fee)
            .ok_or(Error::LargeFee(restore.min_resource_fee))?,
        seq_num: parent.seq_num.clone(),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![Operation {
            source_account: None,
            body: OperationBody::RestoreFootprint(RestoreFootprintOp {
                ext: ExtensionPoint::V0,
            }),
        }]
        .try_into()
        .unwrap(),
        ext: TransactionExt::V1(transaction_data),
    })
}
