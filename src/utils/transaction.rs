use soroban_env_host::xdr::{
    ContractAuth, DiagnosticEvent, HostFunction, OperationBody, ReadXdr, SorobanTransactionData,
    Transaction, TransactionExt, VecM,
};

use crate::utils::client::{Error, LogEvents, SimulateTransactionResponse};

// Apply the result of a simulateTransaction onto a transaction envelope, preparing it for
// submission to the network.
pub fn assemble(
    raw: &Transaction,
    simulation: &SimulateTransactionResponse,
    log_events: Option<LogEvents>,
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

    // TODO: Should we keep this?
    let events = simulation
        .events
        .iter()
        .map(DiagnosticEvent::from_xdr_base64)
        .collect::<Result<Vec<_>, _>>()?;
    if !events.is_empty() {
        tracing::debug!(simulation_events=?events);
    }

    // update the fees of the actual transaction to meet the minimum resource fees.
    let mut fee = tx.fee;
    let classic_transaction_fees = crate::models::fee::Args::default().fee;
    if fee < classic_transaction_fees + simulation.min_resource_fee {
        fee = classic_transaction_fees + simulation.min_resource_fee;
    }

    let transaction_data = SorobanTransactionData::from_xdr_base64(&simulation.transaction_data)?;

    let mut op = tx.operations[0].clone();
    if let OperationBody::InvokeHostFunction(ref mut body) = &mut op.body {
        if simulation.results.len() != body.functions.len() {
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
                        .map(ContractAuth::from_xdr_base64)
                        .collect::<Result<Vec<_>, _>>()?,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(log) = log_events {
            log(&transaction_data.resources.footprint, &auths, &[], None);
        }
        body.functions = body
            .functions
            .iter()
            .zip(auths)
            .map(|(f, auth)| HostFunction {
                args: f.args.clone(),
                auth,
            })
            .collect::<Vec<_>>()
            .try_into()?;
    } else {
        return Err(Error::UnsupportedOperationType);
    }

    tx.fee = fee;
    tx.operations = vec![op].try_into()?;
    tx.ext = TransactionExt::V1(transaction_data);
    Ok(tx)
}
