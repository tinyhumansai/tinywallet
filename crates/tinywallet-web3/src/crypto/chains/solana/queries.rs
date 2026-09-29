//! Read-only Solana lookups by signature.

use serde::Deserialize;
use serde_json::{Value, json};

use crate::crypto::execution::{TxLookupInfo, TxReceiptInfo, TxState, TxStatusInfo};
use crate::crypto::wallet::{WalletChain, WalletEngine};

/// `getSignatureStatuses` to a normalized status.
pub(crate) async fn tx_status(engine: &WalletEngine, hash: &str) -> Result<TxStatusInfo, String> {
    #[derive(Deserialize)]
    struct StatusResp {
        value: Vec<Option<SigStatus>>,
    }
    #[derive(Deserialize)]
    struct SigStatus {
        slot: u64,
        confirmations: Option<u64>,
        err: Option<Value>,
    }
    let resp: StatusResp = engine
        .rpc_call(
            WalletChain::Solana,
            "getSignatureStatuses",
            json!([[hash], {"searchTransactionHistory": true}]),
        )
        .await?;
    let entry = resp.value.into_iter().next().flatten();
    let (state, confirmations, block_number) = match entry {
        None => (TxState::NotFound, None, None),
        Some(status) => {
            let state = if status.err.is_some() {
                TxState::Failed
            } else if status.confirmations.is_none() {
                // null confirmations means "finalized / rooted".
                TxState::Confirmed
            } else {
                TxState::Pending
            };
            (state, status.confirmations, Some(status.slot))
        }
    };
    Ok(TxStatusInfo {
        chain: WalletChain::Solana,
        evm_network: None,
        hash: hash.to_string(),
        state,
        confirmations,
        block_number,
    })
}

async fn get_transaction(engine: &WalletEngine, hash: &str) -> Result<Value, String> {
    engine
        .rpc_call(
            WalletChain::Solana,
            "getTransaction",
            json!([hash, {"maxSupportedTransactionVersion": 0, "encoding": "json"}]),
        )
        .await
}

/// `getTransaction` to a normalized receipt with raw passthrough.
pub(crate) async fn tx_receipt(
    engine: &WalletEngine,
    hash: &str,
) -> Result<TxReceiptInfo, String> {
    let tx = get_transaction(engine, hash).await?;
    if tx.is_null() {
        return Ok(TxReceiptInfo {
            chain: WalletChain::Solana,
            evm_network: None,
            hash: hash.to_string(),
            found: false,
            success: None,
            block_number: None,
            gas_used: None,
            fee_raw: None,
            raw: Value::Null,
        });
    }
    let meta = tx.get("meta");
    let success = meta.map(|m| m.get("err").is_none_or(Value::is_null));
    let fee_raw = meta
        .and_then(|m| m.get("fee"))
        .and_then(Value::as_u64)
        .map(|f| f.to_string());
    let block_number = tx.get("slot").and_then(Value::as_u64);
    Ok(TxReceiptInfo {
        chain: WalletChain::Solana,
        evm_network: None,
        hash: hash.to_string(),
        found: true,
        success,
        block_number,
        gas_used: None,
        fee_raw,
        raw: tx,
    })
}

/// `getTransaction` as a raw transaction passthrough.
pub(crate) async fn lookup_tx(engine: &WalletEngine, hash: &str) -> Result<TxLookupInfo, String> {
    let tx = get_transaction(engine, hash).await?;
    Ok(TxLookupInfo {
        chain: WalletChain::Solana,
        evm_network: None,
        hash: hash.to_string(),
        found: !tx.is_null(),
        raw: tx,
    })
}
