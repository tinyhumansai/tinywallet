//! EVM signing and broadcast (Ethereum mainnet and the L2s). A single key
//! derivation path (`m/44'/60'/…`) serves every EVM network, so every network
//! shares one address.
//!
//! Network selection comes from `PreparedTransaction::evm_network`; `None`
//! (legacy quotes, or callers that did not specify) means Ethereum mainnet.

use log::debug;
use serde_json::{Value, json};
use tinywallet_bus::wire::TransactionSpec;

use crate::crypto::abi::encode_erc20_transfer;
use crate::crypto::defaults::{EvmNetwork, explorer_tx_url_for_evm_network};
use crate::crypto::execution::{
    ExecutionResult, PreparedKind, PreparedStatus, PreparedTransaction, RawBroadcastResult,
    TxLookupInfo, TxReceiptInfo, TxState, TxStatusInfo, hex_to_u128, u128_to_hex,
    validate_calldata,
};
use crate::crypto::wallet::{WalletChain, WalletEngine};

const LOG_PREFIX: &str = "[wallet::evm]";

/// Native balance of `address` on `network`, in wei.
pub(crate) async fn evm_balance(
    engine: &WalletEngine,
    network: EvmNetwork,
    address: &str,
) -> Result<u128, String> {
    let raw: String = engine
        .evm_rpc_call(network, "eth_getBalance", json!([address, "latest"]))
        .await?;
    hex_to_u128(&raw)
}

/// What a signed EVM transaction needs from the node.
struct NodeParams {
    chain_id: u64,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
}

/// Read chain id, nonce, gas price and a gas estimate, and check the node is on
/// the network the quote names.
async fn node_params(
    engine: &WalletEngine,
    network: EvmNetwork,
    from_address: &str,
    estimate_tx: Value,
) -> Result<NodeParams, String> {
    let chain_id_hex: String = engine
        .evm_rpc_call(network, "eth_chainId", json!([]))
        .await?;
    // Use "pending" so already-submitted-but-not-mined txs don't cause a nonce
    // collision when two confirmations land back-to-back.
    let nonce_hex: String = engine
        .evm_rpc_call(
            network,
            "eth_getTransactionCount",
            json!([from_address, "pending"]),
        )
        .await?;
    let gas_price_hex: String = engine
        .evm_rpc_call(network, "eth_gasPrice", json!([]))
        .await?;
    let gas_hex: String = engine
        .evm_rpc_call(network, "eth_estimateGas", json!([estimate_tx]))
        .await?;
    let chain_id = u64::try_from(hex_to_u128(&chain_id_hex)?)
        .map_err(|_| format!("EVM RPC reported an implausible chain_id '{chain_id_hex}'"))?;
    if chain_id != network.chain_id() {
        return Err(format!(
            "EVM RPC chain_id mismatch: rpc reported {} but network {} expects {}",
            chain_id,
            network.as_str(),
            network.chain_id()
        ));
    }
    let nonce = u64::try_from(hex_to_u128(&nonce_hex)?)
        .map_err(|_| format!("EVM RPC reported an implausible nonce '{nonce_hex}'"))?;
    let gas_price = hex_to_u128(&gas_price_hex)?;
    let gas_limit = u64::try_from(hex_to_u128(&gas_hex)?)
        .map_err(|_| format!("EVM RPC reported an implausible gas limit '{gas_hex}'"))?;
    Ok(NodeParams {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
    })
}

/// Sign an EVM transaction `(to, value, data)` with the wallet's key and
/// broadcast it on `network`. Shared core behind both [`execute_evm_quote`]
/// (native and token transfers) and [`sign_and_broadcast_evm`] (raw, dapp and
/// swap calldata from the service).
///
/// Returns `(tx_hash, fee_raw)` where `fee_raw` is the simulated
/// `gas * gasPrice`.
async fn sign_and_broadcast(
    engine: &WalletEngine,
    network: EvmNetwork,
    from_address: &str,
    to: &str,
    value_raw: &str,
    tx_data: Option<String>,
) -> Result<(String, u128), String> {
    let to = tinywallet_crypto::address::evm::validate(to)
        .map_err(|e| format!("invalid EVM target address '{to}': {e}"))?;
    let value = value_raw
        .trim()
        .parse::<u128>()
        .map_err(|e| format!("invalid native value '{value_raw}': {e}"))?;
    let mut estimate_tx = json!({
        "from": from_address,
        "to": to,
        "value": u128_to_hex(value),
    });
    if let Some(data_hex) = tx_data.as_deref() {
        estimate_tx["data"] = json!(data_hex);
    }
    let params = node_params(engine, network, from_address, estimate_tx).await?;

    let transaction = TransactionSpec::Evm {
        to,
        value_wei: value.to_string(),
        data_hex: tx_data.unwrap_or_default(),
        nonce: params.nonce,
        gas_limit: params.gas_limit,
        gas_price_wei: params.gas_price.to_string(),
        chain_id: params.chain_id,
    };
    let signed = engine
        .signer
        .sign_transaction(WalletChain::Evm, &transaction)
        .await?;

    let tx_hash: String = engine
        .evm_rpc_call(network, "eth_sendRawTransaction", json!([signed.raw]))
        .await?;
    let fee = params
        .gas_price
        .checked_mul(u128::from(params.gas_limit))
        .unwrap_or_default();
    debug!(
        "{LOG_PREFIX} sign_and_broadcast network={} tx_hash={tx_hash}",
        network.as_str()
    );
    Ok((tx_hash, fee))
}

/// Sign and broadcast a prepared EVM transfer.
pub(crate) async fn execute_evm_quote(
    engine: &WalletEngine,
    mut quote: PreparedTransaction,
) -> Result<ExecutionResult, String> {
    let network = quote.evm_network.unwrap_or(EvmNetwork::EthereumMainnet);
    let (tx_to, tx_value, tx_data) = match quote.kind {
        // A native transfer pays the recipient directly and carries no data.
        PreparedKind::NativeTransfer => (
            tinywallet_crypto::address::evm::validate(&quote.to_address).map_err(|e| {
                format!("invalid EVM recipient address '{}': {e}", quote.to_address)
            })?,
            quote.amount_raw.clone(),
            None,
        ),
        // A token transfer pays the *contract* zero and puts the recipient and
        // the amount in the calldata instead.
        PreparedKind::TokenTransfer => {
            let token = quote
                .token_address
                .as_deref()
                .ok_or_else(|| "prepared token transfer is missing token_address".to_string())?;
            let calldata = encode_erc20_transfer(&quote.to_address, &quote.amount_raw)?;
            (
                tinywallet_crypto::address::evm::validate(token)
                    .map_err(|e| format!("invalid ERC20 token contract address '{token}': {e}"))?,
                "0".to_string(),
                Some(calldata),
            )
        }
    };

    let (tx_hash, fee) = sign_and_broadcast(
        engine,
        network,
        &quote.from_address,
        &tx_to,
        &tx_value,
        tx_data,
    )
    .await?;
    quote.estimated_fee_raw = fee.to_string();
    quote.status = PreparedStatus::Broadcasted;
    debug!(
        "{LOG_PREFIX} execute_prepared quote_id={} network={} tx_hash={tx_hash}",
        quote.quote_id,
        network.as_str()
    );
    Ok(ExecutionResult {
        quote_id: quote.quote_id.clone(),
        status: PreparedStatus::Broadcasted,
        chain: WalletChain::Evm,
        evm_network: Some(network),
        transaction_hash: tx_hash.clone(),
        explorer_url: explorer_tx_url_for_evm_network(network, &tx_hash),
        transaction: quote,
    })
}

/// Sign an externally-built unsigned EVM transaction (`to` / `data` / `value`)
/// with the wallet's key and broadcast it. Used by the service for deBridge
/// swap/bridge transactions and generic dapp contract calls.
pub(crate) async fn sign_and_broadcast_evm(
    engine: &WalletEngine,
    network: EvmNetwork,
    to: &str,
    data_hex: Option<String>,
    value_raw: &str,
) -> Result<RawBroadcastResult, String> {
    let account = engine.require_evm_account().await?;
    let data = data_hex.map(|d| validate_calldata(&d)).transpose()?;
    // `to` and `value_raw` are validated inside `sign_and_broadcast`, which is
    // the only place that needs them parsed.
    let (tx_hash, fee) = sign_and_broadcast(engine, network, &account, to, value_raw, data).await?;
    Ok(RawBroadcastResult {
        transaction_hash: tx_hash.clone(),
        explorer_url: explorer_tx_url_for_evm_network(network, &tx_hash),
        fee_raw: Some(fee.to_string()),
    })
}

/// A hex-quantity field of a JSON object, parsed.
fn hex_field(value: &Value, key: &str) -> Option<u128> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(|s| hex_to_u128(s).ok())
}

/// `status` of a receipt: `Some(true)` for success. An unparseable status
/// counts as success, matching what nodes that omit it mean.
fn receipt_success(receipt: &Value) -> Option<bool> {
    receipt
        .get("status")
        .and_then(Value::as_str)
        .map(|s| hex_to_u128(s).map_or(true, |v| v != 0))
}

fn block_number_of(receipt: &Value) -> Option<u64> {
    hex_field(receipt, "blockNumber").map(|v| u64::try_from(v).unwrap_or(u64::MAX))
}

/// `eth_getTransactionReceipt` plus `eth_blockNumber` to a normalized status.
pub(crate) async fn tx_status(
    engine: &WalletEngine,
    network: EvmNetwork,
    hash: &str,
) -> Result<TxStatusInfo, String> {
    let receipt: Value = engine
        .evm_rpc_call(network, "eth_getTransactionReceipt", json!([hash]))
        .await?;
    let row = |state, confirmations, block_number| TxStatusInfo {
        chain: WalletChain::Evm,
        evm_network: Some(network),
        hash: hash.to_string(),
        state,
        confirmations,
        block_number,
    };
    if receipt.is_null() {
        // No receipt yet: distinguish pending (tx known) from not-found.
        let tx: Value = engine
            .evm_rpc_call(network, "eth_getTransactionByHash", json!([hash]))
            .await?;
        let state = if tx.is_null() {
            TxState::NotFound
        } else {
            TxState::Pending
        };
        return Ok(row(state, None, None));
    }
    let status_ok = receipt_success(&receipt).unwrap_or(true);
    let block_number = block_number_of(&receipt);
    let confirmations = match block_number {
        Some(bn) => {
            let head_hex: String = engine
                .evm_rpc_call(network, "eth_blockNumber", json!([]))
                .await?;
            hex_to_u128(&head_hex).ok().map(|head| {
                u64::try_from(head)
                    .unwrap_or(u64::MAX)
                    .saturating_sub(bn)
                    .saturating_add(1)
            })
        }
        None => None,
    };
    let state = if status_ok {
        TxState::Confirmed
    } else {
        TxState::Failed
    };
    Ok(row(state, confirmations, block_number))
}

/// `eth_getTransactionReceipt` to a normalized receipt with raw passthrough.
pub(crate) async fn tx_receipt(
    engine: &WalletEngine,
    network: EvmNetwork,
    hash: &str,
) -> Result<TxReceiptInfo, String> {
    let receipt: Value = engine
        .evm_rpc_call(network, "eth_getTransactionReceipt", json!([hash]))
        .await?;
    if receipt.is_null() {
        // No receipt yet: a freshly broadcast tx is still "found" if the node
        // knows the tx hash; only report not-found when both calls are null.
        let tx: Value = engine
            .evm_rpc_call(network, "eth_getTransactionByHash", json!([hash]))
            .await?;
        return Ok(TxReceiptInfo {
            chain: WalletChain::Evm,
            evm_network: Some(network),
            hash: hash.to_string(),
            found: !tx.is_null(),
            success: None,
            block_number: None,
            gas_used: None,
            fee_raw: None,
            raw: Value::Null,
        });
    }
    let gas_used = hex_field(&receipt, "gasUsed");
    let fee_raw = match (gas_used, hex_field(&receipt, "effectiveGasPrice")) {
        (Some(g), Some(p)) => g.checked_mul(p).map(|f| f.to_string()),
        _ => None,
    };
    Ok(TxReceiptInfo {
        chain: WalletChain::Evm,
        evm_network: Some(network),
        hash: hash.to_string(),
        found: true,
        success: receipt_success(&receipt),
        block_number: block_number_of(&receipt),
        gas_used: gas_used.map(|g| g.to_string()),
        fee_raw,
        raw: receipt,
    })
}

/// `eth_getTransactionByHash` as a raw transaction passthrough.
pub(crate) async fn lookup_tx(
    engine: &WalletEngine,
    network: EvmNetwork,
    hash: &str,
) -> Result<TxLookupInfo, String> {
    let tx: Value = engine
        .evm_rpc_call(network, "eth_getTransactionByHash", json!([hash]))
        .await?;
    Ok(TxLookupInfo {
        chain: WalletChain::Evm,
        evm_network: Some(network),
        hash: hash.to_string(),
        found: !tx.is_null(),
        raw: tx,
    })
}

#[cfg(test)]
mod test;
