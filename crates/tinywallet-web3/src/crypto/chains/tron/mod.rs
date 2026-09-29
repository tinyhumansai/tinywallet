//! Tron native TRX and TRC-20 transfers over the `TronGrid` REST API
//! (`wallet/createtransaction`, `wallet/triggersmartcontract`,
//! `wallet/broadcasttransaction`).
//!
//! Tron is the odd chain: the *node* builds the transaction, so a client that
//! signs what it is handed authorises whatever a compromised endpoint returned.
//! [`tron_transaction_spec`] therefore verifies every requested field against
//! the returned bytes before anything reaches the signer, and the signer
//! re-checks independently.
//!
//! Derivation is BIP44 `m/44'/195'/0'/0/0` on secp256k1, done by the signer.

use log::debug;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use tinywallet_bus::wire::TransactionSpec;
use tinywallet_crypto::TronTransfer;

use crate::crypto::defaults::explorer_tx_url;
use crate::crypto::execution::{
    ExecutionResult, PreparedKind, PreparedStatus, PreparedTransaction, TxLookupInfo,
    TxReceiptInfo, TxState, TxStatusInfo,
};
use crate::crypto::wallet::{WalletChain, WalletEngine};

const LOG_PREFIX: &str = "[wallet::tron]";
/// Fixed `TRC20` `fee_limit` (15 TRX = `15_000_000` SUN). A safe upper bound.
const TRC20_FEE_LIMIT_SUN: u64 = 15_000_000;

fn accepted(result: &Result<String, String>) -> &'static str {
    if result.is_ok() {
        "accepted"
    } else {
        "rejected"
    }
}

/// Validate a Tron mainnet base58check address.
pub(crate) fn validate_tron_address(addr: &str) -> Result<String, String> {
    let result = tinywallet_crypto::address::tron::validate(addr).map_err(|e| e.to_string());
    debug!("{LOG_PREFIX} validate_address result={}", accepted(&result));
    result
}

/// Convert a base58check Tron address into the 42-hex-digit form the `TronGrid`
/// API expects, version prefix included. The address is validated first.
pub(crate) fn tron_address_to_hex(addr: &str) -> Result<String, String> {
    let result = tinywallet_crypto::address::tron::to_hex(addr).map_err(|e| e.to_string());
    debug!("{LOG_PREFIX} address_to_hex result={}", accepted(&result));
    result
}

/// Native balance of `address`, in SUN.
pub(crate) async fn native_balance(engine: &WalletEngine, address: &str) -> Result<u128, String> {
    validate_tron_address(address)?;
    let body = json!({
        "address": tron_address_to_hex(address)?,
        "visible": false,
    });
    let resp: Value = engine
        .rest_post_json(WalletChain::Tron, "wallet/getaccount", &body)
        .await?;
    let balance = resp.get("balance").and_then(Value::as_u64).unwrap_or(0);
    Ok(u128::from(balance))
}

#[derive(Debug, Deserialize)]
struct CreateTransactionResponse {
    #[serde(rename = "txID")]
    tx_id: String,
    raw_data: Value,
    raw_data_hex: String,
}

#[derive(Debug, Deserialize)]
struct TriggerSmartContractResponse {
    transaction: CreateTransactionResponse,
}

/// Check a node-built Tron transaction, then describe it for the signer.
///
/// The verification itself lives in `tinywallet_crypto::tx::tron`, which parses
/// `raw_data` structurally. What stays here is the fee limit this client pins
/// and the [`TransactionSpec`] handed to the signer.
fn tron_transaction_spec(
    raw_tx: &CreateTransactionResponse,
    expected_to: String,
    transfer: &TronTransfer,
) -> Result<TransactionSpec, String> {
    let recomputed_txid = tinywallet_crypto::tx::tron::recompute_txid(&raw_tx.raw_data_hex)
        .map_err(|error| format!("invalid Tron raw_data_hex: {error}"))?;

    // The fee limit is ours, not the crate's: it is what this client pinned in
    // the `createtransaction` request, and only a TRC-20 trigger carries one.
    let fee_limit_sun = match transfer {
        TronTransfer::Native { .. } => None,
        TronTransfer::Trc20 { .. } => Some(TRC20_FEE_LIMIT_SUN),
    };

    tinywallet_crypto::tx::tron::verify_contract(
        &raw_tx.raw_data_hex,
        &expected_to,
        &raw_tx.tx_id,
        transfer,
        fee_limit_sun,
    )
    .map_err(|error| format!("Tron node response rejected: {error}"))?;

    Ok(TransactionSpec::Tron {
        raw_data_hex: raw_tx.raw_data_hex.clone(),
        expected_to,
        expected_txid: recomputed_txid,
        // Carried onto the wire so the signer re-checks it against the bytes it
        // is about to sign, rather than trusting this side's verdict.
        transfer: transfer.clone(),
    })
}

fn pad_left_32(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    if bytes.len() <= 32 {
        out[32 - bytes.len()..].copy_from_slice(bytes);
    } else {
        out.copy_from_slice(&bytes[bytes.len() - 32..]);
    }
    out
}

/// The `parameter` field of a TRC20 `triggerSmartContract` call: hex-encoded ABI
/// args with no 4-byte selector (`TronGrid` prepends it from
/// `function_selector`). The address is left-padded to 32 bytes, dropping the
/// `0x41` prefix.
fn encode_trc20_transfer_param(to_hex: &str, amount: u128) -> Result<String, String> {
    let addr_bytes = hex::decode(to_hex).map_err(|e| format!("invalid hex addr: {e}"))?;
    if addr_bytes.len() != 21 {
        return Err(format!(
            "expected 21-byte Tron address, got {}",
            addr_bytes.len()
        ));
    }
    let mut param = vec![0u8; 32];
    param[12..].copy_from_slice(&addr_bytes[1..]); // skip the 0x41 prefix
    let amount_bytes = amount.to_be_bytes();
    param.extend(pad_left_32(&amount_bytes[..]));
    Ok(hex::encode(param))
}

async fn create_native_transaction(
    engine: &WalletEngine,
    owner_hex: &str,
    to_hex: &str,
    amount_sun: u64,
) -> Result<CreateTransactionResponse, String> {
    let body = json!({
        "owner_address": owner_hex,
        "to_address": to_hex,
        "amount": amount_sun,
        "visible": false,
    });
    engine
        .rest_post_json(WalletChain::Tron, "wallet/createtransaction", &body)
        .await
}

async fn trigger_trc20_transfer(
    engine: &WalletEngine,
    owner_hex: &str,
    contract_hex: &str,
    parameter_hex: &str,
) -> Result<CreateTransactionResponse, String> {
    let body = json!({
        "owner_address": owner_hex,
        "contract_address": contract_hex,
        "function_selector": "transfer(address,uint256)",
        "parameter": parameter_hex,
        "fee_limit": TRC20_FEE_LIMIT_SUN,
        "call_value": 0,
        "visible": false,
    });
    let resp: TriggerSmartContractResponse = engine
        .rest_post_json(WalletChain::Tron, "wallet/triggersmartcontract", &body)
        .await?;
    Ok(resp.transaction)
}

/// Ask the node to build the transaction for `quote`, returning it with the
/// recipient the *transaction* pays and the transfer description to verify.
///
/// A native transfer pays the recipient; a TRC-20 transfer pays the token
/// contract and carries the recipient inside the call parameter (left-padded
/// to 32 bytes, so without the `41` prefix that appears in `raw_data` for a
/// native transfer). Verifying a TRC-20 against the user's recipient would
/// therefore never match.
async fn build_transaction(
    engine: &WalletEngine,
    quote: &PreparedTransaction,
    owner_hex: &str,
    to_hex: &str,
    amount: u128,
) -> Result<(String, TronTransfer, CreateTransactionResponse), String> {
    match quote.kind {
        PreparedKind::NativeTransfer => {
            let amount_sun: u64 = amount
                .try_into()
                .map_err(|_| format!("Tron amount {amount} exceeds u64"))?;
            let raw = create_native_transaction(engine, owner_hex, to_hex, amount_sun).await?;
            Ok((
                quote.to_address.clone(),
                TronTransfer::Native { amount_sun },
                raw,
            ))
        }
        PreparedKind::TokenTransfer => {
            let contract = quote
                .token_address
                .as_deref()
                .ok_or_else(|| "TRC20 transfer missing token_address".to_string())?;
            validate_tron_address(contract)?;
            let contract_hex = tron_address_to_hex(contract)?;
            let parameter = encode_trc20_transfer_param(to_hex, amount)?;
            let raw = trigger_trc20_transfer(engine, owner_hex, &contract_hex, &parameter).await?;
            Ok((
                contract.to_string(),
                TronTransfer::Trc20 {
                    parameter_hex: parameter,
                },
                raw,
            ))
        }
    }
}

/// The signature attached to the node-built transaction, ready to broadcast.
fn signed_broadcast_body(raw_tx: CreateTransactionResponse, signature_hex: String) -> Value {
    let mut body = Map::new();
    body.insert("txID".to_string(), Value::String(raw_tx.tx_id));
    body.insert("raw_data".to_string(), raw_tx.raw_data);
    body.insert(
        "raw_data_hex".to_string(),
        Value::String(raw_tx.raw_data_hex),
    );
    body.insert(
        "signature".to_string(),
        Value::Array(vec![Value::String(signature_hex)]),
    );
    // `visible: false` selects hex addresses on broadcast.
    body.insert("visible".to_string(), Value::Bool(false));
    Value::Object(body)
}

/// Sign and broadcast a prepared Tron transfer.
pub(crate) async fn execute_tron_quote(
    engine: &WalletEngine,
    mut quote: PreparedTransaction,
) -> Result<ExecutionResult, String> {
    validate_tron_address(&quote.from_address)?;
    validate_tron_address(&quote.to_address)?;
    let amount: u128 = quote
        .amount_raw
        .parse()
        .map_err(|e| format!("invalid Tron amount '{}': {e}", quote.amount_raw))?;

    let owner_hex = tron_address_to_hex(&quote.from_address)?;
    let to_hex = tron_address_to_hex(&quote.to_address)?;

    let derived_addr = engine
        .signer
        .derive_account(WalletChain::Tron)
        .await?
        .address;
    if derived_addr != quote.from_address {
        return Err(format!(
            "Tron key derivation mismatch: derived {derived_addr} but expected {}",
            quote.from_address
        ));
    }

    let (verified_recipient, transfer, raw_tx) =
        build_transaction(engine, &quote, &owner_hex, &to_hex, amount).await?;

    // The node builds the transaction, so verify every requested field here
    // before the signer hands back a signature. The signer independently
    // rechecks the locally recomputed txid and recipient; the host additionally
    // binds the native amount or full TRC20 parameter.
    let transfer_kind = match &transfer {
        TronTransfer::Native { .. } => "native",
        TronTransfer::Trc20 { .. } => "trc20",
    };
    let transaction = match tron_transaction_spec(&raw_tx, verified_recipient, &transfer) {
        Ok(transaction) => {
            debug!(
                "{LOG_PREFIX} validation=accepted quote_id={} txid={} kind={transfer_kind}",
                quote.quote_id, raw_tx.tx_id
            );
            transaction
        }
        Err(error) => {
            debug!(
                "{LOG_PREFIX} validation=rejected quote_id={} txid={} kind={transfer_kind} reason={error}",
                quote.quote_id, raw_tx.tx_id
            );
            return Err(error);
        }
    };
    let signed = engine
        .signer
        .sign_transaction(WalletChain::Tron, &transaction)
        .await?;

    let tx_id = raw_tx.tx_id.clone();
    let body = signed_broadcast_body(raw_tx, signed.raw);
    let response: Value = engine
        .rest_post_json(WalletChain::Tron, "wallet/broadcasttransaction", &body)
        .await?;
    let ok = response
        .get("result")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !ok {
        let code = response.get("code").and_then(Value::as_str).unwrap_or("");
        let msg = response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or_default();
        return Err(format!(
            "Tron broadcast rejected: code={code} message={msg}"
        ));
    }
    let txid = response
        .get("txid")
        .and_then(Value::as_str)
        .map_or(tx_id, str::to_string);

    quote.status = PreparedStatus::Broadcasted;
    debug!(
        "{LOG_PREFIX} broadcast quote_id={} txid={txid} kind={:?}",
        quote.quote_id, quote.kind
    );
    let explorer_url = explorer_tx_url(WalletChain::Tron, &txid);
    Ok(ExecutionResult {
        quote_id: quote.quote_id.clone(),
        status: PreparedStatus::Broadcasted,
        chain: WalletChain::Tron,
        evm_network: None,
        transaction_hash: txid,
        explorer_url,
        transaction: quote,
    })
}

async fn tron_post(engine: &WalletEngine, path: &str, body: Value) -> Result<Value, String> {
    engine
        .rest_post_json(WalletChain::Tron, path.trim_start_matches('/'), &body)
        .await
}

/// Whether a `gettransactionbyid` reply is a real transaction (`TronGrid`
/// returns `{}` for an unknown id).
fn is_known_tx(tx: &Value) -> bool {
    tx.get("txID").is_some() || tx.get("raw_data").is_some()
}

/// The `receipt.result` of a `gettransactioninfobyid` reply.
fn receipt_result(info: &Value) -> Option<&str> {
    info.get("receipt")
        .and_then(|r| r.get("result"))
        .and_then(Value::as_str)
}

/// `TronGrid` `/wallet/gettransactioninfobyid` to a normalized status.
pub(crate) async fn tx_status(engine: &WalletEngine, hash: &str) -> Result<TxStatusInfo, String> {
    let info = tron_post(
        engine,
        "wallet/gettransactioninfobyid",
        json!({ "value": hash }),
    )
    .await?;
    let (state, block_number) = if let Some(bn) = info.get("blockNumber").and_then(Value::as_u64) {
        // `receipt.result` carries SUCCESS / REVERT / FAILED for contract txs;
        // a bare TRX transfer omits it but is successful once mined.
        let state = match receipt_result(&info) {
            Some("SUCCESS") | None => TxState::Confirmed,
            Some(_) => TxState::Failed,
        };
        (state, Some(bn))
    } else {
        // The info endpoint only has a row once the tx is mined. A freshly
        // broadcast tx is still pending: disambiguate via gettransactionbyid.
        let tx = tron_post(
            engine,
            "wallet/gettransactionbyid",
            json!({ "value": hash }),
        )
        .await?;
        let state = if is_known_tx(&tx) {
            TxState::Pending
        } else {
            TxState::NotFound
        };
        (state, None)
    };
    Ok(TxStatusInfo {
        chain: WalletChain::Tron,
        evm_network: None,
        hash: hash.to_string(),
        state,
        confirmations: None,
        block_number,
    })
}

/// `TronGrid` `/wallet/gettransactioninfobyid` to a normalized receipt.
pub(crate) async fn tx_receipt(engine: &WalletEngine, hash: &str) -> Result<TxReceiptInfo, String> {
    let info = tron_post(
        engine,
        "wallet/gettransactioninfobyid",
        json!({ "value": hash }),
    )
    .await?;
    let Some(block_number) = info.get("blockNumber").and_then(Value::as_u64) else {
        return Ok(TxReceiptInfo {
            chain: WalletChain::Tron,
            evm_network: None,
            hash: hash.to_string(),
            found: false,
            success: None,
            block_number: None,
            gas_used: None,
            fee_raw: None,
            raw: Value::Null,
        });
    };
    let success = Some(matches!(receipt_result(&info), Some("SUCCESS") | None));
    let fee_raw = info
        .get("fee")
        .and_then(Value::as_u64)
        .map(|f| f.to_string());
    let gas_used = info
        .get("receipt")
        .and_then(|r| r.get("energy_usage_total"))
        .and_then(Value::as_u64)
        .map(|g| g.to_string());
    Ok(TxReceiptInfo {
        chain: WalletChain::Tron,
        evm_network: None,
        hash: hash.to_string(),
        found: true,
        success,
        block_number: Some(block_number),
        gas_used,
        fee_raw,
        raw: info,
    })
}

/// `TronGrid` `/wallet/gettransactionbyid` as a raw transaction passthrough.
pub(crate) async fn lookup_tx(engine: &WalletEngine, hash: &str) -> Result<TxLookupInfo, String> {
    let tx = tron_post(
        engine,
        "wallet/gettransactionbyid",
        json!({ "value": hash }),
    )
    .await?;
    Ok(TxLookupInfo {
        chain: WalletChain::Tron,
        evm_network: None,
        hash: hash.to_string(),
        found: is_known_tx(&tx),
        raw: tx,
    })
}

#[cfg(test)]
mod test;
