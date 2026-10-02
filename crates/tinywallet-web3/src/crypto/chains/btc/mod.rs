//! Bitcoin P2WPKH transfers over the Esplora REST API.
//!
//! UTXO discovery and broadcast go through the
//! [`Transport`](tinywallet_crypto::rpc::Transport); the transaction itself is
//! built and signed by the [`WalletSigner`](crate::crypto::seams::WalletSigner),
//! which is handed the already-selected UTXOs so the two sides agree on what is
//! spent. Addresses are BIP84 (`m/84'/0'/0'/0/0`), so any wallet seeded with a
//! standard recovery phrase produces a `bc1q…` native segwit address.

use log::debug;
use serde::Deserialize;
use serde_json::Value;
use tinywallet_bus::wire::{TransactionSpec, Utxo};

use crate::crypto::execution::{
    ExecutionResult, PreparedKind, PreparedStatus, PreparedTransaction, TxLookupInfo,
    TxReceiptInfo, TxState, TxStatusInfo,
};
use crate::crypto::wallet::{WalletChain, WalletEngine};

const LOG_PREFIX: &str = "[wallet::btc]";
/// Hardcoded fee rate (sat/vbyte) used to size the fee of an executed transfer.
/// Conservative: mempools cap out around 50 sat/vB during congestion; 20 keeps
/// us in range without burning sats in quiet times.
const DEFAULT_FEE_RATE_SAT_VB: u64 = 20;
/// Fixed vbytes of a segwit transaction: version, locktime, counts and the
/// witness marker, 10.5 vB, rounded up.
const TX_OVERHEAD_VBYTES: u64 = 11;
/// vbytes one P2WPKH input adds (outpoint, sequence and the discounted witness).
const P2WPKH_INPUT_VBYTES: u64 = 68;
/// vbytes one P2WPKH output adds.
const P2WPKH_OUTPUT_VBYTES: u64 = 31;
/// A change output at or below this many satoshis is dropped and folded into
/// the fee. It is the signer's own threshold (its change is emitted only when
/// the surplus is strictly above it), so the two sides agree on whether the
/// transaction has a change output.
const DUST_THRESHOLD_SATS: u64 = 546;

/// One spendable output as Esplora reports it.
#[derive(Debug, Deserialize, Clone)]
pub(crate) struct EsploraUtxo {
    pub(crate) txid: String,
    pub(crate) vout: u32,
    pub(crate) value: u64,
}

#[derive(Debug, Deserialize)]
struct EsploraAddressInfo {
    chain_stats: EsploraAddressStats,
    mempool_stats: EsploraAddressStats,
}

#[derive(Debug, Deserialize)]
struct EsploraAddressStats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

/// The vbytes of a P2WPKH transaction with `inputs` inputs and `outputs`
/// outputs.
pub(crate) const fn estimated_vbytes(inputs: u64, outputs: u64) -> u64 {
    TX_OVERHEAD_VBYTES + inputs * P2WPKH_INPUT_VBYTES + outputs * P2WPKH_OUTPUT_VBYTES
}

fn accepted(result: &Result<String, String>) -> &'static str {
    if result.is_ok() {
        "accepted"
    } else {
        "rejected"
    }
}

/// Generic BTC address validation: any well-formed mainnet address is fine.
/// Used for recipients, who may prefer any address type.
pub(crate) fn validate_btc_address(addr: &str) -> Result<String, String> {
    let result = tinywallet_crypto::address::btc::validate(addr).map_err(|e| e.to_string());
    debug!(
        "{LOG_PREFIX} validate_address role=recipient result={}",
        accepted(&result)
    );
    result
}

/// Sender-side validation: must be P2WPKH, because the signer only knows how to
/// derive and sign for native segwit (`bc1q…`). Using the recipient rule for a
/// sender would accept an address that only fails later, at signing time.
pub(crate) fn validate_btc_sender_address(addr: &str) -> Result<String, String> {
    let result = tinywallet_crypto::address::btc::validate_sender(addr).map_err(|e| e.to_string());
    debug!(
        "{LOG_PREFIX} validate_address role=sender result={}",
        accepted(&result)
    );
    result
}

/// Confirmed plus mempool balance of `address`, in satoshis.
pub(crate) async fn native_balance(engine: &WalletEngine, address: &str) -> Result<u128, String> {
    validate_btc_address(address)?;
    let info: EsploraAddressInfo = engine
        .rest_get_json(WalletChain::Btc, &format!("address/{address}"))
        .await?;
    let confirmed = info
        .chain_stats
        .funded_txo_sum
        .saturating_sub(info.chain_stats.spent_txo_sum);
    let pending = info
        .mempool_stats
        .funded_txo_sum
        .saturating_sub(info.mempool_stats.spent_txo_sum);
    Ok(u128::from(confirmed) + u128::from(pending))
}

async fn fetch_utxos(engine: &WalletEngine, address: &str) -> Result<Vec<EsploraUtxo>, String> {
    engine
        .rest_get_json(WalletChain::Btc, &format!("address/{address}/utxo"))
        .await
}

async fn broadcast_raw_hex(engine: &WalletEngine, tx_hex: &str) -> Result<String, String> {
    engine
        .rest_post_text(WalletChain::Btc, "tx", tx_hex, "text/plain")
        .await
}

/// The coins chosen for a transfer, the fee they pay, and the change they leave.
#[derive(Debug, Clone)]
pub(crate) struct SpendPlan {
    /// The UTXOs to spend, largest first.
    pub(crate) selected: Vec<EsploraUtxo>,
    /// The fee, in satoshis. When the change would be dust this is everything
    /// the inputs hold beyond the amount, so the two sides agree on it.
    pub(crate) fee_sats: u64,
    /// The change returned to the sender, in satoshis; zero when there is no
    /// change output.
    pub(crate) change_sats: u64,
}

/// Price a transaction of `inputs` inputs and `outputs` outputs at
/// `fee_rate_sat_vb`.
fn fee_for(fee_rate_sat_vb: u64, inputs: u64, outputs: u64) -> Result<u64, String> {
    fee_rate_sat_vb
        .checked_mul(estimated_vbytes(inputs, outputs))
        .ok_or_else(|| "amount + fee overflow".to_string())
}

/// Select UTXOs, largest first, to cover `amount_sats` plus a fee sized for the
/// transaction those inputs make.
///
/// Every input adds weight and so fee, which the next input may or may not
/// cover; the selection therefore grows one input at a time and re-prices the
/// transaction after each. A change output is planned for first (two outputs);
/// if what is left over would be dust, it is dropped (one output) and the whole
/// surplus goes to the fee.
pub(crate) fn plan_spend(
    utxos: &[EsploraUtxo],
    amount_sats: u64,
    fee_rate_sat_vb: u64,
) -> Result<SpendPlan, String> {
    let mut sorted = utxos.to_vec();
    sorted.sort_by_key(|item| std::cmp::Reverse(item.value));
    // The cheapest a spend can be: no inputs beyond the first, no change. It
    // fails the whole call when even that overflows.
    fee_for(fee_rate_sat_vb, 1, 1)?
        .checked_add(amount_sats)
        .ok_or_else(|| "amount + fee overflow".to_string())?;
    let mut total: u64 = 0;
    let mut chosen = Vec::new();
    for utxo in sorted {
        total = total
            .checked_add(utxo.value)
            .ok_or_else(|| "utxo sum overflow".to_string())?;
        chosen.push(utxo);
        let inputs = chosen.len() as u64;
        let fee_with_change = fee_for(fee_rate_sat_vb, inputs, 2)?;
        let fee_without_change = fee_for(fee_rate_sat_vb, inputs, 1)?;
        let with_change = amount_sats.saturating_add(fee_with_change);
        if total >= with_change && total - with_change > DUST_THRESHOLD_SATS {
            return Ok(SpendPlan {
                selected: chosen,
                fee_sats: fee_with_change,
                change_sats: total - with_change,
            });
        }
        if total >= amount_sats.saturating_add(fee_without_change) {
            return Ok(SpendPlan {
                selected: chosen,
                fee_sats: total - amount_sats,
                change_sats: 0,
            });
        }
    }
    let inputs = chosen.len() as u64;
    let fee_sats = fee_for(fee_rate_sat_vb, inputs, 1)?;
    let target = amount_sats.saturating_add(fee_sats);
    Err(format!(
        "insufficient BTC: have {total} sats, need {target} (amount {amount_sats} + fee {fee_sats})"
    ))
}

/// Sign and broadcast a prepared Bitcoin transfer.
pub(crate) async fn execute_btc_quote(
    engine: &WalletEngine,
    mut quote: PreparedTransaction,
) -> Result<ExecutionResult, String> {
    if !matches!(quote.kind, PreparedKind::NativeTransfer) {
        return Err(format!(
            "BTC only supports native transfers; got kind {:?}",
            quote.kind
        ));
    }
    let amount_sats: u64 = quote
        .amount_raw
        .parse()
        .map_err(|e| format!("invalid BTC amount '{}': {e}", quote.amount_raw))?;
    let from_addr = quote.from_address.clone();
    let to_addr = quote.to_address.clone();
    validate_btc_sender_address(&from_addr)?;
    validate_btc_address(&to_addr)?;

    let utxos = fetch_utxos(engine, &from_addr).await?;
    if utxos.is_empty() {
        return Err(format!("no spendable UTXOs for {from_addr}"));
    }
    let SpendPlan {
        selected,
        fee_sats,
        change_sats,
    } = plan_spend(&utxos, amount_sats, DEFAULT_FEE_RATE_SAT_VB)?;

    // Selection stays here (this crate knows the fee policy and the UTXO
    // source), but the transaction itself is encoded by the signer, which also
    // re-runs the same largest-first selection over the UTXOs it is handed.
    // Passing only the already-selected set keeps the two in agreement.
    let transaction = TransactionSpec::Btc {
        from: from_addr.clone(),
        to: to_addr.clone(),
        amount_sat: amount_sats,
        fee_sat: fee_sats,
        utxos: selected
            .iter()
            .map(|utxo| Utxo {
                txid: utxo.txid.clone(),
                vout: utxo.vout,
                value: utxo.value,
            })
            .collect(),
    };
    // One signature per selected input, all produced inside the signer and
    // applied there in input order.
    let signed = engine
        .signer
        .sign_transaction(WalletChain::Btc, &transaction)
        .await?;

    let txid_hex = broadcast_raw_hex(engine, &signed.raw).await?;
    quote.estimated_fee_raw = fee_sats.to_string();
    quote.status = PreparedStatus::Broadcasted;
    debug!(
        "{LOG_PREFIX} broadcast quote_id={} txid={} amount_sats={} change_sats={}",
        quote.quote_id, txid_hex, amount_sats, change_sats
    );
    let explorer_url = engine.explorer_url(WalletChain::Btc, &txid_hex);
    Ok(ExecutionResult {
        quote_id: quote.quote_id.clone(),
        status: PreparedStatus::Broadcasted,
        chain: WalletChain::Btc,
        evm_network: None,
        transaction_hash: txid_hex,
        explorer_url,
        transaction: quote,
    })
}

/// Esplora answers 404 for an unknown txid; the transport surfaces it as
/// `status=404` in the message.
fn is_not_found(error: &str) -> bool {
    error.contains("status=404")
}

fn status_row(
    hash: &str,
    state: TxState,
    confirmations: Option<u64>,
    block: Option<u64>,
) -> TxStatusInfo {
    TxStatusInfo {
        chain: WalletChain::Btc,
        evm_network: None,
        hash: hash.to_string(),
        state,
        confirmations,
        block_number: block,
    }
}

/// Esplora `/tx/:txid/status` to a normalized status. Confirmations come from
/// the chain tip (`/blocks/tip/height`) once the transaction is confirmed.
pub(crate) async fn tx_status(engine: &WalletEngine, hash: &str) -> Result<TxStatusInfo, String> {
    let status: Value = match engine
        .rest_get_json(WalletChain::Btc, &format!("tx/{hash}/status"))
        .await
    {
        Ok(v) => v,
        // Esplora returns 404 for unknown txids; surface as NotFound.
        Err(e) if is_not_found(&e) => return Ok(status_row(hash, TxState::NotFound, None, None)),
        Err(e) => return Err(e),
    };
    let confirmed = status
        .get("confirmed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !confirmed {
        return Ok(status_row(hash, TxState::Pending, Some(0), None));
    }
    let block_number = status.get("block_height").and_then(Value::as_u64);
    let confirmations = match block_number {
        Some(bn) => {
            let tip = engine
                .rest_get_text(WalletChain::Btc, "blocks/tip/height")
                .await
                .ok();
            tip.and_then(|t| t.trim().parse::<u64>().ok())
                .map(|tip| tip.saturating_sub(bn).saturating_add(1))
        }
        None => None,
    };
    Ok(status_row(
        hash,
        TxState::Confirmed,
        confirmations,
        block_number,
    ))
}

/// Esplora `/tx/:txid` to a normalized receipt (fee and confirmed height).
pub(crate) async fn tx_receipt(engine: &WalletEngine, hash: &str) -> Result<TxReceiptInfo, String> {
    let tx: Value = match engine
        .rest_get_json(WalletChain::Btc, &format!("tx/{hash}"))
        .await
    {
        Ok(v) => v,
        Err(e) if is_not_found(&e) => {
            return Ok(TxReceiptInfo {
                chain: WalletChain::Btc,
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
        Err(e) => return Err(e),
    };
    let confirmed = tx
        .get("status")
        .and_then(|s| s.get("confirmed"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let block_number = tx
        .get("status")
        .and_then(|s| s.get("block_height"))
        .and_then(Value::as_u64);
    let fee_raw = tx.get("fee").and_then(Value::as_u64).map(|f| f.to_string());
    // Leave `success` unset until the tx is confirmed: an unconfirmed mempool
    // tx is pending (see `tx_status`), not a failure.
    let success = confirmed.then_some(true);
    Ok(TxReceiptInfo {
        chain: WalletChain::Btc,
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

/// Esplora `/tx/:txid` as a raw transaction passthrough.
pub(crate) async fn lookup_tx(engine: &WalletEngine, hash: &str) -> Result<TxLookupInfo, String> {
    match engine
        .rest_get_json::<Value>(WalletChain::Btc, &format!("tx/{hash}"))
        .await
    {
        Ok(tx) => Ok(TxLookupInfo {
            chain: WalletChain::Btc,
            evm_network: None,
            hash: hash.to_string(),
            found: true,
            raw: tx,
        }),
        Err(e) if is_not_found(&e) => Ok(TxLookupInfo {
            chain: WalletChain::Btc,
            evm_network: None,
            hash: hash.to_string(),
            found: false,
            raw: Value::Null,
        }),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
