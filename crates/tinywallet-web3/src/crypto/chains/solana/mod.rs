//! Solana native SOL and SPL token transfers.
//!
//! The wire format is hand-built in [`wire`] so the crate does not pull in
//! `solana-sdk`. Key derivation is SLIP-0010 ed25519 (`m/44'/501'/0'/0'`); a
//! Solana address is a 32-byte ed25519 public key, base58-encoded. Neither
//! happens here: the [`WalletSigner`](crate::crypto::seams::WalletSigner)
//! derives the account and signs the message, and this module only assembles
//! the bytes.
//!
//! - [`wire`] — shortvec, message encoding, program-derived addresses.
//! - `versioned` — signing an externally-built versioned transaction.
//! - `queries` — status, receipt and lookup by signature.

mod queries;
mod versioned;
mod wire;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use log::debug;
use serde::Deserialize;
use serde_json::json;
use tinywallet_bus::wire::{Scheme, Signature};

use crate::crypto::execution::{
    ExecutionResult, PreparedKind, PreparedStatus, PreparedTransaction,
};
use crate::crypto::wallet::{WalletChain, WalletEngine};

pub(crate) use queries::{lookup_tx, tx_receipt, tx_status};
pub(crate) use versioned::sign_and_broadcast_versioned;
use wire::{
    associated_token_account, b58_to_pubkey, build_native_transfer_message,
    build_spl_transfer_message, encode_shortvec, pubkey_to_b58,
};

const LOG_PREFIX: &str = "[wallet::sol]";

#[derive(Debug, Deserialize)]
struct BalanceResult {
    value: u64,
}

#[derive(Debug, Deserialize)]
struct AccountInfoResponse {
    value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct BlockhashResponse {
    value: BlockhashValue,
}

#[derive(Debug, Deserialize)]
struct BlockhashValue {
    blockhash: String,
}

/// Validate a Solana address (a base58 ed25519 public key).
pub(crate) fn validate_solana_address(addr: &str) -> Result<String, String> {
    let result = tinywallet_crypto::address::solana::validate(addr).map_err(|e| e.to_string());
    debug!(
        "{LOG_PREFIX} validate_address result={}",
        if result.is_ok() {
            "accepted"
        } else {
            "rejected"
        }
    );
    result
}

/// Native balance of `address`, in lamports.
pub(crate) async fn native_balance(engine: &WalletEngine, address: &str) -> Result<u128, String> {
    validate_solana_address(address)?;
    let result: BalanceResult = engine
        .rpc_call(WalletChain::Solana, "getBalance", json!([address]))
        .await?;
    Ok(u128::from(result.value))
}

/// The wallet's Solana public key, as the signer derives it.
async fn signer_pubkey(engine: &WalletEngine) -> Result<[u8; 32], String> {
    let account = engine.signer.derive_account(WalletChain::Solana).await?;
    b58_to_pubkey(&account.address)
}

/// Decode lowercase hex.
fn hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("odd-length hex from the wallet module".to_string());
    }
    (0..value.len() / 2)
        .map(|i| {
            value
                .get(i * 2..i * 2 + 2)
                .ok_or_else(|| "invalid hex from the wallet module: not ascii".to_string())
                .and_then(|pair| {
                    u8::from_str_radix(pair, 16)
                        .map_err(|e| format!("invalid hex from the wallet module: {e}"))
                })
        })
        .collect()
}

/// Sign `message` with the wallet key, through the signer.
async fn solana_sign(engine: &WalletEngine, message: &[u8]) -> Result<[u8; 64], String> {
    let signature = engine
        .signer
        .sign_message(WalletChain::Solana, message, Scheme::Ed25519)
        .await?;
    let Signature::Ed25519 { signature_hex } = signature else {
        return Err("the wallet module returned a non-ed25519 Solana signature".to_string());
    };
    let bytes = hex_to_bytes(&signature_hex)?;
    <[u8; 64]>::try_from(bytes.as_slice())
        .map_err(|_| "the wallet module returned a malformed Solana signature".to_string())
}

/// Best-effort `getAccountInfo` check: `Ok(true)` when the account exists,
/// `Ok(false)` when the RPC reports `value: null`, or the transport error.
async fn account_exists(engine: &WalletEngine, address_b58: &str) -> Result<bool, String> {
    let resp: AccountInfoResponse = engine
        .rpc_call(
            WalletChain::Solana,
            "getAccountInfo",
            json!([address_b58, {"encoding": "base64"}]),
        )
        .await?;
    Ok(!resp.value.is_null())
}

async fn fetch_recent_blockhash(engine: &WalletEngine) -> Result<[u8; 32], String> {
    let result: BlockhashResponse = engine
        .rpc_call(
            WalletChain::Solana,
            "getLatestBlockhash",
            json!([{"commitment": "finalized"}]),
        )
        .await?;
    b58_to_pubkey(&result.value.blockhash)
}

/// `sendTransaction` a signed wire transaction.
async fn broadcast_solana(engine: &WalletEngine, signed: &[u8]) -> Result<String, String> {
    let b64 = B64.encode(signed);
    engine
        .rpc_call(
            WalletChain::Solana,
            "sendTransaction",
            json!([b64, {"encoding": "base64", "preflightCommitment": "processed"}]),
        )
        .await
}

/// The message bytes for a quote: a native transfer, or an SPL transfer after
/// checking the destination Associated Token Account exists.
async fn transfer_message(
    engine: &WalletEngine,
    quote: &PreparedTransaction,
    from_pk: [u8; 32],
    to_pubkey: [u8; 32],
    amount: u64,
) -> Result<Vec<u8>, String> {
    let recent_blockhash = fetch_recent_blockhash(engine).await?;
    match quote.kind {
        PreparedKind::NativeTransfer => Ok(build_native_transfer_message(
            from_pk,
            to_pubkey,
            amount,
            recent_blockhash,
        )),
        PreparedKind::TokenTransfer => {
            let mint_addr = quote
                .token_address
                .as_deref()
                .ok_or_else(|| "SPL transfer missing token_address (mint)".to_string())?;
            let mint = b58_to_pubkey(mint_addr)?;
            let src_ata = associated_token_account(&from_pk, &mint)?;
            let dst_ata = associated_token_account(&to_pubkey, &mint)?;
            // Preflight: refuse to send to a non-existent ATA so we don't burn
            // the broadcast on a guaranteed on-chain failure. Creating the ATA
            // in the same transaction is left to a future change; for now fail
            // loudly with a clear message.
            if !account_exists(engine, &pubkey_to_b58(&dst_ata)).await? {
                return Err(format!(
                    "SPL preflight: destination Associated Token Account does not exist for mint {} owner {}; create it before transferring",
                    mint_addr,
                    pubkey_to_b58(&to_pubkey)
                ));
            }
            build_spl_transfer_message(from_pk, src_ata, dst_ata, amount, recent_blockhash)
        }
    }
}

/// Sign and broadcast a prepared Solana transfer.
pub(crate) async fn execute_solana_quote(
    engine: &WalletEngine,
    mut quote: PreparedTransaction,
) -> Result<ExecutionResult, String> {
    let from_addr = quote.from_address.clone();
    let to_addr = quote.to_address.clone();
    validate_solana_address(&from_addr)?;
    validate_solana_address(&to_addr)?;
    let amount: u64 = quote
        .amount_raw
        .parse()
        .map_err(|e| format!("invalid Solana amount '{}': {e}", quote.amount_raw))?;

    let from_pk = signer_pubkey(engine).await?;
    let expected_from = b58_to_pubkey(&from_addr)?;
    if from_pk != expected_from {
        return Err(format!(
            "Solana key derivation mismatch: derived {} but expected {}",
            pubkey_to_b58(&from_pk),
            from_addr
        ));
    }

    let to_pubkey = b58_to_pubkey(&to_addr)?;
    let message_bytes = transfer_message(engine, &quote, from_pk, to_pubkey, amount).await?;

    let sig_bytes = solana_sign(engine, &message_bytes).await?;
    let mut wire = Vec::with_capacity(1 + 64 + message_bytes.len());
    wire.extend(encode_shortvec(1));
    wire.extend(sig_bytes);
    wire.extend(&message_bytes);

    let tx_sig = broadcast_solana(engine, &wire).await?;
    quote.status = PreparedStatus::Broadcasted;
    debug!(
        "{LOG_PREFIX} broadcast quote_id={} sig={tx_sig} kind={:?}",
        quote.quote_id, quote.kind
    );
    let explorer_url = engine.explorer_url(WalletChain::Solana, &tx_sig);
    Ok(ExecutionResult {
        quote_id: quote.quote_id.clone(),
        status: PreparedStatus::Broadcasted,
        chain: WalletChain::Solana,
        evm_network: None,
        transaction_hash: tx_sig,
        explorer_url,
        transaction: quote,
    })
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
