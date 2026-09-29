//! Signing an externally-built, hex-encoded `VersionedTransaction` (for
//! example a deBridge swap or bridge transaction).
//!
//! Wire layout of a Solana transaction: `shortvec(num_signatures)`, then
//! `num_signatures * 64` signature slots, then the serialized message. The
//! signature slot whose account key equals the wallet's pubkey is filled by
//! signing the full message bytes (legacy or v0: the slice includes the v0
//! version prefix, which is what Solana signs).

use log::debug;

use crate::crypto::defaults::explorer_tx_url;
use crate::crypto::execution::RawBroadcastResult;
use crate::crypto::wallet::{WalletChain, WalletEngine};

use super::wire::{decode_shortvec, pubkey_to_b58};
use super::{LOG_PREFIX, broadcast_solana, signer_pubkey, solana_sign};

/// Where the signer keys and message sit inside a transaction blob.
struct Layout {
    /// Offset of the first signature slot.
    sigs_start: usize,
    /// Number of signature slots.
    num_signatures: usize,
    /// Offset of the message.
    message_start: usize,
    /// Offset of the first account key within the message.
    keys_start: usize,
    /// How many leading account keys are signers and present in the blob.
    signer_keys: usize,
}

/// Parse just enough of `wire` to find the signer keys.
fn parse_layout(wire: &[u8]) -> Result<Layout, String> {
    let (num_signatures, sig_count_len) = decode_shortvec(wire)?;
    let sigs_start = sig_count_len;
    let num_signatures = usize::from(num_signatures);
    let message_start = sigs_start + num_signatures * 64;
    if message_start > wire.len() {
        return Err("Solana tx blob truncated before message".to_string());
    }
    let message = &wire[message_start..];
    let Some(first) = message.first() else {
        return Err("Solana tx blob has empty message".to_string());
    };

    // Determine message version and header offset.
    let versioned = first & 0x80 != 0;
    let header_off = usize::from(versioned);
    if message.len() < header_off + 3 {
        return Err("Solana message header truncated".to_string());
    }
    let num_required_signatures = usize::from(message[header_off]);
    if num_required_signatures == 0 {
        return Err("Solana message declares zero required signatures".to_string());
    }
    // Parse account keys (need at least the signer keys to find our index).
    let keys_off = header_off + 3;
    let (account_count, count_len) = decode_shortvec(&message[keys_off..])?;
    let keys_start = keys_off + count_len;
    let signer_keys = num_required_signatures.min(usize::from(account_count));
    if keys_start + signer_keys * 32 > message.len() {
        return Err("Solana account keys region truncated".to_string());
    }
    Ok(Layout {
        sigs_start,
        num_signatures,
        message_start,
        keys_start,
        signer_keys,
    })
}

/// Sign an externally-built hex `VersionedTransaction` with the wallet's
/// Solana key and broadcast it.
pub(crate) async fn sign_and_broadcast_versioned(
    engine: &WalletEngine,
    tx_blob_hex: &str,
) -> Result<RawBroadcastResult, String> {
    let trimmed = tx_blob_hex.trim();
    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    let mut wire =
        hex::decode(normalized).map_err(|e| format!("invalid Solana transaction hex blob: {e}"))?;
    let layout = parse_layout(&wire)?;

    let our_pubkey = signer_pubkey(engine).await?;
    let message = &wire[layout.message_start..];
    let our_index = (0..layout.signer_keys)
        .find(|i| {
            let off = layout.keys_start + i * 32;
            message[off..off + 32] == our_pubkey
        })
        .ok_or_else(|| {
            format!(
                "wallet Solana address {} is not a required signer of this transaction",
                pubkey_to_b58(&our_pubkey)
            )
        })?;
    if our_index >= layout.num_signatures {
        return Err("Solana signer index exceeds signature slot count".to_string());
    }

    // Sign the message bytes and write into our signature slot.
    let sig_bytes = solana_sign(engine, message).await?;
    let slot_off = layout.sigs_start + our_index * 64;
    wire[slot_off..slot_off + 64].copy_from_slice(&sig_bytes);

    let tx_sig = broadcast_solana(engine, &wire).await?;
    debug!("{LOG_PREFIX} sign_and_broadcast_versioned sig={tx_sig}");
    Ok(RawBroadcastResult {
        transaction_hash: tx_sig.clone(),
        explorer_url: explorer_tx_url(WalletChain::Solana, &tx_sig),
        // Solana fees are dynamic (base plus priority) and only known once the
        // tx is confirmed: leave unset rather than misreporting a free
        // transfer.
        fee_raw: None,
    })
}
