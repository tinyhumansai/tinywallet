//! Address, amount and calldata validation, amount formatting, hex
//! conversions and the estimated-fee table used when preparing a quote.

use log::debug;

use crate::crypto::wallet::WalletChain;

use super::types::PreparedKind;

const LOG_PREFIX: &str = "[wallet]";

/// Parse a base-10 amount in the smallest unit.
pub(crate) fn validate_amount(raw: &str) -> Result<u128, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("amount is empty".to_string());
    }
    trimmed
        .parse::<u128>()
        .map_err(|_| format!("amount '{trimmed}' is not a valid non-negative integer"))
}

/// Validate `addr` for `chain`, returning it trimmed.
///
/// Every arm delegates to `tinywallet-crypto`, which owns the four address
/// formats. For Bitcoin this is the **recipient** rule (any well-formed mainnet
/// address); sender addresses go through
/// [`chains::btc::validate_sender_address`](crate::crypto::chains), which also
/// requires P2WPKH.
pub(crate) fn validate_address(chain: WalletChain, addr: &str) -> Result<String, String> {
    debug!("{LOG_PREFIX} validate_address chain={chain:?} role=recipient");
    let result = tinywallet_crypto::address::validate(chain.to_chain(), addr)
        .map_err(|error| error.to_string());
    debug!(
        "{LOG_PREFIX} validate_address chain={chain:?} role=recipient result={}",
        if result.is_ok() {
            "accepted"
        } else {
            "rejected"
        }
    );
    result
}

/// Validate `0x`-prefixed, byte-aligned hex calldata.
pub(crate) fn validate_calldata(data: &str) -> Result<String, String> {
    let trimmed = data.trim();
    let Some(body) = trimmed.strip_prefix("0x") else {
        return Err("calldata must be 0x-prefixed hex".to_string());
    };
    if body.len() % 2 != 0 {
        return Err("calldata hex must be byte-aligned".to_string());
    }
    if !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("calldata contains non-hex characters".to_string());
    }
    Ok(trimmed.to_string())
}

/// Render a smallest-unit amount with its decimal point.
pub(crate) fn format_amount(raw: u128, decimals: u8) -> String {
    if decimals == 0 {
        return raw.to_string();
    }
    let digits = raw.to_string();
    let width = usize::from(decimals);
    if digits.len() <= width {
        format!("0.{digits:0>width$}")
    } else {
        let split = digits.len() - width;
        format!("{}.{}", &digits[..split], &digits[split..])
    }
}

/// The flat fee estimate stamped on a prepared quote.
pub(crate) fn estimated_fee_raw(chain: WalletChain, kind: PreparedKind) -> String {
    let base = match (chain, kind) {
        (WalletChain::Evm, PreparedKind::NativeTransfer) => 21_000u128 * 30_000_000_000,
        (WalletChain::Evm, PreparedKind::TokenTransfer) => 65_000u128 * 30_000_000_000,
        (WalletChain::Btc | WalletChain::Solana, _) => 5_000,
        (WalletChain::Tron, PreparedKind::NativeTransfer) => 1_000_000,
        (WalletChain::Tron, PreparedKind::TokenTransfer) => 15_000_000,
    };
    base.to_string()
}

/// Parse an `0x`-prefixed hex quantity, as every EVM JSON-RPC result encodes
/// integers.
///
/// `u128` rather than a 256-bit type. Nothing this wallet reads from a node (a
/// nonce, a gas price, a gas limit, a wei balance) approaches 2^128, which is
/// about 3.4e20 ETH. A value that genuinely did overflow is reported rather
/// than truncated.
///
/// # Errors
///
/// A message naming the offending value if it is not hex, or does not fit.
pub fn hex_to_u128(hex_value: &str) -> Result<u128, String> {
    let trimmed = hex_value.trim();
    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    u128::from_str_radix(normalized, 16)
        .map_err(|e| format!("invalid hex quantity '{hex_value}': {e}"))
}

/// Render an integer the way an EVM JSON-RPC parameter expects it.
#[must_use]
pub fn u128_to_hex(value: u128) -> String {
    format!("0x{value:x}")
}

/// Decode hex bytes, with or without an `0x` prefix.
///
/// # Errors
///
/// A message naming the offending value if it is not valid hex.
pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>, String> {
    let trimmed = value.trim();
    let normalized = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    hex::decode(normalized).map_err(|e| format!("invalid hex bytes '{value}': {e}"))
}

#[cfg(test)]
mod test;
