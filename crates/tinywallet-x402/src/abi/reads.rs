//! The two read-only calls the x402 `upto` flow makes before it signs: the
//! payer's ERC-20 `allowance` to Permit2, and the token's EIP-2612 `nonces`.
//!
//! Both take only static arguments, so each is a selector followed by
//! left-padded address words, and each answers one `uint256` word.

use super::{Error, Result, decode_evm_address, left_pad_address, push_hex};
use crate::eip712::U256Bytes;

/// `keccak256("allowance(address,address)")[..4]`.
pub(super) const ALLOWANCE_SELECTOR: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];

/// `keccak256("nonces(address)")[..4]`.
pub(super) const NONCES_SELECTOR: [u8; 4] = [0x7e, 0xce, 0xbe, 0x00];

/// ABI-encode an ERC-20 `allowance(owner, spender)` call, as `0x` hex.
///
/// # Errors
///
/// [`Error::InvalidRecipient`] when either address is not a valid EVM address.
pub fn encode_erc20_allowance(owner: &str, spender: &str) -> Result<String> {
    encode_call(ALLOWANCE_SELECTOR, &[owner, spender])
}

/// ABI-encode an EIP-2612 `nonces(owner)` call, as `0x` hex.
///
/// # Errors
///
/// [`Error::InvalidRecipient`] when `owner` is not a valid EVM address.
pub fn encode_eip2612_nonces(owner: &str) -> Result<String> {
    encode_call(NONCES_SELECTOR, &[owner])
}

/// Decode an `eth_call` reply that is exactly one `uint256` word.
///
/// # Errors
///
/// [`Error::InvalidReply`] when the reply is not `0x` plus 64 hex digits.
pub fn decode_uint256(reply: &str) -> Result<U256Bytes> {
    let invalid = |reason: &str| Error::InvalidReply {
        reason: reason.to_string(),
    };
    let body = reply
        .strip_prefix("0x")
        .ok_or_else(|| invalid("missing 0x prefix"))?;
    if body.len() != 64 {
        return Err(invalid("expected one 32-byte word"));
    }
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = body
            .get(index * 2..index * 2 + 2)
            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
            .ok_or_else(|| invalid("not hex"))?;
    }
    Ok(out)
}

fn encode_call(selector: [u8; 4], addresses: &[&str]) -> Result<String> {
    let mut out = String::with_capacity(2 + 8 + 64 * addresses.len());
    out.push_str("0x");
    for byte in selector {
        push_hex(&mut out, byte);
    }
    for address in addresses {
        let validated = tinywallet_crypto::address::evm::validate(address).map_err(|e| {
            Error::InvalidRecipient {
                reason: e.to_string(),
            }
        })?;
        for byte in left_pad_address(decode_evm_address(&validated)?) {
            push_hex(&mut out, byte);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[path = "reads_tests.rs"]
mod tests;
