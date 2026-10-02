//! The sliver of Ethereum ABI encoding a wallet actually needs.
//!
//! Exactly one call is encoded here — ERC-20 `transfer(address,uint256)` — and
//! that is deliberate. A general ABI encoder is a parser for a type grammar; a
//! token transfer is a four-byte selector followed by two 32-byte words. Taking
//! a full Ethereum library for the second is how a wallet ends up carrying the
//! first, along with a bignum type and a signer stack.
//!
//! This lives outside the `tx` gate on purpose. Calldata is an *input* to
//! building a transaction, so a host that has moved building into a loadable
//! module still needs to produce it — and would otherwise have to pay a bus
//! round trip for keccak over 68 bytes, or link the chain library it just spent
//! the effort removing.

use crate::eip712::u256_from_decimal;

/// `keccak256("transfer(address,uint256)")[..4]`.
///
/// Pinned, and re-derived from the signature in the tests below. Every ERC-20
/// transfer on every EVM chain starts with these four bytes; getting them wrong
/// produces a call that either reverts or, on a contract with a colliding
/// selector, does something else entirely.
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// The signature the selector is taken from, kept beside it for the test.
#[cfg(test)]
const TRANSFER_SIGNATURE: &[u8] = b"transfer(address,uint256)";

/// Why calldata could not be encoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The recipient is not a valid EVM address.
    #[error("invalid recipient: {reason}")]
    InvalidRecipient {
        /// What was wrong with it.
        reason: String,
    },

    /// The amount is not a base-10 integer, or overflows 256 bits.
    #[error("invalid amount: {reason}")]
    InvalidAmount {
        /// What was wrong with it.
        reason: String,
    },
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, Error>;

/// ABI-encode an ERC-20 `transfer(address,uint256)` call.
///
/// `amount` is a base-10 string rather than an integer because token amounts
/// are denominated in the token's own smallest unit: an 18-decimal token puts
/// ordinary balances past `u64`, and a caller almost always has the value as
/// text from an RPC or a user. See [`u256_from_decimal`].
///
/// Returns `0x`-prefixed hex, which is what `eth_call` and a transaction's
/// `data` field both take.
///
/// # Errors
///
/// [`Error::InvalidRecipient`] or [`Error::InvalidAmount`].
///
/// # Examples
///
/// ```
/// # #[cfg(all(feature = "abi"))] {
/// use tinywallet_x402::abi;
///
/// let data = abi::encode_erc20_transfer(
///     "0x1111111111111111111111111111111111111111",
///     "1000000",
/// )?;
/// assert!(data.starts_with("0xa9059cbb"));
/// // Selector plus two 32-byte words, hex-encoded, plus the `0x`.
/// assert_eq!(data.len(), 2 + 8 + 128);
/// # }
/// # Ok::<(), tinywallet_x402::abi::Error>(())
/// ```
pub fn encode_erc20_transfer(to: &str, amount: &str) -> Result<String> {
    let recipient =
        tinywallet_crypto::address::evm::validate(to).map_err(|e| Error::InvalidRecipient {
            reason: e.to_string(),
        })?;
    let bytes = decode_evm_address(&recipient)?;
    let value = u256_from_decimal(amount).map_err(|e| Error::InvalidAmount {
        reason: e.to_string(),
    })?;

    let mut out = String::with_capacity(2 + 8 + 128);
    out.push_str("0x");
    for byte in TRANSFER_SELECTOR {
        push_hex(&mut out, byte);
    }
    // Both arguments are static types, so each is one 32-byte word in order —
    // no head/tail offsets, which is the entire reason this can be 20 lines.
    for byte in left_pad_address(bytes) {
        push_hex(&mut out, byte);
    }
    for byte in value {
        push_hex(&mut out, byte);
    }
    Ok(out)
}

/// The 20 raw bytes of an already-validated `0x`-prefixed EVM address.
fn decode_evm_address(address: &str) -> Result<[u8; 20]> {
    let body = address.strip_prefix("0x").unwrap_or(address);
    let mut out = [0u8; 20];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = body.get(index * 2..index * 2 + 2).ok_or_else(|| {
            // Unreachable via `encode_erc20_transfer`, which validates first.
            // Mapped rather than unwrapped so a future caller cannot turn a
            // malformed address into a panic inside a wallet.
            Error::InvalidRecipient {
                reason: "address is shorter than 20 bytes".to_string(),
            }
        })?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| Error::InvalidRecipient {
            reason: "address is not hex".to_string(),
        })?;
    }
    Ok(out)
}

/// An address as the left-padded 32-byte word the ABI encodes it as.
fn left_pad_address(address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

/// Append one byte as two lowercase hex digits.
fn push_hex(out: &mut String, byte: u8) {
    use std::fmt::Write as _;
    // Writing into a String cannot fail; discarded rather than unwrapped so
    // this stays panic-free.
    let _ = write!(out, "{byte:02x}");
}

/// Keccak-256, used only by the selector test.
///
/// Scoped to tests because production code uses the pinned
/// [`TRANSFER_SELECTOR`] rather than hashing the signature on every call.
#[cfg(test)]
fn keccak(bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest as _, Keccak256};
    Keccak256::digest(bytes).into()
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
