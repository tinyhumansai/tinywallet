//! Tron address validation and hex conversion.
//!
//! Tron addresses come in two forms, and any code touching the chain deals
//! with both:
//!
//! - **Base58check** (`T…`) — the user-facing form. 21 bytes: a `0x41` version
//!   prefix plus a 20-byte payload, with a 4-byte checksum appended.
//! - **Hex** (`41…`) — the same 21 bytes, hex-encoded. This is what the
//!   `TronGrid` API speaks.
//!
//! [`to_hex`] converts between them. Unlike Solana, Tron addresses *are*
//! checksummed, so a mistyped address is reliably caught here rather than
//! silently naming a different account.

use crate::chain::Chain;
use crate::{Error, Result};

/// Tron mainnet address version prefix.
///
/// Every decoded mainnet address starts with this byte; base58check decoding
/// verifies it, which is what makes a testnet or foreign-chain address fail
/// rather than decode to something plausible.
pub const MAINNET_PREFIX: u8 = 0x41;

/// Length in bytes of a decoded Tron address: the version prefix plus a
/// 20-byte payload.
pub const ADDRESS_BYTES: usize = 21;

/// Validate a Tron mainnet address and return it trimmed.
///
/// # Errors
///
/// - [`Error::EmptyAddress`] if `address` is empty or all whitespace.
/// - [`Error::InvalidAddress`] if base58check decoding fails — a bad checksum,
///   a non-base58 character, or a version byte other than
///   [`MAINNET_PREFIX`] — or if the payload is not [`ADDRESS_BYTES`] bytes.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::tron;
///
/// assert!(tron::validate("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t").is_ok());
///
/// // One character changed: the checksum catches it.
/// assert!(tron::validate("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u").is_err());
/// ```
pub fn validate(address: &str) -> Result<String> {
    decode(address).map(|_| address.trim().to_string())
}

/// Validate a Tron address and return its decoded 21 bytes, version prefix
/// included.
///
/// # Errors
///
/// Identical to [`validate`].
pub fn decode(address: &str) -> Result<[u8; ADDRESS_BYTES]> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyAddress { chain: Chain::Tron });
    }

    let decoded = bs58::decode(trimmed)
        .with_check(Some(MAINNET_PREFIX))
        .into_vec()
        .map_err(|e| Error::InvalidAddress {
            chain: Chain::Tron,
            address: trimmed.to_string(),
            reason: format!("base58check decoding failed: {e}"),
        })?;

    decoded
        .try_into()
        .map_err(|v: Vec<u8>| Error::InvalidAddress {
            chain: Chain::Tron,
            address: trimmed.to_string(),
            reason: format!(
                "expected {ADDRESS_BYTES} bytes after base58check, got {}",
                v.len()
            ),
        })
}

/// Convert a base58check Tron address to its hex form.
///
/// The result is 42 lowercase hex digits — the 21 decoded bytes including the
/// `41` version prefix, with no `0x`. That is the form the `TronGrid` API
/// expects; it is **not** an EVM address, despite the superficial resemblance.
///
/// # Errors
///
/// Identical to [`validate`].
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::tron;
///
/// let hex = tron::to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")?;
/// assert_eq!(hex.len(), 42);
/// assert!(hex.starts_with("41"), "the version prefix is retained");
/// # Ok::<(), tinywallet_bus::Error>(())
/// ```
pub fn to_hex(address: &str) -> Result<String> {
    Ok(hex::encode(decode(address)?))
}

/// Render 21 decoded bytes as a base58check Tron address.
///
/// The inverse of [`decode`]. The input must be a full mainnet address —
/// version prefix included — so its first byte must be [`MAINNET_PREFIX`].
/// Enforcing that here means every successful result round-trips through both
/// [`decode`] and [`validate`].
///
/// # Errors
///
/// - [`Error::WrongNetwork`] if the first byte is not [`MAINNET_PREFIX`]: the
///   bytes are then a well-formed address for some other Tron network, not
///   mainnet.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::tron;
///
/// let bytes = tron::decode("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")?;
/// assert_eq!(tron::encode(&bytes)?, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t");
/// # Ok::<(), tinywallet_bus::Error>(())
/// ```
pub fn encode(bytes: &[u8; ADDRESS_BYTES]) -> Result<String> {
    if bytes[0] != MAINNET_PREFIX {
        return Err(Error::WrongNetwork {
            chain: Chain::Tron,
            address: hex::encode(bytes),
            expected: "mainnet".to_string(),
            reason: format!(
                "version prefix is {:#04x}, expected {MAINNET_PREFIX:#04x}",
                bytes[0]
            ),
        });
    }
    Ok(bs58::encode(bytes).with_check().into_string())
}

#[cfg(test)]
mod test;
