//! Solana address validation.
//!
//! A Solana address is an ed25519 public key — 32 raw bytes — rendered in
//! base58. There is no checksum and no version byte, so validation is exactly
//! two questions: does it decode as base58, and is the result 32 bytes.
//!
//! That absence of a checksum is worth knowing: unlike Bitcoin or Tron, a
//! single mistyped character in a Solana address usually produces *another
//! syntactically valid address*. Validation here catches malformed input, not
//! typos, and no amount of parsing can change that.

use crate::chain::Chain;
use crate::{Error, Result};

/// Length in bytes of a decoded Solana address (an ed25519 public key).
pub const ADDRESS_BYTES: usize = 32;

/// Validate a Solana address and return it trimmed.
///
/// # Errors
///
/// - [`Error::EmptyAddress`] if `address` is empty or all whitespace.
/// - [`Error::InvalidAddress`] if it is not base58, or does not decode to
///   exactly [`ADDRESS_BYTES`] bytes.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::solana;
///
/// // The system program id — 32 zero bytes.
/// assert!(solana::validate("11111111111111111111111111111111").is_ok());
///
/// // `0` is not in the base58 alphabet.
/// assert!(solana::validate("0OIl").is_err());
/// ```
pub fn validate(address: &str) -> Result<String> {
    decode(address).map(|_| address.trim().to_string())
}

/// Validate a Solana address and return its decoded 32 bytes.
///
/// The same check as [`validate`], for a caller that needs the key material
/// rather than the string — deriving an associated token account, say. Offered
/// so callers do not have to decode a second time immediately after
/// validating.
///
/// # Errors
///
/// Identical to [`validate`].
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::solana;
///
/// let bytes = solana::decode("11111111111111111111111111111111")?;
/// assert_eq!(bytes, [0u8; 32]);
/// # Ok::<(), tinywallet_bus::Error>(())
/// ```
pub fn decode(address: &str) -> Result<[u8; ADDRESS_BYTES]> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyAddress {
            chain: Chain::Solana,
        });
    }

    let decoded = bs58::decode(trimmed)
        .into_vec()
        .map_err(|e| Error::InvalidAddress {
            chain: Chain::Solana,
            address: trimmed.to_string(),
            reason: format!("not valid base58: {e}"),
        })?;

    decoded
        .try_into()
        .map_err(|v: Vec<u8>| Error::InvalidAddress {
            chain: Chain::Solana,
            address: trimmed.to_string(),
            reason: format!("expected {ADDRESS_BYTES} bytes, got {}", v.len()),
        })
}

/// Render 32 raw bytes as a base58 Solana address.
///
/// The inverse of [`decode`]. Infallible: every 32-byte array is a
/// syntactically valid address.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::solana;
///
/// assert_eq!(solana::encode(&[0u8; 32]), "11111111111111111111111111111111");
/// ```
#[must_use]
pub fn encode(bytes: &[u8; ADDRESS_BYTES]) -> String {
    bs58::encode(bytes).into_string()
}

#[cfg(test)]
mod test;
