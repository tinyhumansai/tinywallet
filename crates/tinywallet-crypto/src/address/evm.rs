//! EVM address validation.
//!
//! An EVM address is 20 bytes rendered as 40 hex digits, conventionally with a
//! `0x` prefix. That is the entire format, which is why this module has no
//! dependencies: pulling a chain client in to call its `Address::from_str`
//! would drag a large secp256k1 and RLP stack in to check a string is hex.
//!
//! ## EIP-55 is checked separately, and that is deliberate
//!
//! [`validate`] accepts any correctly-shaped address, mixed case included,
//! without verifying an EIP-55 checksum. Rejecting a non-checksummed address
//! would break every lowercase address in the wild — they are valid, just
//! unchecksummed, and most tooling emits them.
//!
//! [`is_checksum_valid`] is offered separately for a caller that *has* a
//! mixed-case address and wants the typo protection EIP-55 provides. Keeping
//! the two apart means a host chooses its own strictness instead of inheriting
//! ours.

use crate::chain::Chain;
use crate::{Error, Result};

/// Number of hex digits in an EVM address: 20 bytes, two digits each.
const ADDRESS_HEX_LEN: usize = 40;

/// Validate an EVM address and return it trimmed.
///
/// Accepts an address with or without the lowercase `0x` prefix. The hex body
/// may be any case; an uppercase `0X` prefix is **rejected**, since no tooling
/// emits it and accepting it would widen what counts as an address for no
/// benefit. The returned string is the input with surrounding whitespace
/// removed and is
/// otherwise **unmodified** — case and prefix are preserved, because callers
/// echo the address back to users and normalising it would silently change
/// what they typed. Use [`to_checksummed`] when a canonical form is wanted.
///
/// # Errors
///
/// - [`Error::EmptyAddress`] if `address` is empty or all whitespace.
/// - [`Error::InvalidAddress`] if it is not 40 hex digits after an optional
///   `0x` prefix.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::evm;
///
/// let addr = evm::validate("  0x52908400098527886E0F7030069857D2E4169EE7  ")?;
/// assert_eq!(addr, "0x52908400098527886E0F7030069857D2E4169EE7");
///
/// // The `0x` prefix is optional.
/// assert!(evm::validate("52908400098527886E0F7030069857D2E4169EE7").is_ok());
///
/// // But an uppercase `0X` prefix is not accepted.
/// assert!(evm::validate("0X52908400098527886E0F7030069857D2E4169EE7").is_err());
/// # Ok::<(), tinywallet_bus::Error>(())
/// ```
pub fn validate(address: &str) -> Result<String> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyAddress { chain: Chain::Evm });
    }

    let body = strip_prefix(trimmed);
    if body.len() != ADDRESS_HEX_LEN {
        return Err(Error::InvalidAddress {
            chain: Chain::Evm,
            address: trimmed.to_string(),
            reason: format!("expected {ADDRESS_HEX_LEN} hex digits, got {}", body.len()),
        });
    }
    if let Some(bad) = body.chars().find(|c| !c.is_ascii_hexdigit()) {
        return Err(Error::InvalidAddress {
            chain: Chain::Evm,
            address: trimmed.to_string(),
            reason: format!("contains a non-hex character '{bad}'"),
        });
    }
    Ok(trimmed.to_string())
}

/// Strip an optional lowercase `0x` prefix.
///
/// Deliberately does not accept `0X`: see [`validate`].
fn strip_prefix(address: &str) -> &str {
    address.strip_prefix("0x").unwrap_or(address)
}

/// Whether `address` carries a valid EIP-55 checksum.
///
/// This compares the input against the canonical mixed-case rendering
/// [`to_checksummed`] produces: it returns `true` only when the two are
/// byte-for-byte identical. That is what makes a typo detectable — a wrong
/// character almost always breaks the agreement.
///
/// Concretely, an all-uppercase address never matches, and an all-lowercase
/// one usually does not either, because the canonical form is normally
/// mixed-case. The `usually` matters: an address whose canonical form is
/// itself entirely lowercase (as with
/// `0xde709f2102306220921060314715629080e2fb77`) matches as-is. So this
/// answers "does the address carry a correct checksum", not "is it a valid
/// address" — pair it with [`validate`], which is the function that answers
/// the latter.
///
/// # Errors
///
/// Propagates [`validate`]'s errors: the address must be well-formed before a
/// checksum question is meaningful.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::evm;
///
/// // A correctly checksummed address.
/// assert!(evm::is_checksum_valid("0x52908400098527886E0F7030069857D2E4169EE7")?);
/// // Valid, but carries no checksum information.
/// assert!(!evm::is_checksum_valid("0x52908400098527886e0f7030069857d2e4169ee7")?);
/// # Ok::<(), tinywallet_bus::Error>(())
/// ```
#[cfg(feature = "keccak")]
pub fn is_checksum_valid(address: &str) -> Result<bool> {
    let validated = validate(address)?;
    Ok(to_checksummed(&validated)? == prefixed(strip_prefix(&validated)))
}

/// Render `address` in canonical EIP-55 mixed-case form, `0x`-prefixed.
///
/// # Errors
///
/// Propagates [`validate`]'s errors.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::evm;
///
/// let canonical = evm::to_checksummed("0x52908400098527886e0f7030069857d2e4169ee7")?;
/// assert_eq!(canonical, "0x52908400098527886E0F7030069857D2E4169EE7");
/// # Ok::<(), tinywallet_bus::Error>(())
/// ```
#[cfg(feature = "keccak")]
pub fn to_checksummed(address: &str) -> Result<String> {
    use sha3::{Digest, Keccak256};

    let validated = validate(address)?;
    let lower = strip_prefix(&validated).to_ascii_lowercase();
    let hash = Keccak256::digest(lower.as_bytes());

    let mut out = String::with_capacity(2 + ADDRESS_HEX_LEN);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        // EIP-55: uppercase digit `i` when nibble `i` of the hash is >= 8.
        // Nibbles are big-endian within each byte, so even indices take the
        // high nibble.
        let nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };
        if c.is_ascii_digit() || nibble < 8 {
            out.push(c);
        } else {
            out.push(c.to_ascii_uppercase());
        }
    }
    Ok(out)
}

/// Re-attach the `0x` prefix to a bare hex body.
#[cfg(feature = "keccak")]
fn prefixed(body: &str) -> String {
    format!("0x{body}")
}

#[cfg(test)]
mod test;
