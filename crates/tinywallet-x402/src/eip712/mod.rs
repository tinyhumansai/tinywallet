//! EIP-712 typed-data hashing, and the EIP-3009 payload x402 signs.
//!
//! # Why this is here rather than in a chain library
//!
//! EIP-712 is a hashing scheme, not a chain client. Everything below is
//! keccak-256 over a fixed byte layout — there is no RPC, no signing, and no
//! elliptic curve involved. Hosting it here means the x402 payment path needs
//! `sha3` and nothing else, where routing it through a full Ethereum library
//! costs an ABI encoder, a bignum type, a signer stack, and their tails.
//!
//! # Integers are big-endian `[u8; 32]`, deliberately
//!
//! EIP-712 encodes every `uint256` as a 32-byte big-endian word, so that is the
//! type this module takes. Introducing a bignum just to convert it back to the
//! same 32 bytes would add a dependency to this crate and force one on every
//! caller. [`u256_from_u64`] and [`u256_from_decimal`] cover the two ways a
//! caller actually has the value.
//!
//! # Nothing here signs
//!
//! [`signing_digest`] returns the 32 bytes to sign and stops. That is the same
//! split the rest of this crate makes — see [`crate::wire`] — and it is what
//! lets the payload be built somewhere the signing key is not.

use sha3::{Digest, Keccak256};

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
///
/// Pinned rather than computed at each call: it is a published constant, and a
/// test below recomputes it, so a typo in the type string is caught here rather
/// than as a signature a contract silently rejects.
const DOMAIN_TYPE_HASH: [u8; 32] = [
    0x8b, 0x73, 0xc3, 0xc6, 0x9b, 0xb8, 0xfe, 0x3d, 0x51, 0x2e, 0xcc, 0x4c, 0xf7, 0x59, 0xcc, 0x79,
    0x23, 0x9f, 0x7b, 0x17, 0x9b, 0x0f, 0xfa, 0xca, 0xa9, 0xa7, 0x5d, 0x52, 0x2b, 0x39, 0x40, 0x0f,
];

/// The EIP-712 type string for the EIP-3009 authorization x402 uses.
const TRANSFER_WITH_AUTHORIZATION_TYPE: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";

/// The EIP-712 domain string, kept beside its pinned hash.
///
/// Test-only, and that is the point: production code uses [`DOMAIN_TYPE_HASH`]
/// directly rather than hashing this on every call, and the test re-derives the
/// hash from this string to prove the two agree. Keeping the string here is
/// what makes pinning the hash safe instead of merely fast — a typo in either
/// one fails the test rather than silently changing every signature.
#[cfg(test)]
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// A 32-byte big-endian unsigned integer, as EIP-712 encodes `uint256`.
pub type U256Bytes = [u8; 32];

/// An EVM address as its raw 20 bytes.
pub type Address20 = [u8; 20];

/// Widen a `u64` into the 32-byte big-endian form EIP-712 wants.
#[must_use]
pub fn u256_from_u64(value: u64) -> U256Bytes {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&value.to_be_bytes());
    out
}

/// Parse a base-10 integer string into the 32-byte big-endian form.
///
/// Token amounts arrive as decimal strings — a `u64` cannot hold 18-decimal
/// values — so this does the widening without a bignum dependency, by long
/// multiplication over the 32 bytes.
///
/// # Errors
///
/// [`Error::InvalidAmount`] if `value` is empty, holds a non-digit, or does not
/// fit in 256 bits.
pub fn u256_from_decimal(value: &str) -> Result<U256Bytes> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::InvalidAmount {
            reason: "expected a base-10 integer".to_string(),
        });
    }

    let mut out = [0u8; 32];
    for digit in trimmed.bytes().map(|b| u32::from(b - b'0')) {
        // out = out * 10 + digit, big-endian, carrying from the least
        // significant byte upwards.
        let mut carry = digit;
        for byte in out.iter_mut().rev() {
            let product = u32::from(*byte) * 10 + carry;
            *byte = u8::try_from(product & 0xff).unwrap_or(0);
            carry = product >> 8;
        }
        if carry != 0 {
            return Err(Error::InvalidAmount {
                reason: "value does not fit in 256 bits".to_string(),
            });
        }
    }
    Ok(out)
}

/// Why an EIP-712 payload could not be built.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An amount was not a base-10 integer, or overflowed 256 bits.
    #[error("invalid amount: {reason}")]
    InvalidAmount {
        /// What was wrong with it.
        reason: String,
    },
}

/// Result alias for this module.
pub type Result<T> = std::result::Result<T, Error>;

/// The EIP-712 domain separator.
///
/// `name` and `version` are the token contract's, not the caller's choice: USDC
/// uses `("USD Coin", "2")`, but an x402 `extra` may name different ones, and a
/// mismatch produces a signature the contract rejects rather than an error
/// anything local can detect.
#[must_use]
pub fn domain_separator(
    verifying_contract: Address20,
    chain_id: u64,
    name: &str,
    version: &str,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(5 * 32);
    encoded.extend_from_slice(&DOMAIN_TYPE_HASH);
    encoded.extend_from_slice(&keccak(name.as_bytes()));
    encoded.extend_from_slice(&keccak(version.as_bytes()));
    encoded.extend_from_slice(&u256_from_u64(chain_id));
    encoded.extend_from_slice(&left_pad_address(verifying_contract));
    keccak(&encoded)
}

/// The EIP-3009 `TransferWithAuthorization` struct hash.
#[must_use]
pub fn transfer_with_authorization_hash(
    from: Address20,
    to: Address20,
    value: U256Bytes,
    valid_after: U256Bytes,
    valid_before: U256Bytes,
    nonce: [u8; 32],
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(7 * 32);
    encoded.extend_from_slice(&keccak(TRANSFER_WITH_AUTHORIZATION_TYPE));
    encoded.extend_from_slice(&left_pad_address(from));
    encoded.extend_from_slice(&left_pad_address(to));
    encoded.extend_from_slice(&value);
    encoded.extend_from_slice(&valid_after);
    encoded.extend_from_slice(&valid_before);
    encoded.extend_from_slice(&nonce);
    keccak(&encoded)
}

/// The 32 bytes a caller signs: `keccak256(0x19 0x01 ‖ domain ‖ struct)`.
///
/// The `0x1901` prefix is what keeps a typed-data signature from ever being
/// replayable as a transaction signature — it makes the preimage impossible to
/// confuse with an RLP-encoded transaction.
///
/// Already hashed: sign it with a "prehash" entry point, never by hashing again.
#[must_use]
pub fn signing_digest(domain_separator: [u8; 32], struct_hash: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(2 + 64);
    preimage.extend_from_slice(&[0x19, 0x01]);
    preimage.extend_from_slice(&domain_separator);
    preimage.extend_from_slice(&struct_hash);
    keccak(&preimage)
}

/// Keccak-256.
fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

/// An address as a left-padded 32-byte word, which is how EIP-712 encodes it.
fn left_pad_address(address: Address20) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

#[cfg(test)]
mod test;
