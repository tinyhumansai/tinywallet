//! Tron key derivation: BIP-32 on secp256k1, address via Keccak-256 plus the
//! `0x41` version byte and a base58check envelope.
//!
//! Identical to EVM up to the Keccak hash — Tron reuses Ethereum's address
//! construction and then re-encodes it. That similarity is a trap worth naming:
//! the hex form of a Tron address looks like an EVM address but is 21 bytes,
//! not 20, because of the version prefix.

use sha3::{Digest, Keccak256};

use super::{DerivedKey, Result, bip32, derivation_failed, seed_from_mnemonic};
use crate::address::tron::{ADDRESS_BYTES, MAINNET_PREFIX};
use crate::chain::Chain;

/// Derive the Tron signing key and address for `path`.
pub(super) fn derive(mnemonic: &str, path: &str) -> Result<DerivedKey> {
    let seed = seed_from_mnemonic(mnemonic)?;
    let key = bip32::derive(&seed, path)?;
    let address = address_from_public(&key.uncompressed_public())?;
    Ok(DerivedKey::new(
        Chain::Tron,
        address,
        key.secret_bytes().to_vec(),
    ))
}

/// Keccak-256 the uncompressed public key without its `0x04` prefix, take the
/// last 20 bytes, prepend the Tron mainnet version byte, and base58check it.
///
/// `encode` verifies the version byte and so returns a `Result`. It cannot
/// fail here (the prefix is written two lines above), so the error is mapped
/// by [`derivation_failed`] rather than unwrapped.
fn address_from_public(uncompressed: &[u8; 65]) -> Result<String> {
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut bytes = [0u8; ADDRESS_BYTES];
    bytes[0] = MAINNET_PREFIX;
    bytes[1..].copy_from_slice(&hash[12..]);
    crate::address::tron::encode(&bytes).map_err(derivation_failed("Tron address encoding"))
}
