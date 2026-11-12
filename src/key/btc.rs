//! Bitcoin key derivation: BIP-32 on secp256k1, P2WPKH address.
//!
//! Produces a native segwit (`bc1q…`) address, matching
//! [`crate::address::btc::validate_sender`] — the only script type this crate's
//! callers can sign for. Deriving a P2PKH or P2SH address here would hand back
//! something that passes recipient validation and then fails at signing time.
//!
//! The address is assembled here rather than by the `bitcoin` crate, which this
//! module used to route through. A P2WPKH address is fully specified by BIP-141
//! and BIP-173 as `bech32(hrp="bc", version=0, hash160(compressed_pubkey))`, and
//! both halves of that are owned elsewhere: the bech32 encoding by
//! [`crate::address::btc::encode_p2wpkh`], which also decodes it, and the
//! BIP-32 walk by [`super::bip32`], which still delegates to a vetted
//! implementation.

use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use super::{DerivedKey, Result, bip32, derivation_failed, seed_from_mnemonic};
use crate::address::btc::encode_p2wpkh;
use crate::chain::Chain;

/// Derive the Bitcoin signing key and P2WPKH address for `path`.
pub(super) fn derive(mnemonic: &str, path: &str) -> Result<DerivedKey> {
    let seed = seed_from_mnemonic(mnemonic)?;
    let key = bip32::derive(&seed, path)?;

    // The *compressed* encoding: a P2WPKH witness program is defined over it,
    // and hashing the uncompressed form instead produces a valid-looking
    // address for an account holding no funds.
    let address = encode_p2wpkh(&hash160(&key.compressed_public()))
        .map_err(derivation_failed("BTC P2WPKH address"))?;

    Ok(DerivedKey::new(
        Chain::Btc,
        address,
        key.secret_bytes().to_vec(),
    ))
}

/// `RIPEMD160(SHA256(data))` — Bitcoin's HASH160.
fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let ripemd = Ripemd160::digest(sha);
    let mut out = [0u8; 20];
    // RIPEMD-160 is 20 bytes by definition.
    out.copy_from_slice(&ripemd);
    out
}
