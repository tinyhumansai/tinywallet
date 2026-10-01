//! Tron transaction signing.
//!
//! Everything about a Tron transaction that reads or checks bytes — the
//! `raw_data` protobuf walk, the txid recomputation, the structural
//! verification of what a node handed back, and the assembly of the 65-byte
//! signature — lives in [`tinywallet_crypto::tx::tron`] and is re-exported here,
//! so `tinywallet::tx::tron::verify_transfer` still resolves.
//!
//! What is left in this crate is the one thing that needs a secp256k1
//! implementation: turning a key and a digest into those 64 bytes. That is the
//! split the `tx` gate is for. A host that has moved signing into a loadable
//! module takes the bus crate, verifies the node's answer itself, and links no
//! `bitcoin` crate and no native C build to do it.
//!
//! ## Why verification exists at all
//!
//! Tron inverts the usual arrangement: the **node** builds the transaction. A
//! client POSTs the transfer parameters to `wallet/createtransaction`, gets
//! back a protobuf `raw_data`, signs it, and POSTs it back to
//! `wallet/broadcasttransaction`. Signing whatever a node hands back is
//! trusting it to have built the transfer that was asked for, which is why the
//! checks in the bus crate are not optional politeness.

use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

use super::{Error, Result};

pub use tinywallet_crypto::tx::tron::{
    Signature, attach_signature, digest, recompute_txid, signature_hex, verify_contract,
    verify_transfer,
};

/// Sign a Tron `raw_data` payload.
///
/// Signs `sha256(raw_data)` — the same value as the `txID`.
///
/// # Errors
///
/// [`Error::InvalidField`] for malformed hex, [`Error::Signing`] for an
/// invalid key.
pub fn sign(raw_data_hex: &str, secret_key: &[u8]) -> Result<Signature> {
    let secret = SecretKey::from_slice(secret_key).map_err(|_| Error::Signing {
        reason: "not a valid secp256k1 secret key".to_string(),
    })?;
    let message = Message::from_digest(digest(raw_data_hex)?);

    let secp = Secp256k1::signing_only();
    let recoverable = secp.sign_ecdsa_recoverable(&message, &secret);
    let (recovery_id, compact) = recoverable.serialize_compact();

    let recovery = recovery_byte(recovery_id.to_i32())?;
    attach_signature(&compact, recovery)
}

/// Narrow a secp256k1 recovery id to the single byte Tron appends.
fn recovery_byte(id: i32) -> Result<u8> {
    u8::try_from(id).map_err(|_| Error::Signing {
        reason: "unexpected recovery id".to_string(),
    })
}

#[cfg(test)]
#[path = "tron_test_tests.rs"]
mod test;
