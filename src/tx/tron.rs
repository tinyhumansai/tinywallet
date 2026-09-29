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

    let recovery = u8::try_from(recovery_id.to_i32()).map_err(|_| Error::Signing {
        reason: "unexpected recovery id".to_string(),
    })?;
    attach_signature(&compact, recovery)
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{sign, signature_hex};
    use crate::tx::Error;

    const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";
    const TO: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    fn key() -> Vec<u8> {
        crate::key::derive(crate::Chain::Tron, VECTOR, "m/44'/195'/0'/0/0")
            .unwrap()
            .secret_bytes()
            .to_vec()
    }

    /// A `raw_data`-shaped hex blob embedding the recipient's hex address.
    fn raw_data() -> String {
        let to_hex = crate::address::tron::to_hex(TO).unwrap();
        format!("0a02b1f42208{to_hex}5a0f")
    }

    #[test]
    fn the_signature_is_65_bytes_ending_in_a_bare_recovery_id() {
        // Tron borrowed Ethereum's addresses but not EIP-155's v encoding.
        let signature = sign(&raw_data(), &key()).unwrap();
        assert_eq!(signature.len(), 65);
        assert!(signature[64] <= 3, "recovery id, not a v value");
        assert_eq!(signature_hex(&signature).len(), 130);
    }

    #[test]
    fn signing_is_deterministic() {
        let raw = raw_data();
        assert_eq!(sign(&raw, &key()).unwrap(), sign(&raw, &key()).unwrap());
    }

    #[test]
    fn different_raw_data_produces_a_different_signature() {
        let a = sign(&raw_data(), &key()).unwrap();
        let b = sign(&raw_data().replace("0a02", "0a03"), &key()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(matches!(
            sign("zz", &key()).unwrap_err(),
            Error::InvalidField { .. }
        ));
    }

    #[test]
    fn an_invalid_key_is_rejected() {
        assert!(matches!(
            sign(&raw_data(), &[0u8; 32]).unwrap_err(),
            Error::Signing { .. }
        ));
    }
}
