#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{recovery_byte, sign, signature_hex};
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

#[test]
fn a_recovery_id_outside_one_byte_is_a_signing_error() {
    assert_eq!(recovery_byte(0).unwrap(), 0);
    assert_eq!(recovery_byte(3).unwrap(), 3);
    assert!(matches!(recovery_byte(-1), Err(Error::Signing { .. })));
    assert!(matches!(recovery_byte(256), Err(Error::Signing { .. })));
}
