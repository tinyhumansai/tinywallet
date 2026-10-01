//! Unit tests for the crate-wide error type.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::Error;
use crate::Chain;

#[test]
fn empty_address_names_its_chain() {
    let err = Error::EmptyAddress { chain: Chain::Btc };
    assert_eq!(err.to_string(), "btc address is empty");
}

#[test]
fn invalid_address_shows_the_address_and_the_reason() {
    // The rejected address appears verbatim: it is public data, and eliding it
    // turns a one-line fix into a debugging session.
    let err = Error::InvalidAddress {
        chain: Chain::Solana,
        address: "0OIl".to_string(),
        reason: "not valid base58".to_string(),
    };
    let rendered = err.to_string();
    assert!(rendered.contains("0OIl"), "{rendered}");
    assert!(rendered.contains("not valid base58"), "{rendered}");
    assert!(rendered.contains("solana"), "{rendered}");
}

#[test]
fn wrong_network_names_the_expected_network() {
    let err = Error::WrongNetwork {
        chain: Chain::Btc,
        address: "tb1qexample".to_string(),
        expected: "mainnet".to_string(),
        reason: "address is testnet".to_string(),
    };
    assert!(err.to_string().contains("mainnet"));
}

#[test]
fn unsupported_address_type_explains_what_is_supported() {
    let err = Error::UnsupportedAddressType {
        chain: Chain::Btc,
        address: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2".to_string(),
        reason: "only P2WPKH (bc1q… native segwit) can be signed for".to_string(),
    };
    // A caller reading this should learn the fix, not just the failure.
    assert!(err.to_string().contains("P2WPKH"));
}

#[test]
fn errors_compare_by_value() {
    // Callers assert on specific errors in their own tests, so equality has to
    // be structural rather than by message.
    assert_eq!(
        Error::EmptyAddress { chain: Chain::Evm },
        Error::EmptyAddress { chain: Chain::Evm }
    );
    assert_ne!(
        Error::EmptyAddress { chain: Chain::Evm },
        Error::EmptyAddress { chain: Chain::Btc }
    );
}
