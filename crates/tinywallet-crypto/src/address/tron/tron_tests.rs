//! Unit tests for Tron address validation and hex conversion.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{ADDRESS_BYTES, MAINNET_PREFIX, decode, encode, to_hex, validate};
use crate::{Chain, Error};

/// The USDT TRC20 contract address — a real, checksummed mainnet address.
const USDT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

#[test]
fn accepts_a_real_mainnet_address() {
    assert_eq!(validate(USDT).unwrap(), USDT);
}

#[test]
fn trims_surrounding_whitespace() {
    assert_eq!(validate(&format!("  {USDT}\n")).unwrap(), USDT);
}

#[test]
fn rejects_an_empty_address() {
    assert_eq!(
        validate("  ").unwrap_err(),
        Error::EmptyAddress { chain: Chain::Tron }
    );
}

#[test]
fn rejects_a_mistyped_address_via_its_checksum() {
    // Unlike Solana, Tron addresses are checksummed, so a typo is caught.
    let mut chars: Vec<char> = USDT.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'u' { 'v' } else { 'u' };
    let typo: String = chars.into_iter().collect();
    assert_ne!(typo, USDT, "the fixture must actually differ");

    match validate(&typo).unwrap_err() {
        Error::InvalidAddress { chain, address, .. } => {
            assert_eq!(chain, Chain::Tron);
            assert_eq!(address, typo);
        }
        other => panic!("expected InvalidAddress, got {other:?}"),
    }
}

#[test]
fn rejects_a_non_base58_address() {
    assert!(matches!(
        validate("not!an!address").unwrap_err(),
        Error::InvalidAddress { .. }
    ));
}

#[test]
fn rejects_an_address_with_a_foreign_version_prefix() {
    // Same 20-byte payload, a different version byte. Base58check verifies the
    // prefix, which is what stops a foreign-chain address decoding to
    // something plausible.
    let mut bytes = [0u8; ADDRESS_BYTES];
    bytes[0] = 0x30;
    let foreign = bs58::encode(bytes).with_check().into_string();
    assert!(
        validate(&foreign).is_err(),
        "a non-{MAINNET_PREFIX:#x} prefix must be rejected"
    );
}

#[test]
fn rejects_a_base58check_value_with_the_right_prefix_but_wrong_length() {
    let short = bs58::encode([MAINNET_PREFIX]).with_check().into_string();
    assert!(matches!(
        decode(&short),
        Err(Error::InvalidAddress {
            chain: Chain::Tron,
            ..
        })
    ));
}

#[test]
fn decode_retains_the_version_prefix() {
    let bytes = decode(USDT).unwrap();
    assert_eq!(bytes.len(), ADDRESS_BYTES);
    assert_eq!(bytes[0], MAINNET_PREFIX);
}

#[test]
fn encode_and_decode_round_trip() {
    assert_eq!(encode(&decode(USDT).unwrap()).unwrap(), USDT);
}

#[test]
fn encode_rejects_a_non_mainnet_version_prefix() {
    // `encode` must not mint an address that `validate` would reject: with any
    // first byte other than the mainnet prefix the result is well-formed
    // base58check for some *other* Tron network.
    let mut bytes = [0u8; ADDRESS_BYTES];
    bytes[0] = 0x30;
    match encode(&bytes).unwrap_err() {
        Error::WrongNetwork {
            chain,
            address,
            expected,
            reason,
        } => {
            assert_eq!(chain, Chain::Tron);
            assert!(address.starts_with("30"), "hex form: {address}");
            assert_eq!(expected, "mainnet");
            assert!(reason.contains(&format!("{MAINNET_PREFIX:#04x}")));
        }
        other => panic!("expected WrongNetwork, got {other:?}"),
    }
}

#[test]
fn to_hex_produces_the_trongrid_form() {
    let hex = to_hex(USDT).unwrap();
    // 21 bytes, two hex digits each — and no `0x`, because this is not an EVM
    // address despite the resemblance.
    assert_eq!(hex.len(), ADDRESS_BYTES * 2);
    assert!(!hex.starts_with("0x"));
    assert!(
        hex.starts_with("41"),
        "the version prefix is retained: {hex}"
    );
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(hex, hex.to_lowercase(), "hex output is lowercase");
}

#[test]
fn to_hex_rejects_exactly_what_validate_rejects() {
    for input in [
        "",
        "   ",
        "not!base58",
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u",
    ] {
        assert_eq!(
            validate(input).is_err(),
            to_hex(input).is_err(),
            "validate and to_hex disagreed on {input:?}"
        );
    }
}
