//! Tests for validation, formatting and hex helpers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    estimated_fee_raw, format_amount, hex_to_bytes, hex_to_u128, u128_to_hex, validate_address,
    validate_amount, validate_calldata,
};
use crate::crypto::execution::PreparedKind;
use crate::crypto::wallet::WalletChain;

#[test]
fn amounts_reject_empty_and_non_numeric() {
    assert_eq!(validate_amount(""), Err("amount is empty".to_string()));
    assert_eq!(
        validate_amount("abc"),
        Err("amount 'abc' is not a valid non-negative integer".to_string())
    );
    assert!(validate_amount("-1").is_err());
    assert_eq!(validate_amount(" 42 ").unwrap(), 42);
}

#[test]
fn calldata_must_be_prefixed_aligned_hex() {
    assert_eq!(
        validate_calldata("deadbeef").unwrap_err(),
        "calldata must be 0x-prefixed hex"
    );
    assert_eq!(
        validate_calldata("0xabc").unwrap_err(),
        "calldata hex must be byte-aligned"
    );
    assert_eq!(
        validate_calldata("0xZZ").unwrap_err(),
        "calldata contains non-hex characters"
    );
    assert_eq!(validate_calldata(" 0xdeadbeef ").unwrap(), "0xdeadbeef");
    assert_eq!(validate_calldata("0x").unwrap(), "0x");
}

#[test]
fn amounts_format_with_their_decimals() {
    assert_eq!(format_amount(0, 18), "0.000000000000000000");
    assert_eq!(format_amount(1, 8), "0.00000001");
    assert_eq!(format_amount(123_456_789, 8), "1.23456789");
    assert_eq!(format_amount(100, 0), "100");
    assert_eq!(format_amount(5, 1), "0.5");
}

#[test]
fn fees_are_a_flat_estimate_per_chain_and_kind() {
    let evm_native = estimated_fee_raw(WalletChain::Evm, PreparedKind::NativeTransfer);
    let evm_token = estimated_fee_raw(WalletChain::Evm, PreparedKind::TokenTransfer);
    assert_eq!(evm_native, "630000000000000");
    assert_eq!(evm_token, "1950000000000000");
    assert_eq!(
        estimated_fee_raw(WalletChain::Btc, PreparedKind::NativeTransfer),
        "5000"
    );
    assert_eq!(
        estimated_fee_raw(WalletChain::Solana, PreparedKind::TokenTransfer),
        "5000"
    );
    assert_eq!(
        estimated_fee_raw(WalletChain::Tron, PreparedKind::NativeTransfer),
        "1000000"
    );
    assert_eq!(
        estimated_fee_raw(WalletChain::Tron, PreparedKind::TokenTransfer),
        "15000000"
    );
}

#[test]
fn hex_quantities_round_trip_and_report_the_offending_value() {
    assert_eq!(hex_to_u128("0x10").unwrap(), 16);
    assert_eq!(hex_to_u128(" 10 ").unwrap(), 16);
    assert_eq!(u128_to_hex(255), "0xff");
    assert_eq!(hex_to_u128(&u128_to_hex(u128::MAX)).unwrap(), u128::MAX);
    let error = hex_to_u128("0xzz").unwrap_err();
    assert!(error.contains("invalid hex quantity '0xzz'"), "{error}");
}

#[test]
fn hex_bytes_accept_an_optional_prefix() {
    assert_eq!(hex_to_bytes("0xdead").unwrap(), vec![0xde, 0xad]);
    assert_eq!(hex_to_bytes("dead").unwrap(), vec![0xde, 0xad]);
    assert!(
        hex_to_bytes("0xd")
            .unwrap_err()
            .contains("invalid hex bytes")
    );
}

#[test]
fn addresses_are_checked_per_chain_and_returned_trimmed() {
    let evm = "0x1111111111111111111111111111111111111111";
    assert_eq!(
        validate_address(WalletChain::Evm, &format!(" {evm} ")).unwrap(),
        evm
    );
    assert!(validate_address(WalletChain::Evm, "nope").is_err());
    // Bitcoin uses the recipient rule: any mainnet type is accepted.
    let p2tr = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    assert_eq!(validate_address(WalletChain::Btc, p2tr).unwrap(), p2tr);
    assert!(validate_address(WalletChain::Tron, evm).is_err());
    assert!(validate_address(WalletChain::Solana, "tooShort").is_err());
}
