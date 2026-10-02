//! Tests for ERC-20 calldata encoding.
//!
//! Calldata is signed, then executed by a contract that will do exactly what
//! the bytes say. A wrong recipient word or a wrong amount word produces a
//! transaction that succeeds and moves the wrong money, so the encoding is
//! checked against the ABI specification's layout rather than against itself.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{Error, TRANSFER_SELECTOR, TRANSFER_SIGNATURE, encode_erc20_transfer, keccak};

const RECIPIENT: &str = "0x1111111111111111111111111111111111111111";

#[test]
fn the_pinned_selector_matches_its_signature() {
    // The constant is pinned so the hash is not recomputed per call; this is
    // the test that makes pinning safe rather than a place for a typo to hide.
    assert_eq!(keccak(TRANSFER_SIGNATURE)[..4], TRANSFER_SELECTOR);
}

#[test]
fn the_selector_is_the_published_erc20_transfer_selector() {
    assert_eq!(TRANSFER_SELECTOR, [0xa9, 0x05, 0x9c, 0xbb]);
}

#[test]
fn the_encoding_is_a_selector_and_two_left_padded_words() {
    let data = encode_erc20_transfer(RECIPIENT, "1000000").unwrap();

    // 0x + 4-byte selector + 2 x 32-byte words, hex.
    assert_eq!(data.len(), 2 + 8 + 128);
    assert_eq!(
        data,
        "0xa9059cbb\
         0000000000000000000000001111111111111111111111111111111111111111\
         00000000000000000000000000000000000000000000000000000000000f4240"
    );
}

#[test]
fn the_recipient_is_right_aligned_in_its_word() {
    // Left-padding is the ABI rule for `address`. Getting it backwards yields
    // a well-formed call paying an address nobody controls.
    let data = encode_erc20_transfer(RECIPIENT, "1").unwrap();
    let recipient_word = &data[10..74];
    assert!(recipient_word.starts_with(&"0".repeat(24)));
    assert!(recipient_word.ends_with(&"11".repeat(20)));
}

#[test]
fn an_amount_beyond_u64_encodes_exactly() {
    // The reason the amount is a string: an 18-decimal token puts ordinary
    // balances past u64, and truncating would silently transfer the wrong sum.
    let data = encode_erc20_transfer(RECIPIENT, "340282366920938463463374607431768211456").unwrap();
    assert!(data.ends_with("0000000000000000000000000000000100000000000000000000000000000000"));
}

#[test]
fn the_largest_representable_amount_is_accepted() {
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    let data = encode_erc20_transfer(RECIPIENT, max).unwrap();
    assert!(data.ends_with(&"f".repeat(64)));
}

#[test]
fn a_zero_amount_encodes_as_a_zero_word_not_an_empty_one() {
    // Static types are always a full word; an empty encoding would shift the
    // call's shape and make it unparseable by the contract.
    let data = encode_erc20_transfer(RECIPIENT, "0").unwrap();
    assert_eq!(data.len(), 2 + 8 + 128);
    assert!(data.ends_with(&"0".repeat(64)));
}

#[test]
fn a_checksummed_recipient_encodes_the_same_as_a_lowercase_one() {
    // EIP-55 casing is display metadata, not part of the address.
    let lower = encode_erc20_transfer("0xab5801a7d398351b8be11c439e05c5b3259aec9b", "5").unwrap();
    let checksummed =
        encode_erc20_transfer("0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B", "5").unwrap();
    assert_eq!(lower, checksummed);
}

#[test]
fn an_invalid_recipient_is_refused() {
    for bad in [
        "",
        "0x",
        "not-an-address",
        "0x111",
        &format!("0x{}", "1".repeat(41)),
    ] {
        assert!(
            matches!(
                encode_erc20_transfer(bad, "1"),
                Err(Error::InvalidRecipient { .. })
            ),
            "{bad:?} should be refused"
        );
    }
}

#[test]
fn a_non_numeric_or_overflowing_amount_is_refused() {
    for bad in [
        "",
        "12a",
        "-1",
        "1.5",
        "0x10",
        // 2^256 exactly: one past the top.
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    ] {
        assert!(
            matches!(
                encode_erc20_transfer(RECIPIENT, bad),
                Err(Error::InvalidAmount { .. })
            ),
            "{bad:?} should be refused"
        );
    }
}

#[test]
fn the_address_decoder_refuses_malformed_input_rather_than_panicking() {
    // `encode_erc20_transfer` validates before calling this, so these arms are
    // defensive — but defensive code that is never exercised is code nobody
    // knows works, and the failure mode it guards against is a panic inside a
    // wallet. Tested directly because the public path cannot reach it.
    use super::decode_evm_address;

    assert!(matches!(
        decode_evm_address("0x1111"),
        Err(Error::InvalidRecipient { .. })
    ));
    assert!(matches!(
        decode_evm_address(&format!("0x{}", "zz".repeat(20))),
        Err(Error::InvalidRecipient { .. })
    ));

    // The happy path, unprefixed, to pin that the `0x` is optional here.
    assert_eq!(decode_evm_address(&"11".repeat(20)).unwrap(), [0x11u8; 20]);
}
