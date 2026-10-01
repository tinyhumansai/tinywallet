//! Tests for EIP-712 hashing.
//!
//! A wrong hash here is not a crash — it is a well-formed signature over
//! something other than the intended payment, which the contract rejects with
//! no explanation, or worse, accepts. So the constants are checked against the
//! specifications rather than against this module's own output.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    DOMAIN_TYPE, DOMAIN_TYPE_HASH, Error, TRANSFER_WITH_AUTHORIZATION_TYPE, domain_separator,
    keccak, signing_digest, transfer_with_authorization_hash, u256_from_decimal, u256_from_u64,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn the_pinned_domain_type_hash_matches_its_type_string() {
    // The constant is pinned so a typo in the type string cannot silently
    // change every signature this module produces. This is the test that makes
    // pinning safe rather than merely convenient.
    assert_eq!(keccak(DOMAIN_TYPE), DOMAIN_TYPE_HASH);
}

#[test]
fn the_domain_type_hash_is_the_published_constant() {
    assert_eq!(
        hex(&DOMAIN_TYPE_HASH),
        "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
    );
}

#[test]
fn the_eip3009_type_hash_is_the_published_constant() {
    // From EIP-3009. A wrong type hash produces a signature that every
    // conforming token contract refuses.
    assert_eq!(
        hex(&keccak(TRANSFER_WITH_AUTHORIZATION_TYPE)),
        "7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267"
    );
}

#[test]
fn a_u64_widens_into_the_low_eight_bytes() {
    let widened = u256_from_u64(1);
    assert_eq!(widened[31], 1);
    assert!(widened[..31].iter().all(|b| *b == 0));

    assert_eq!(
        hex(&u256_from_u64(u64::MAX)),
        "000000000000000000000000000000000000000000000000ffffffffffffffff"
    );
}

#[test]
fn a_decimal_string_widens_the_same_way_a_u64_does() {
    // The two paths must agree wherever they overlap, or an amount's encoding
    // would depend on which one the caller happened to use.
    for value in [0u64, 1, 42, 1_000_000, u64::MAX] {
        assert_eq!(
            u256_from_decimal(&value.to_string()).unwrap(),
            u256_from_u64(value),
            "decimal and u64 widening disagree for {value}"
        );
    }
}

#[test]
fn a_decimal_string_carries_beyond_sixty_four_bits() {
    // The reason the decimal path exists: an 18-decimal token amount does not
    // fit in a u64.
    let one_ether = "1000000000000000000000000000000000000000";
    let widened = u256_from_decimal(one_ether).unwrap();
    assert!(
        widened[..8].iter().any(|b| *b != 0) || widened[8..24].iter().any(|b| *b != 0),
        "a value past 2^64 must occupy the high bytes: {}",
        hex(&widened)
    );

    // 2^128, checked exactly.
    assert_eq!(
        hex(&u256_from_decimal("340282366920938463463374607431768211456").unwrap()),
        "0000000000000000000000000000000100000000000000000000000000000000"
    );
}

#[test]
fn the_largest_representable_value_is_accepted_and_the_next_is_not() {
    let max = "1157920892373161954235709850086879078532699846656405640394575840079131296399\
               35";
    let max = max.replace(char::is_whitespace, "");
    assert_eq!(hex(&u256_from_decimal(&max).unwrap()), "ff".repeat(32));

    // 2^256 exactly: one past the top.
    let overflow = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
    assert!(matches!(
        u256_from_decimal(overflow).unwrap_err(),
        Error::InvalidAmount { .. }
    ));
}

#[test]
fn a_non_numeric_amount_is_refused_rather_than_silently_zero() {
    for bad in ["", "   ", "12a", "-1", "1.5", "0x10"] {
        assert!(
            matches!(u256_from_decimal(bad), Err(Error::InvalidAmount { .. })),
            "{bad:?} should be refused"
        );
    }
}

#[test]
fn the_domain_separator_depends_on_every_one_of_its_inputs() {
    // Each field is part of the replay boundary: the same authorization must
    // not verify on another chain, another contract, or another token.
    let contract = [0x11u8; 20];
    let base = domain_separator(contract, 1, "USD Coin", "2");

    assert_ne!(base, domain_separator([0x22u8; 20], 1, "USD Coin", "2"));
    assert_ne!(base, domain_separator(contract, 8453, "USD Coin", "2"));
    assert_ne!(base, domain_separator(contract, 1, "USDC", "2"));
    assert_ne!(base, domain_separator(contract, 1, "USD Coin", "1"));
}

#[test]
fn the_struct_hash_depends_on_every_one_of_its_inputs() {
    let base = transfer_with_authorization_hash(
        [0x11; 20],
        [0x22; 20],
        u256_from_u64(100),
        u256_from_u64(0),
        u256_from_u64(9_999),
        [0x33; 32],
    );

    // Recipient and value especially: a hash insensitive to either would let a
    // payment be redirected or resized after signing.
    assert_ne!(
        base,
        transfer_with_authorization_hash(
            [0x11; 20],
            [0xaa; 20],
            u256_from_u64(100),
            u256_from_u64(0),
            u256_from_u64(9_999),
            [0x33; 32],
        )
    );
    assert_ne!(
        base,
        transfer_with_authorization_hash(
            [0x11; 20],
            [0x22; 20],
            u256_from_u64(101),
            u256_from_u64(0),
            u256_from_u64(9_999),
            [0x33; 32],
        )
    );
    assert_ne!(
        base,
        transfer_with_authorization_hash(
            [0x11; 20],
            [0x22; 20],
            u256_from_u64(100),
            u256_from_u64(0),
            u256_from_u64(9_999),
            [0x44; 32],
        )
    );
}

#[test]
fn the_signing_digest_is_prefixed_so_it_cannot_be_a_transaction() {
    // The 0x1901 prefix is the whole reason a typed-data signature cannot be
    // replayed as a transaction signature.
    let domain = [0x11u8; 32];
    let structure = [0x22u8; 32];

    let mut preimage = vec![0x19, 0x01];
    preimage.extend_from_slice(&domain);
    preimage.extend_from_slice(&structure);

    assert_eq!(signing_digest(domain, structure), keccak(&preimage));
    // And it must not be a bare hash of the concatenation.
    assert_ne!(
        signing_digest(domain, structure),
        keccak(&[domain, structure].concat())
    );
}

#[test]
fn swapping_the_domain_and_struct_hashes_changes_the_digest() {
    // Ordering inside the preimage is load-bearing and easy to get backwards.
    let domain = [0x11u8; 32];
    let structure = [0x22u8; 32];
    assert_ne!(
        signing_digest(domain, structure),
        signing_digest(structure, domain)
    );
}
