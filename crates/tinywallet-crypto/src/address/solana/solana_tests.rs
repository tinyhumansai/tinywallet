//! Unit tests for Solana address validation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{ADDRESS_BYTES, decode, encode, validate};
use crate::{Chain, Error};

/// The system program id: 32 zero bytes.
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
/// The SPL token program id — a real 32-byte key with a full alphabet.
const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

#[test]
fn accepts_real_addresses() {
    for addr in [SYSTEM_PROGRAM, TOKEN_PROGRAM] {
        assert_eq!(validate(addr).unwrap(), addr);
    }
}

#[test]
fn trims_surrounding_whitespace() {
    assert_eq!(
        validate(&format!("  {TOKEN_PROGRAM}\n")).unwrap(),
        TOKEN_PROGRAM
    );
}

#[test]
fn rejects_an_empty_address() {
    assert_eq!(
        validate("   ").unwrap_err(),
        Error::EmptyAddress {
            chain: Chain::Solana
        }
    );
}

#[test]
fn rejects_characters_outside_the_base58_alphabet() {
    // `0`, `O`, `I` and `l` are excluded from base58 precisely because they
    // are visually ambiguous.
    for bad in ["0OIl", "hello world", "not!base58"] {
        match validate(bad).unwrap_err() {
            Error::InvalidAddress { chain, reason, .. } => {
                assert_eq!(chain, Chain::Solana);
                assert!(reason.contains("base58"), "reason was {reason:?}");
            }
            other => panic!("expected InvalidAddress for {bad:?}, got {other:?}"),
        }
    }
}

#[test]
fn rejects_a_decoded_length_other_than_32_bytes() {
    // Valid base58, wrong length — the check a base58 decode alone misses.
    let short = encode_arbitrary(&[1u8; 16]);
    match validate(&short).unwrap_err() {
        Error::InvalidAddress { reason, .. } => {
            assert!(reason.contains("32"), "reason was {reason:?}");
            assert!(
                reason.contains("16"),
                "reason should report the actual length"
            );
        }
        other => panic!("expected InvalidAddress, got {other:?}"),
    }

    let long = encode_arbitrary(&[1u8; 33]);
    assert!(validate(&long).is_err());
}

#[test]
fn decode_returns_the_raw_key_bytes() {
    assert_eq!(decode(SYSTEM_PROGRAM).unwrap(), [0u8; ADDRESS_BYTES]);
}

#[test]
fn encode_and_decode_round_trip() {
    let mut bytes = [0u8; ADDRESS_BYTES];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::try_from(i).unwrap();
    }
    assert_eq!(decode(&encode(&bytes)).unwrap(), bytes);
}

#[test]
fn decode_rejects_exactly_what_validate_rejects() {
    // The two share a code path; this pins that they cannot drift apart.
    for input in ["", "   ", "0OIl", &encode_arbitrary(&[7u8; 31])] {
        assert_eq!(
            validate(input).is_err(),
            decode(input).is_err(),
            "validate and decode disagreed on {input:?}"
        );
    }
}

#[test]
fn a_single_character_typo_is_not_caught() {
    // Documenting a real property of the chain, not endorsing it: Solana
    // addresses carry no checksum, so a typo usually yields another valid
    // address. Callers must confirm addresses out of band.
    let mut chars: Vec<char> = TOKEN_PROGRAM.chars().collect();
    chars[4] = if chars[4] == 'a' { 'b' } else { 'a' };
    let typo: String = chars.into_iter().collect();
    assert_ne!(typo, TOKEN_PROGRAM);
    assert!(
        validate(&typo).is_ok(),
        "a Solana typo is indistinguishable from a real address"
    );
}

/// Base58-encode arbitrary bytes, bypassing the 32-byte contract, so tests can
/// build wrong-length-but-valid-base58 inputs.
fn encode_arbitrary(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}
