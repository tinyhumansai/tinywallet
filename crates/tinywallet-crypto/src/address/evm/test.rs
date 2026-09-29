//! Unit tests for EVM address validation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::validate;
use crate::{Chain, Error};

/// The four EIP-55 test vectors from the specification.
const EIP55_VECTORS: [&str; 4] = [
    "0x52908400098527886E0F7030069857D2E4169EE7",
    "0x8617E340B3D01FA5F11F306F4090FD50E238070D",
    "0xde709f2102306220921060314715629080e2fb77",
    "0x27b1fdb04752bbc536007a920d24acb045561c26",
];

#[test]
fn accepts_a_prefixed_address() {
    assert_eq!(
        validate("0x52908400098527886E0F7030069857D2E4169EE7").unwrap(),
        "0x52908400098527886E0F7030069857D2E4169EE7"
    );
}

#[test]
fn accepts_an_unprefixed_address() {
    let bare = "52908400098527886E0F7030069857D2E4169EE7";
    assert_eq!(validate(bare).unwrap(), bare);
}

#[test]
fn rejects_an_uppercase_prefix() {
    // No tooling emits `0X`, so accepting it would widen what counts as an
    // address for no benefit. It falls out as a length failure: `0X…` is 42
    // characters once the prefix is not stripped.
    assert!(matches!(
        validate("0X52908400098527886E0F7030069857D2E4169EE7").unwrap_err(),
        Error::InvalidAddress { .. }
    ));
}

#[test]
fn preserves_the_input_rather_than_normalising_it() {
    // Callers echo the returned address back to users, so changing its case or
    // stripping its prefix would silently alter what they typed.
    let lower = "0x52908400098527886e0f7030069857d2e4169ee7";
    assert_eq!(validate(lower).unwrap(), lower);
}

#[test]
fn trims_surrounding_whitespace() {
    assert_eq!(
        validate("  0x52908400098527886E0F7030069857D2E4169EE7\n").unwrap(),
        "0x52908400098527886E0F7030069857D2E4169EE7"
    );
}

#[test]
fn rejects_an_empty_address() {
    assert_eq!(
        validate("   ").unwrap_err(),
        Error::EmptyAddress { chain: Chain::Evm }
    );
}

#[test]
fn rejects_a_short_address() {
    match validate("0xdeadbeef").unwrap_err() {
        Error::InvalidAddress { chain, reason, .. } => {
            assert_eq!(chain, Chain::Evm);
            assert!(reason.contains("got 8"), "reason was {reason:?}");
        }
        other => panic!("expected InvalidAddress, got {other:?}"),
    }
}

#[test]
fn rejects_a_long_address() {
    let long = format!("0x{}", "a".repeat(41));
    assert!(matches!(
        validate(&long).unwrap_err(),
        Error::InvalidAddress { .. }
    ));
}

#[test]
fn rejects_a_non_hex_character() {
    // 40 characters, but `z` is not hex — a length check alone would pass it.
    let bad = format!("0x{}z", "a".repeat(39));
    match validate(&bad).unwrap_err() {
        Error::InvalidAddress { reason, .. } => {
            assert!(
                reason.contains('z'),
                "reason should name the char: {reason:?}"
            );
        }
        other => panic!("expected InvalidAddress, got {other:?}"),
    }
}

#[test]
fn the_error_carries_the_rejected_address_verbatim() {
    // Diagnosing a rejection means seeing exactly what was rejected.
    match validate("0xnope").unwrap_err() {
        Error::InvalidAddress { address, .. } => assert_eq!(address, "0xnope"),
        other => panic!("expected InvalidAddress, got {other:?}"),
    }
}

#[test]
fn accepts_every_eip55_vector_regardless_of_case() {
    // Validation is case-insensitive: an unchecksummed lowercase address is
    // valid, just unchecksummed.
    for vector in EIP55_VECTORS {
        assert!(validate(vector).is_ok(), "{vector} should validate");
        assert!(validate(&vector.to_lowercase()).is_ok());
    }
}

#[cfg(feature = "keccak")]
mod checksum {
    use super::EIP55_VECTORS;
    use crate::address::evm::{is_checksum_valid, to_checksummed};

    #[test]
    fn canonicalises_every_eip55_vector() {
        for vector in EIP55_VECTORS {
            assert_eq!(
                to_checksummed(&vector.to_lowercase()).unwrap(),
                *vector,
                "EIP-55 vector {vector} did not round-trip"
            );
        }
    }

    #[test]
    fn accepts_a_correctly_checksummed_address() {
        for vector in EIP55_VECTORS {
            assert!(is_checksum_valid(vector).unwrap(), "{vector}");
        }
    }

    #[test]
    fn rejects_a_wrongly_cased_address() {
        // Flip the case of one letter in a checksummed vector.
        let vector = "0x52908400098527886E0F7030069857D2E4169EE7";
        let broken = vector.replacen('E', "e", 1);
        assert_ne!(broken, vector, "the fixture must actually differ");
        assert!(!is_checksum_valid(&broken).unwrap());
    }

    #[test]
    fn reports_an_all_lowercase_address_as_unchecksummed() {
        // Not a failure of validity — it simply carries no checksum data.
        let lower = "0x52908400098527886e0f7030069857d2e4169ee7";
        assert!(crate::address::evm::validate(lower).is_ok());
        assert!(!is_checksum_valid(lower).unwrap());
    }

    #[test]
    fn checksumming_is_idempotent() {
        for vector in EIP55_VECTORS {
            let once = to_checksummed(vector).unwrap();
            assert_eq!(to_checksummed(&once).unwrap(), once);
        }
    }

    #[test]
    fn checksumming_accepts_an_unprefixed_address_and_adds_the_prefix() {
        let bare = "52908400098527886e0f7030069857d2e4169ee7";
        assert_eq!(
            to_checksummed(bare).unwrap(),
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
    }

    #[test]
    fn checksum_helpers_reject_a_malformed_address() {
        assert!(to_checksummed("0xdeadbeef").is_err());
        assert!(is_checksum_valid("0xdeadbeef").is_err());
    }
}
