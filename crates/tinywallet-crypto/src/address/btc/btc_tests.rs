//! Unit tests for Bitcoin address validation.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{validate, validate_sender};
use crate::{Chain, Error};

/// P2WPKH — native segwit. The only type valid as a sender.
const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
/// P2PKH — legacy. A fine recipient.
const P2PKH: &str = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
/// P2SH — wrapped segwit or multisig. A fine recipient.
const P2SH: &str = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
/// P2WSH — native segwit script hash. A fine recipient.
const P2WSH: &str = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";

#[test]
fn accepts_every_mainnet_address_type_as_a_recipient() {
    for addr in [P2WPKH, P2PKH, P2SH, P2WSH] {
        assert!(validate(addr).is_ok(), "{addr} should validate");
    }
}

#[test]
fn trims_surrounding_whitespace() {
    assert_eq!(validate(&format!("  {P2WPKH}\n")).unwrap(), P2WPKH);
}

#[test]
fn rejects_an_empty_address() {
    assert_eq!(
        validate("  ").unwrap_err(),
        Error::EmptyAddress { chain: Chain::Btc }
    );
}

#[test]
fn rejects_a_malformed_address() {
    assert!(matches!(
        validate("not-an-address").unwrap_err(),
        Error::InvalidAddress { .. }
    ));
}

#[test]
fn rejects_a_mistyped_address_via_its_checksum() {
    // Bitcoin addresses are checksummed, so a single changed character is
    // caught rather than naming a different account.
    let mut chars: Vec<char> = P2PKH.chars().collect();
    chars[5] = if chars[5] == 'a' { 'b' } else { 'a' };
    let typo: String = chars.into_iter().collect();
    assert_ne!(typo, P2PKH, "the fixture must actually differ");
    assert!(
        validate(&typo).is_err(),
        "a checksum failure must be caught"
    );
}

#[test]
fn rejects_a_testnet_address_as_the_wrong_network() {
    // Well-formed, but on the wrong network — a distinct variant because it is
    // the failure a caller is likely to handle rather than merely report.
    let testnet = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    match validate(testnet).unwrap_err() {
        Error::WrongNetwork {
            chain,
            address,
            expected,
            ..
        } => {
            assert_eq!(chain, Chain::Btc);
            assert_eq!(address, testnet);
            assert_eq!(expected, "mainnet");
        }
        other => panic!("expected WrongNetwork, got {other:?}"),
    }
}

#[test]
fn accepts_p2wpkh_as_a_sender() {
    assert_eq!(validate_sender(P2WPKH).unwrap(), P2WPKH);
}

#[test]
fn rejects_every_non_p2wpkh_type_as_a_sender() {
    // These are all valid recipients. The sender rule is strictly narrower
    // because signing is only implemented for P2WPKH.
    for addr in [P2PKH, P2SH, P2WSH] {
        assert!(
            validate(addr).is_ok(),
            "{addr} must remain a valid recipient"
        );
        match validate_sender(addr).unwrap_err() {
            Error::UnsupportedAddressType { chain, address, .. } => {
                assert_eq!(chain, Chain::Btc);
                assert_eq!(address, addr);
            }
            other => panic!("expected UnsupportedAddressType for {addr}, got {other:?}"),
        }
    }
}

#[test]
fn sender_validation_still_reports_the_underlying_failure_first() {
    // A malformed or wrong-network address should not be reported as an
    // unsupported *type* — that would point at the wrong fix.
    assert!(matches!(
        validate_sender("garbage").unwrap_err(),
        Error::InvalidAddress { .. }
    ));
    assert!(matches!(
        validate_sender("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap_err(),
        Error::WrongNetwork { .. }
    ));
    assert!(matches!(
        validate_sender("   ").unwrap_err(),
        Error::EmptyAddress { .. }
    ));
}

// ---------------------------------------------------------------------------
// Branch coverage for the hand-rolled parser.
//
// These are the paths that only exist because this module stopped delegating
// to the `bitcoin` crate. Each one is a rejection, and a rejection that never
// fires is indistinguishable from one that is wrong — so every arm gets a
// vector, drawn from BIP-173 and BIP-350 where they publish one.
// ---------------------------------------------------------------------------

/// P2TR — taproot, witness v1, bech32m. A valid recipient, not a sender.
const P2TR: &str = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";

#[test]
fn accepts_taproot_as_a_recipient_but_not_as_a_sender() {
    // Witness v1 uses bech32m rather than bech32; accepting it proves the
    // checksum variant is selected by version rather than assumed.
    assert_eq!(validate(P2TR).unwrap(), P2TR);
    assert!(matches!(
        validate_sender(P2TR).unwrap_err(),
        Error::UnsupportedAddressType { .. }
    ));
}

#[test]
fn rejects_a_v0_address_carrying_a_bech32m_checksum() {
    // BIP-350's central rule. Both strings below are well-formed bech32-ish;
    // what separates them is which checksum constant they were built with, and
    // accepting the wrong one would accept addresses no other wallet does.
    let v0_with_bech32m = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh";
    assert!(validate(v0_with_bech32m).is_err());
}

#[test]
fn rejects_a_taproot_address_carrying_a_bech32_checksum() {
    // The mirror of the case above: v1 must be bech32m.
    let v1_with_bech32 = "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4";
    assert!(validate(v1_with_bech32).is_err());
}

#[test]
fn rejects_a_witness_program_with_the_wrong_checksum_for_version_three() {
    // BIP-350: witness versions 1..=16 require bech32m, not bech32. This
    // vector decodes to witness version 3, so it is the checksum variant that
    // rejects it, not the program length the old test name claimed.
    let v0_16_bytes = "bc1rw5uspcuh";
    assert!(validate(v0_16_bytes).is_err());
}

#[test]
fn rejects_a_mixed_case_bech32_address() {
    // Mixed case is invalid per BIP-173 because it breaks the checksum's
    // case-folding guarantee.
    let mixed = "bc1QW508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    assert!(validate(mixed).is_err());
}

#[test]
fn reports_a_testnet_base58_address_as_the_wrong_network_not_as_malformed() {
    // A testnet P2PKH is perfectly well-formed; naming it correctly is the
    // difference between a user fixing their address and thinking it is broken.
    let testnet_p2pkh = "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn";
    assert!(matches!(
        validate(testnet_p2pkh).unwrap_err(),
        Error::WrongNetwork { .. }
    ));
}

#[test]
fn reports_a_regtest_bech32_address_as_the_wrong_network() {
    let regtest = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
    assert!(matches!(
        validate(regtest).unwrap_err(),
        Error::WrongNetwork { .. }
    ));
}

#[test]
fn rejects_a_base58_address_with_an_unknown_version_byte() {
    // Valid base58check, valid length, but a version byte that is neither
    // P2PKH nor P2SH on mainnet — a namecoin address, for instance.
    let unknown_version = "NCXn6ZQTr8GN5T4bB1oSHnLRcNPQXswcpv";
    match validate(unknown_version) {
        Err(Error::InvalidAddress { .. } | Error::WrongNetwork { .. }) => {}
        other => panic!("expected a rejection, got {other:?}"),
    }
}

#[test]
fn rejects_a_bech32_address_for_another_coin() {
    // Well-formed bech32 with a human-readable part that is not Bitcoin's.
    let not_bitcoin = "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9";
    assert!(validate(not_bitcoin).is_err());
}

#[test]
fn encodes_a_p2wpkh_address_its_own_validator_accepts() {
    // Closes the loop: what `key::btc` produces must parse back here, and the
    // encoder is the only part of this module the validators do not exercise.
    let pubkey_hash = [0x75u8; 20];
    let encoded = super::encode_p2wpkh(&pubkey_hash).unwrap();
    assert!(encoded.starts_with("bc1q"));
    assert_eq!(validate_sender(&encoded).unwrap(), encoded);
}

/// Encode `version || payload` as base58check, the way a real address is built.
///
/// Constructed rather than copied from a block explorer because these vectors
/// have to be *valid* base58check that is wrong in one specific way — a
/// hand-typed string would fail its checksum first and never reach the rule
/// under test.
fn base58check(version: u8, payload: &[u8]) -> String {
    let mut body = Vec::with_capacity(1 + payload.len());
    body.push(version);
    body.extend_from_slice(payload);
    bs58::encode(body).with_check().into_string()
}

#[test]
fn rejects_a_base58_address_with_an_unrecognised_version_byte() {
    // Valid checksum, 20-byte hash, but a version that is neither P2PKH (0x00)
    // nor P2SH (0x05) on mainnet — a Litecoin P2PKH, for instance.
    let litecoin = base58check(0x30, &[0x11; 20]);
    match validate(&litecoin).unwrap_err() {
        Error::InvalidAddress { reason, .. } => assert!(reason.contains("version"), "{reason}"),
        other => panic!("expected InvalidAddress, got {other:?}"),
    }
}

#[test]
fn rejects_a_base58_address_whose_hash_is_the_wrong_length() {
    // A well-formed base58check envelope around a 19-byte hash. Accepting it
    // would build a transaction paying a script nobody can spend.
    let short = base58check(0x00, &[0x11; 19]);
    match validate(&short).unwrap_err() {
        Error::InvalidAddress { reason, .. } => assert!(reason.contains("20 bytes"), "{reason}"),
        other => panic!("expected InvalidAddress, got {other:?}"),
    }
}

#[test]
fn rejects_an_empty_base58check_payload() {
    // Checksum over nothing at all: there is no version byte to read.
    let empty = bs58::encode(Vec::<u8>::new()).with_check().into_string();
    assert!(validate(&empty).is_err());
}

#[test]
fn reports_a_testnet_p2sh_version_as_the_wrong_network() {
    // 0xc4 is testnet P2SH. The sibling 0x6f (testnet P2PKH) is covered above
    // by a real address; this one completes the pair.
    let testnet_p2sh = base58check(0xc4, &[0x11; 20]);
    assert!(matches!(
        validate(&testnet_p2sh).unwrap_err(),
        Error::WrongNetwork { .. }
    ));
}

#[test]
fn reports_a_foreign_bech32_chain_as_the_wrong_network_not_as_bad_base58() {
    // The check this exercises was unreachable when dispatch matched on a
    // hardcoded `bc1` prefix: a Litecoin bech32 address fell through to the
    // base58 parser and came back with a nonsensical error.
    let litecoin = "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9";
    match validate(litecoin).unwrap_err() {
        Error::WrongNetwork { reason, .. } => {
            assert!(reason.contains("human-readable part"), "{reason}");
        }
        other => panic!("expected WrongNetwork, got {other:?}"),
    }
}
