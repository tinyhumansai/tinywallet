//! Unit tests for key derivation.
//!
//! These are pinned against the canonical BIP-39 test-vector mnemonic and the
//! addresses every mainstream wallet derives from it. That matters more here
//! than in most test suites: a derivation bug does not crash, it produces a
//! *valid key for the wrong account*, and the only way to catch that is to
//! compare against an address derived independently by other software.
//!
//! The mnemonic below is the published all-`abandon` test vector. It is public,
//! and its accounts have been swept continuously for years — never put funds
//! in an address derived from it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{Error, derive};
use crate::chain::Chain;

/// The canonical BIP-39 test vector: 11 × "abandon" + "about".
const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";

/// Standard first-account path per chain, matching each ecosystem's default.
const EVM_PATH: &str = "m/44'/60'/0'/0/0";
const BTC_PATH: &str = "m/84'/0'/0'/0/0";
const TRON_PATH: &str = "m/44'/195'/0'/0/0";
const SOLANA_PATH: &str = "m/44'/501'/0'/0'";

#[test]
fn evm_matches_the_published_test_vector() {
    // This is the address MetaMask, Trust and every EIP-55 tool derive from
    // the vector mnemonic at the standard Ethereum path.
    let key = derive(Chain::Evm, VECTOR, EVM_PATH).unwrap();
    assert_eq!(key.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
    assert_eq!(key.chain(), Chain::Evm);
    assert_eq!(key.secret_bytes().len(), 32);
}

#[test]
fn btc_derives_the_published_native_segwit_vector() {
    // BIP-84's own test vector for account 0, first receive address.
    let key = derive(Chain::Btc, VECTOR, BTC_PATH).unwrap();
    assert_eq!(key.address(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    assert!(
        key.address().starts_with("bc1q"),
        "must be P2WPKH — the only type this crate can sign for"
    );
}

#[test]
fn btc_derives_an_address_its_own_sender_rule_accepts() {
    // The derived address has to satisfy `validate_sender`, not merely
    // `validate`. Deriving a P2PKH here would pass recipient validation and
    // then fail at signing time.
    let key = derive(Chain::Btc, VECTOR, BTC_PATH).unwrap();
    assert!(crate::address::btc::validate_sender(key.address()).is_ok());
}

#[test]
fn solana_derives_the_published_vector() {
    let key = derive(Chain::Solana, VECTOR, SOLANA_PATH).unwrap();
    assert_eq!(
        key.address(),
        "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk"
    );
    assert_eq!(key.chain(), Chain::Solana);
}

#[test]
fn every_chain_derives_an_address_its_own_validator_accepts() {
    // Cheap end-to-end coupling check between `key` and `address`: a
    // derivation that produced a malformed address would be caught here even
    // without a published vector to compare against.
    for (chain, path) in [
        (Chain::Evm, EVM_PATH),
        (Chain::Btc, BTC_PATH),
        (Chain::Tron, TRON_PATH),
        (Chain::Solana, SOLANA_PATH),
    ] {
        let key = derive(chain, VECTOR, path).unwrap();
        assert!(
            crate::address::validate(chain, key.address()).is_ok(),
            "{chain} derived an address its own validator rejects: {}",
            key.address()
        );
        assert_eq!(key.chain(), chain);
        assert_eq!(key.secret_bytes().len(), 32, "{chain} secret length");
    }
}

#[test]
fn tron_derives_a_mainnet_address_not_an_evm_one() {
    // Tron reuses Ethereum's address construction then re-encodes it, so the
    // easy bug is emitting the 20-byte EVM form. It must be 21 bytes with the
    // 0x41 version prefix, in base58check.
    let key = derive(Chain::Tron, VECTOR, TRON_PATH).unwrap();
    assert!(
        key.address().starts_with('T'),
        "expected base58check Tron form, got {}",
        key.address()
    );
    let decoded = crate::address::tron::decode(key.address()).unwrap();
    assert_eq!(decoded.len(), 21);
    assert_eq!(decoded[0], crate::address::tron::MAINNET_PREFIX);
}

#[test]
fn evm_and_tron_share_a_key_but_not_an_address() {
    // Both are secp256k1 + Keccak, so at the same path the secret is identical
    // and only the encoding differs. Pinning this documents why Tron support
    // costs almost nothing beyond an encoder.
    let evm = derive(Chain::Evm, VECTOR, EVM_PATH).unwrap();
    let tron = derive(Chain::Tron, VECTOR, EVM_PATH).unwrap();
    assert_eq!(evm.secret_bytes(), tron.secret_bytes());
    assert_ne!(evm.address(), tron.address());
}

#[test]
fn derivation_is_deterministic() {
    for (chain, path) in [(Chain::Evm, EVM_PATH), (Chain::Solana, SOLANA_PATH)] {
        let first = derive(chain, VECTOR, path).unwrap();
        let second = derive(chain, VECTOR, path).unwrap();
        assert_eq!(first.address(), second.address());
        assert_eq!(first.secret_bytes(), second.secret_bytes());
    }
}

#[test]
fn a_different_path_yields_a_different_account() {
    let first = derive(Chain::Evm, VECTOR, "m/44'/60'/0'/0/0").unwrap();
    let second = derive(Chain::Evm, VECTOR, "m/44'/60'/0'/0/1").unwrap();
    assert_ne!(first.address(), second.address());
    assert_ne!(first.secret_bytes(), second.secret_bytes());
}

#[test]
fn the_mnemonic_is_trimmed_not_rejected_for_surrounding_whitespace() {
    let padded = format!("  {VECTOR}\n");
    let key = derive(Chain::Evm, &padded, EVM_PATH).unwrap();
    assert_eq!(key.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
}

#[test]
fn an_invalid_mnemonic_is_rejected_without_quoting_it() {
    // The error must not echo any part of the phrase — an error string is the
    // easiest way for a secret to reach a log.
    let bad = "abandon abandon notaword abandon abandon abandon \
               abandon abandon abandon abandon abandon about";
    let err = derive(Chain::Evm, bad, EVM_PATH).unwrap_err();
    assert_eq!(err, Error::InvalidMnemonic);
    let rendered = err.to_string();
    assert!(!rendered.contains("notaword"), "leaked a word: {rendered}");
    assert!(!rendered.contains("abandon"), "leaked a word: {rendered}");
}

#[test]
fn a_wrong_length_mnemonic_is_rejected() {
    assert_eq!(
        derive(Chain::Evm, "abandon about", EVM_PATH).unwrap_err(),
        Error::InvalidMnemonic
    );
}

#[test]
fn a_malformed_path_is_rejected_and_names_the_path() {
    // A path is public metadata about which account was meant, so unlike the
    // mnemonic it is safe — and useful — to echo.
    match derive(Chain::Evm, VECTOR, "not-a-path").unwrap_err() {
        Error::InvalidPath { path, .. } => assert_eq!(path, "not-a-path"),
        other => panic!("expected InvalidPath, got {other:?}"),
    }
}

#[test]
fn an_unhardened_solana_path_is_rejected_rather_than_silently_hardened() {
    // The heart of the SLIP-0010 restriction: this path is syntactically fine
    // and simply cannot be derived on ed25519. Hardening it silently would
    // return a DIFFERENT account than the caller named, which is the failure
    // this variant exists to prevent.
    match derive(Chain::Solana, VECTOR, "m/44'/501'/0'/0").unwrap_err() {
        Error::UnhardenedSolanaPath { path } => assert_eq!(path, "m/44'/501'/0'/0"),
        other => panic!("expected UnhardenedSolanaPath, got {other:?}"),
    }
}

#[test]
fn a_solana_path_with_no_segments_is_rejected() {
    assert!(matches!(
        derive(Chain::Solana, VECTOR, "m").unwrap_err(),
        Error::InvalidPath { .. }
    ));
}

#[test]
fn a_solana_path_not_starting_at_m_is_rejected() {
    assert!(matches!(
        derive(Chain::Solana, VECTOR, "44'/501'/0'/0'").unwrap_err(),
        Error::InvalidPath { .. }
    ));
}

#[test]
fn a_solana_path_with_a_non_numeric_segment_is_rejected() {
    match derive(Chain::Solana, VECTOR, "m/44'/not-an-index'/0'").unwrap_err() {
        Error::InvalidPath { path, reason } => {
            assert_eq!(path, "m/44'/not-an-index'/0'");
            assert!(reason.contains("not-an-index"), "{reason}");
        }
        other => panic!("expected InvalidPath, got {other:?}"),
    }
}

#[test]
fn a_solana_path_with_an_already_hardened_index_is_rejected() {
    // `2147483648` is `0x8000_0000`. The caller hardens each segment itself,
    // so an index that already carries the bit would OR to itself and derive
    // the same key as `m/44'/501'/0'` — two visibly different paths, one key.
    assert!(matches!(
        derive(Chain::Solana, VECTOR, "m/44'/501'/2147483648'").unwrap_err(),
        Error::InvalidPath { .. }
    ));
}

#[test]
fn derivation_backend_failures_remain_specific_without_leaking_inputs() {
    // Drives the real derivation path rather than the backend's error mapper.
    // The previous version of this test called two private helpers with a
    // hand-built `bitcoin::bip32::Error`; both are gone, and one of them —
    // the uncompressed-public-key mapper — no longer has a reachable failure
    // mode at all, because the address is now encoded from the compressed
    // SEC1 point directly. Asserting on behaviour instead means this test
    // survives the next backend swap the way it did not survive this one.
    //
    // BIP-32 depth is a single byte, so a path past 255 levels cannot be
    // walked. This must be a clean refusal: the `coins-bip32` backend
    // increments its depth counter unguarded, so without tinywallet's own
    // bound this input panics in debug and — far worse — silently wraps in
    // release, deriving a real key at the wrong depth.
    let too_deep = format!("m/{}", vec!["0"; 256].join("/"));
    let error = derive(Chain::Btc, VECTOR, &too_deep).unwrap_err();

    match &error {
        Error::InvalidPath { path, reason } => {
            assert_eq!(path, &too_deep);
            assert!(reason.contains("255"), "{reason}");
        }
        other => panic!("expected InvalidPath for an over-deep path, got {other:?}"),
    }

    // The depth just under the limit must still derive, so the bound is a
    // guard rather than an off-by-one that rejects legitimate paths.
    let deepest = format!("m/{}", vec!["0"; 255].join("/"));
    assert!(
        derive(Chain::Btc, VECTOR, &deepest).is_ok(),
        "255 levels is the documented maximum and must still derive"
    );

    // The whole point of collapsing backend errors into a fixed `step` string:
    // the mnemonic and the path must not ride out inside the message.
    let rendered = error.to_string();
    for secret in VECTOR.split_whitespace() {
        assert!(
            !rendered.contains(secret),
            "derivation error leaked mnemonic word '{secret}': {rendered}"
        );
    }
}

#[test]
fn debug_never_prints_key_material() {
    // A derived Debug here would put a private key into every panic message
    // and every log line that formats a struct containing one.
    let key = derive(Chain::Evm, VECTOR, EVM_PATH).unwrap();
    let rendered = format!("{key:?}");

    assert!(rendered.contains("<redacted>"), "{rendered}");
    assert!(rendered.contains(key.address()), "address is safe to show");

    // The secret must not appear in any plausible encoding.
    let hex = key.secret_bytes().iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    });
    assert!(!rendered.contains(&hex), "leaked the secret as hex");
    assert!(
        !rendered.contains(&format!("{:?}", key.secret_bytes())),
        "leaked the secret as a byte slice"
    );
}
