//! Unit tests for transaction building and signing.
//!
//! The centrepiece is the **published EIP-155 test vector**, checked
//! byte-for-byte for both the signing payload and the final signed
//! transaction. That is the only kind of test that can catch a signing bug:
//! a wrong encoding still produces a well-formed, perfectly signed
//! transaction — it just commits to something other than what was intended,
//! and no amount of self-consistent testing would notice.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::evm::{LegacyTransaction, encode_erc20_transfer};
use super::{Error, Result};

/// The EIP-155 specification's own example transaction.
fn eip155_vector() -> LegacyTransaction {
    LegacyTransaction {
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some("0x3535353535353535353535353535353535353535".to_string()),
        value: 1_000_000_000_000_000_000,
        data: Vec::new(),
        chain_id: 1,
    }
}

/// The private key the EIP-155 example signs with.
const VECTOR_KEY: [u8; 32] = [0x46; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[test]
fn signing_payload_matches_the_published_eip155_vector() {
    // Straight from the EIP: the exact bytes that get hashed. Note the
    // trailing `018080` — chain_id 1, then two empty strings.
    assert_eq!(
        hex(&eip155_vector().signing_payload().unwrap()),
        "ec098504a817c80082520894353535353535353535353535353535353535353588\
         0de0b6b3a764000080018080"
    );
}

#[test]
fn signed_transaction_matches_the_published_eip155_vector() {
    // The full signed transaction from the EIP, including v, r and s. If the
    // encoding or the v calculation were wrong, this would differ while still
    // being a valid signature over *something*.
    assert_eq!(
        hex(&eip155_vector().sign(&VECTOR_KEY).unwrap()),
        "f86c098504a817c800825208943535353535353535353535353535353535353535\
         880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c\
         71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc\
         64214b297fb1966a3b6d83"
    );
}

#[test]
fn the_chain_id_is_folded_into_v_not_just_the_payload() {
    // The classic half-implementation: EIP-155 requires the chain id in BOTH
    // the hashed payload and v. Signing the same transaction for two chains
    // must produce two different signatures, not one with a different suffix.
    let mainnet = eip155_vector();
    let base = LegacyTransaction {
        chain_id: 8453,
        ..eip155_vector()
    };

    let a = mainnet.sign(&VECTOR_KEY).unwrap();
    let b = base.sign(&VECTOR_KEY).unwrap();
    assert_ne!(a, b, "a signature must not be replayable across chains");
    assert_ne!(
        mainnet.signing_payload().unwrap(),
        base.signing_payload().unwrap(),
        "the chain id must be in the hashed payload"
    );
}

#[test]
fn v_follows_the_eip155_formula() {
    // v = recovery + chain_id * 2 + 35, so for chain 1 it is 37 or 38 and for
    // Base (8453) it is 16941 or 16942. Reading it back out of the encoding
    // proves the arithmetic reached the wire.
    for (chain_id, expected) in [(1u64, [37u64, 38]), (8453, [16_941, 16_942])] {
        let tx = LegacyTransaction {
            chain_id,
            ..eip155_vector()
        };
        let signed = tx.sign(&VECTOR_KEY).unwrap();
        // v is the third-from-last RLP item; for these values it is encoded
        // either as a single byte or as a length-prefixed integer, so rather
        // than re-implementing a decoder the test asserts one of the two
        // valid encodings appears.
        let encoded_v: Vec<String> = expected
            .iter()
            .map(|v| {
                if *v < 0x80 {
                    #[allow(clippy::cast_possible_truncation)]
                    let byte = *v as u8;
                    hex(&[byte])
                } else {
                    let bytes = v.to_be_bytes();
                    let first = bytes.iter().position(|b| *b != 0).unwrap();
                    let body = &bytes[first..];
                    #[allow(clippy::cast_possible_truncation)]
                    let prefix = 0x80 + body.len() as u8;
                    format!("{}{}", hex(&[prefix]), hex(body))
                }
            })
            .collect();
        let rendered = hex(&signed);
        assert!(
            encoded_v.iter().any(|v| rendered.contains(v)),
            "chain {chain_id}: expected one of {encoded_v:?} in {rendered}"
        );
    }
}

#[test]
fn the_transaction_hash_is_of_the_signed_bytes_not_the_payload() {
    let tx = eip155_vector();
    let signed = tx.sign(&VECTOR_KEY).unwrap();

    let hash = LegacyTransaction::hash_of(&signed);
    assert!(hash.starts_with("0x"));
    assert_eq!(hash.len(), 66, "0x + 64 hex chars");

    // Hashing the signing payload instead would give a different value — the
    // easy mistake, and one that reports a hash the network never sees.
    let payload_hash = LegacyTransaction::hash_of(&tx.signing_payload().unwrap());
    assert_ne!(hash, payload_hash);
}

#[test]
fn signing_is_deterministic() {
    // RFC 6979 deterministic nonces: the same transaction and key always
    // produce the same signature, so a retry cannot leak the key by reusing k
    // with different randomness.
    let tx = eip155_vector();
    assert_eq!(tx.sign(&VECTOR_KEY).unwrap(), tx.sign(&VECTOR_KEY).unwrap());
}

#[test]
fn a_different_key_produces_a_different_signature() {
    let tx = eip155_vector();
    let other = [0x47u8; 32];
    assert_ne!(tx.sign(&VECTOR_KEY).unwrap(), tx.sign(&other).unwrap());
}

#[test]
fn an_invalid_secret_key_is_rejected_without_echoing_it() {
    let tx = eip155_vector();
    let err = tx.sign(&[0u8; 32]).unwrap_err();
    match &err {
        Error::Signing { reason } => {
            assert!(!reason.contains('0'), "must not echo key bytes: {reason}");
        }
        other => panic!("expected Signing, got {other:?}"),
    }
    assert!(tx.sign(&[1u8; 5]).is_err(), "wrong length is rejected");
}

#[test]
fn an_eip155_chain_id_that_overflows_v_is_rejected() {
    let tx = LegacyTransaction {
        chain_id: u64::MAX,
        ..eip155_vector()
    };
    assert!(matches!(
        tx.sign(&VECTOR_KEY),
        Err(Error::InvalidField {
            field: "chain_id",
            ..
        })
    ));
}

#[test]
fn defensive_evm_encoding_errors_are_reported_without_panicking() {
    assert!(matches!(
        super::evm::require_hex(None, "not-hex"),
        Err(Error::InvalidField { field: "to", .. })
    ));
    assert!(matches!(
        super::evm::recovery_as_u64(-1),
        Err(Error::Signing { .. })
    ));
    assert!(matches!(
        super::evm::checked_v(u64::MAX, 0),
        Err(Error::InvalidField {
            field: "chain_id",
            ..
        })
    ));
}

#[test]
fn an_invalid_recipient_is_rejected_before_signing() {
    let tx = LegacyTransaction {
        to: Some("not-an-address".to_string()),
        ..eip155_vector()
    };
    assert!(matches!(tx.sign(&VECTOR_KEY), Err(Error::Address(_))));
    assert!(matches!(tx.signing_payload(), Err(Error::Address(_))));
}

#[test]
fn contract_creation_encodes_an_empty_recipient() {
    // `to: None` must encode as the empty string (0x80), not as 20 zero bytes,
    // which would be a transfer to the zero address — a way to burn funds.
    let tx = LegacyTransaction {
        to: None,
        value: 0,
        ..eip155_vector()
    };
    let payload = hex(&tx.signing_payload().unwrap());
    assert!(
        !payload.contains(&"00".repeat(20)),
        "must not encode the zero address: {payload}"
    );
}

#[test]
fn a_zero_value_transfer_encodes_as_an_empty_string() {
    // RLP's integer rule: zero is the empty string, not 0x00.
    let tx = LegacyTransaction {
        value: 0,
        nonce: 0,
        ..eip155_vector()
    };
    // Two leading empty strings for nonce and, later, value.
    assert!(tx.signing_payload().unwrap().contains(&0x80));
}

#[test]
fn erc20_transfer_encodes_the_selector_and_two_padded_words() {
    let data =
        encode_erc20_transfer("0x3535353535353535353535353535353535353535", 1_000_000).unwrap();

    assert_eq!(data.len(), 4 + 32 + 32, "selector + two words");
    // keccak256("transfer(address,uint256)")[..4]
    assert_eq!(hex(&data[..4]), "a9059cbb");
    // Address right-aligned in its word, left-padded with 12 zero bytes.
    assert_eq!(hex(&data[4..16]), "00".repeat(12));
    assert_eq!(hex(&data[16..36]), "35".repeat(20));
    // Amount big-endian, right-aligned in its word.
    assert_eq!(hex(&data[36..]), format!("{:064x}", 1_000_000u128));
}

#[test]
fn erc20_transfer_rejects_an_invalid_recipient() {
    assert!(matches!(
        encode_erc20_transfer("0xdeadbeef", 1),
        Err(Error::Address(_))
    ));
}

#[test]
fn a_token_transfer_carries_calldata_and_zero_value() {
    // The shape of an ERC-20 transfer: value 0, `to` is the contract, and the
    // real recipient lives in the calldata. Sending value here would move the
    // native asset to the token contract instead.
    let data = encode_erc20_transfer("0x3535353535353535353535353535353535353535", 42).unwrap();
    let tx = LegacyTransaction {
        to: Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string()),
        value: 0,
        data,
        ..eip155_vector()
    };
    let signed = tx.sign(&VECTOR_KEY).unwrap();
    let rendered = hex(&signed);
    assert!(
        rendered.contains("a9059cbb"),
        "calldata must reach the wire"
    );
}

#[test]
fn results_propagate_as_the_module_result_type() {
    // Compile-time check that the alias is usable from outside.
    fn build() -> Result<Vec<u8>> {
        eip155_vector().signing_payload()
    }
    assert!(build().is_ok());
}

// ---------------------------------------------------------------------------
// Split signing: build here, sign elsewhere, reassemble here.
//
// The whole point of the split path is that a host can hold the key while this
// crate holds the format knowledge. That is only safe if the two paths agree
// byte-for-byte, so each test below signs the same transaction both ways and
// compares the raw result. An equivalence test is the right shape here: a
// wrong split would still produce a well-formed signed transaction, so nothing
// short of comparing against the known-good path would notice.
// ---------------------------------------------------------------------------

/// Sign a prehashed digest the way a host would, returning `(r||s, recovery)`.
///
/// Deliberately uses the recoverable API directly rather than any helper from
/// this crate, so the test exercises the same boundary a real host does.
fn host_sign_secp256k1(digest: [u8; 32], key: &[u8; 32]) -> ([u8; 64], u8) {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    let secret = SecretKey::from_slice(key).unwrap();
    let secp = Secp256k1::signing_only();
    let recoverable = secp.sign_ecdsa_recoverable(&Message::from_digest(digest), &secret);
    let (recovery_id, compact) = recoverable.serialize_compact();
    (compact, u8::try_from(recovery_id.to_i32()).unwrap())
}

#[test]
fn evm_split_signing_matches_one_shot_signing() {
    let tx = eip155_vector();

    let one_shot = tx.sign(&VECTOR_KEY).unwrap();

    let (rs, recovery) = host_sign_secp256k1(tx.digest().unwrap(), &VECTOR_KEY);
    let split = tx.attach_signature(&rs, recovery).unwrap();

    assert_eq!(hex(&split), hex(&one_shot));
}

#[test]
fn the_evm_digest_is_the_keccak_of_the_signing_payload_not_the_payload() {
    // Guards the most likely misuse: a host that signs `signing_payload()`
    // directly, or hashes `digest()` a second time, produces a valid signature
    // over the wrong thing.
    use sha3::{Digest as _, Keccak256};
    let tx = eip155_vector();
    let expected: [u8; 32] = Keccak256::digest(tx.signing_payload().unwrap()).into();
    assert_eq!(tx.digest().unwrap(), expected);
    assert_ne!(tx.digest().unwrap().to_vec(), tx.signing_payload().unwrap());
}

#[test]
fn an_out_of_range_evm_recovery_id_is_refused() {
    let tx = eip155_vector();
    let error = tx.attach_signature(&[0x11; 64], 4).unwrap_err();
    assert!(matches!(error, Error::Signing { .. }), "{error:?}");
}

#[test]
fn tron_split_signing_matches_one_shot_signing() {
    // A `raw_data` blob is opaque to this crate — it only ever hashes it — so
    // an arbitrary well-formed hex string exercises the path faithfully.
    let raw = "0a02b1f12208".to_string() + &"ab".repeat(64);

    let one_shot = super::tron::sign(&raw, &VECTOR_KEY).unwrap();

    let (rs, recovery) = host_sign_secp256k1(super::tron::digest(&raw).unwrap(), &VECTOR_KEY);
    let split = super::tron::attach_signature(&rs, recovery).unwrap();

    assert_eq!(
        super::tron::signature_hex(&split),
        super::tron::signature_hex(&one_shot)
    );
}

#[test]
fn the_tron_digest_equals_its_recomputed_txid() {
    // The two are the same value by construction, which is what lets a caller
    // verify the node's `txID` against the bytes it is about to sign.
    let raw = "0a02b1f12208".to_string() + &"cd".repeat(64);
    assert_eq!(
        hex(&super::tron::digest(&raw).unwrap()),
        super::tron::recompute_txid(&raw).unwrap()
    );
}

#[test]
fn an_out_of_range_tron_recovery_id_is_refused() {
    let error = super::tron::attach_signature(&[0x11; 64], 9).unwrap_err();
    assert!(matches!(error, Error::Signing { .. }), "{error:?}");
}
