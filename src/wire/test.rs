//! Tests for the host/backend wire contract.
//!
//! These are contract tests, not logic tests: the module holds no behaviour.
//! What can break here is compatibility — a field renamed, a tag changed, an
//! enum representation altered — and each of those breaks a host and a backend
//! that were built from different revisions, at runtime, with a deserialization
//! error rather than a compile failure. So the shapes are pinned literally.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;

use super::{
    AttachRequest, PublicKey, Scheme, Signature, SignedTransaction, SigningPayload, SigningRequest,
    TransactionSpec, UnsignedTransaction, Utxo,
};

#[test]
fn a_signing_request_round_trips_through_json() {
    let request = SigningRequest {
        transaction: TransactionSpec::Evm {
            to: "0x1111111111111111111111111111111111111111".to_string(),
            value_wei: "1000".to_string(),
            data_hex: "0x".to_string(),
            nonce: 7,
            gas_limit: 21_000,
            gas_price_wei: "20000000000".to_string(),
            chain_id: 1,
        },
        public_key: PublicKey {
            key_hex: "02".repeat(33),
        },
    };

    let encoded = serde_json::to_string(&request).unwrap();
    let decoded: SigningRequest = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, request);
}

#[test]
fn the_transaction_spec_tag_is_the_published_one() {
    // A host and a backend from different revisions meet here. The tag and the
    // field names are the contract, so they are asserted against literals
    // rather than against a re-serialization of the same value, which would
    // agree with itself no matter what it was renamed to.
    let spec = TransactionSpec::Solana {
        from: "11111111111111111111111111111112".to_string(),
        to: "11111111111111111111111111111113".to_string(),
        lamports: 5,
        recent_blockhash: "11111111111111111111111111111114".to_string(),
    };
    assert_eq!(
        serde_json::to_value(&spec).unwrap(),
        json!({
            "kind": "solana",
            "from": "11111111111111111111111111111112",
            "to": "11111111111111111111111111111113",
            "lamports": 5,
            "recent_blockhash": "11111111111111111111111111111114",
        })
    );
}

#[test]
fn a_signature_is_tagged_by_its_scheme() {
    assert_eq!(
        serde_json::to_value(Signature::Secp256k1 {
            rs_hex: "ab".repeat(64),
            recovery_id: 1,
        })
        .unwrap(),
        json!({ "scheme": "secp256k1", "rs_hex": "ab".repeat(64), "recovery_id": 1 })
    );
    assert_eq!(
        serde_json::to_value(Signature::Ed25519 {
            signature_hex: "cd".repeat(64),
        })
        .unwrap(),
        json!({ "scheme": "ed25519", "signature_hex": "cd".repeat(64) })
    );
}

#[test]
fn an_ed25519_signature_cannot_deserialize_as_a_secp256k1_one() {
    // The enum is tagged precisely so a host cannot return the wrong scheme's
    // signature and have it fail deep inside reassembly instead of at the
    // boundary.
    let ed = json!({ "scheme": "ed25519", "signature_hex": "cd".repeat(64) });
    let decoded: Signature = serde_json::from_value(ed).unwrap();
    assert!(matches!(decoded, Signature::Ed25519 { .. }));
}

#[test]
fn unknown_fields_are_refused_rather_than_ignored() {
    // A backend newer than its host would otherwise silently drop a field it
    // was told about, which for a transaction means signing something other
    // than what was asked for.
    let with_extra = json!({
        "txid": "aa".repeat(32),
        "vout": 0,
        "value": 1000,
        "surprise": true,
    });
    assert!(serde_json::from_value::<Utxo>(with_extra).is_err());
}

#[test]
fn the_signing_scheme_names_are_stable() {
    assert_eq!(
        serde_json::to_value(Scheme::Secp256k1Prehash).unwrap(),
        json!("secp256k1_prehash")
    );
    assert_eq!(
        serde_json::to_value(Scheme::Ed25519).unwrap(),
        json!("ed25519")
    );
}

#[test]
fn an_attach_request_carries_one_signature_per_payload() {
    // Not a rule the type can enforce, but the pairing is the contract: the
    // Bitcoin path returns one payload per selected input and expects them
    // back in the same order.
    let unsigned = UnsignedTransaction {
        payloads: vec![
            SigningPayload {
                bytes_hex: "11".repeat(32),
                scheme: Scheme::Secp256k1Prehash,
            },
            SigningPayload {
                bytes_hex: "22".repeat(32),
                scheme: Scheme::Secp256k1Prehash,
            },
        ],
    };
    let attach = AttachRequest {
        transaction: TransactionSpec::Btc {
            from: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
            amount_sat: 1_000,
            fee_sat: 5,
            utxos: vec![],
        },
        public_key: PublicKey {
            key_hex: "02".repeat(33),
        },
        signatures: vec![
            Signature::Secp256k1 {
                rs_hex: "ab".repeat(64),
                recovery_id: 0,
            },
            Signature::Secp256k1 {
                rs_hex: "cd".repeat(64),
                recovery_id: 1,
            },
        ],
    };
    assert_eq!(attach.signatures.len(), unsigned.payloads.len());

    let encoded = serde_json::to_string(&attach).unwrap();
    assert_eq!(
        serde_json::from_str::<AttachRequest>(&encoded).unwrap(),
        attach
    );
}

#[test]
fn a_signed_transaction_may_omit_a_locally_unknowable_txid() {
    let signed = SignedTransaction {
        raw: "0xdeadbeef".to_string(),
        txid: None,
    };
    let encoded = serde_json::to_string(&signed).unwrap();
    assert_eq!(
        serde_json::from_str::<SignedTransaction>(&encoded).unwrap(),
        signed
    );
}

#[test]
fn every_transaction_names_its_own_chain() {
    // `chain()` is the single source of truth now that the requests carry no
    // `chain` field, so a wrong arm here would route a transaction to the
    // wrong chain's builder — with a real key already loaded.
    use crate::chain::Chain;

    let cases = [
        (
            TransactionSpec::Btc {
                from: String::new(),
                to: String::new(),
                amount_sat: 0,
                fee_sat: 0,
                utxos: Vec::new(),
            },
            Chain::Btc,
        ),
        (
            TransactionSpec::Evm {
                to: String::new(),
                value_wei: "0".to_string(),
                data_hex: String::new(),
                nonce: 0,
                gas_limit: 0,
                gas_price_wei: "0".to_string(),
                chain_id: 1,
            },
            Chain::Evm,
        ),
        (
            TransactionSpec::Solana {
                from: String::new(),
                to: String::new(),
                lamports: 0,
                recent_blockhash: String::new(),
            },
            Chain::Solana,
        ),
        (
            TransactionSpec::Tron {
                raw_data_hex: String::new(),
                expected_to: String::new(),
                expected_txid: String::new(),
            },
            Chain::Tron,
        ),
    ];

    for (spec, expected) in cases {
        assert_eq!(spec.chain(), expected);
    }
}
