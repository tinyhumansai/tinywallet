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
    AttachRequest, EncodeErc20TransferRequest, EncodeErc20TransferResponse,
    GenerateMnemonicRequest, GenerateMnemonicResponse, PublicKey, Scheme, Signature,
    SignedTransaction, SigningPayload, SigningRequest, TransactionSpec, UnsignedTransaction, Utxo,
    WalletChain, Web3QuoteKind, Web3QuoteResponse,
};

#[test]
fn erc20_encoding_wire_shape_is_explicit_and_round_trips() {
    let request = EncodeErc20TransferRequest {
        to_address: "0x1111111111111111111111111111111111111111".into(),
        amount_raw: "1000000".into(),
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(
        encoded,
        json!({
            "to_address": "0x1111111111111111111111111111111111111111",
            "amount_raw": "1000000"
        })
    );
    assert_eq!(
        serde_json::from_value::<EncodeErc20TransferRequest>(encoded).unwrap(),
        request
    );

    let response = EncodeErc20TransferResponse {
        calldata: format!(
            "0xa9059cbb{}{}{}{}",
            "0".repeat(24),
            "11".repeat(20),
            "0".repeat(63),
            "1"
        ),
    };
    let encoded = serde_json::to_value(&response).unwrap();
    assert_eq!(encoded["calldata"], response.calldata);
    assert_eq!(
        serde_json::from_value::<EncodeErc20TransferResponse>(encoded).unwrap(),
        response
    );
}

#[test]
fn mnemonic_generation_wire_shape_is_explicit_and_secret_marked_by_member() {
    let request = GenerateMnemonicRequest { word_count: 24 };
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        json!({ "word_count": 24 })
    );
    let response = GenerateMnemonicResponse {
        phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
        word_count: 12,
    };
    assert!(!format!("{response:?}").contains("abandon"));
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        json!({
            "phrase": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "word_count": 12
        })
    );
}

#[test]
fn mnemonic_seed_wire_types_redact_secret_debug_and_keep_the_seed_byte_shape() {
    use super::{DeriveMnemonicSeedRequest, DeriveMnemonicSeedResponse};

    let request = DeriveMnemonicSeedRequest {
        mnemonic: "secret recovery phrase".into(),
    };
    let response = DeriveMnemonicSeedResponse {
        seed: vec![0x5e; 64],
    };

    assert!(!format!("{request:?}").contains("secret recovery phrase"));
    assert_eq!(
        format!("{response:?}"),
        "DeriveMnemonicSeedResponse { seed: \"<redacted>\" }"
    );
    let encoded = serde_json::to_value(&response).expect("seed response serializes");
    assert_eq!(encoded["seed"].as_array().map(Vec::len), Some(64));
    assert_eq!(
        serde_json::from_value::<DeriveMnemonicSeedResponse>(encoded).unwrap(),
        response
    );
}

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
fn web3_quote_response_publishes_module_selected_signing_chain() {
    let response = Web3QuoteResponse {
        quote_id: "quote-1".into(),
        kind: Web3QuoteKind::Bridge,
        expires_at_ms: 1234,
        signing_chain: WalletChain::Solana,
        quote: json!({"provider": "summary"}),
    };
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(
        encoded,
        json!({
            "quoteId": "quote-1",
            "kind": "bridge",
            "expiresAtMs": 1234,
            "signingChain": "solana",
            "quote": {"provider": "summary"}
        })
    );
    assert!(
        serde_json::from_value::<Web3QuoteResponse>(json!({
            "quoteId": "quote-1",
            "kind": "bridge",
            "expiresAtMs": 1234,
            "quote": {"provider": "summary"}
        }))
        .is_err(),
        "hosts must not infer a missing signing chain from provider data"
    );
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

    // And the converse: an ed25519-length signature labelled `secp256k1` is
    // refused at the boundary rather than accepted and failed later.
    let mismatched = json!({
        "scheme": "secp256k1",
        "signature_hex": "cd".repeat(64)
    });
    assert!(serde_json::from_value::<Signature>(mismatched).is_err());
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
    use crate::Chain;

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
                transfer: super::TronTransfer::Native { amount_sun: 0 },
            },
            Chain::Tron,
        ),
    ];

    for (spec, expected) in cases {
        assert_eq!(spec.chain(), expected);
    }
}

#[test]
fn address_validation_errors_preserve_wire_and_share_implementation_types() {
    use super::ValidateAddressResponse;
    use crate::{Chain, Error};
    let reply = ValidateAddressResponse {
        result: Err(Error::EmptyAddress { chain: Chain::Evm }),
    };
    let wire = serde_json::to_value(&reply).unwrap();
    assert_eq!(
        wire,
        serde_json::json!({"result":{"Err":{"EmptyAddress":{"chain":"evm"}}}})
    );
    assert_eq!(
        serde_json::from_value::<ValidateAddressResponse>(wire).unwrap(),
        reply
    );
}

#[test]
fn address_validation_rejects_misspelled_sender_and_preserves_default_recipient() {
    let request = serde_json::json!({"chain":"btc", "address":"1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "is_sender":true});
    assert!(serde_json::from_value::<super::ValidateAddressRequest>(request).is_err());
    let recipient: super::ValidateAddressRequest =
        serde_json::from_value(serde_json::json!({"chain":"btc", "address":"fixture"})).unwrap();
    assert!(!recipient.sender);
}

#[test]
fn x402_chain_secret_extension_preserves_legacy_serialization() {
    let legacy = json!({
        "service": {"handle": "fixture"},
        "url": "https://fixture.invalid/resource",
        "payment_required": "encoded-challenge",
        "secret": {
            "mnemonic": "secret phrase",
            "derivation_path": "m/44'/60'/0'/0/0",
            "chain": "evm"
        }
    });
    let request: super::X402PreparePaymentRequest = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(request).unwrap(), legacy);
}

#[test]
fn an_x402_authorization_names_its_scheme_and_older_hosts_still_parse_it() {
    let request = super::AuthorizeX402PaymentRequest {
        url: "https://twitr.sh/api/tools/x_search".into(),
        network: "eip155:8453".into(),
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
        recipient: "0xb5194A98DbDBb7028B585Db26B972e7F0F3f826A".into(),
        amount_atomic: 3600,
        owner: None,
        scheme: Some("upto".into()),
    };
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["scheme"], "upto");
    assert_eq!(
        serde_json::from_value::<super::AuthorizeX402PaymentRequest>(encoded).unwrap(),
        request
    );

    let legacy = json!({
        "url": "https://x", "network": "eip155:8453", "asset": "a",
        "recipient": "r", "amount_atomic": 1
    });
    let parsed: super::AuthorizeX402PaymentRequest = serde_json::from_value(legacy).unwrap();
    assert_eq!(parsed.scheme, None);
    let unnamed = super::AuthorizeX402PaymentRequest {
        scheme: None,
        ..parsed
    };
    assert!(
        serde_json::to_value(&unnamed)
            .unwrap()
            .get("scheme")
            .is_none()
    );
}
