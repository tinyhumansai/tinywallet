//! Tests for the wallet service boundary.
//!
//! These drive `build_unsigned` and `attach_signature` directly rather than
//! over a bus. What they are checking is the translation layer — wire types in,
//! `tinywallet` calls out, wire types back — and a broker in between would only
//! add a runtime to every case. The real loader round trip lives in
//! `tests/module_e2e.rs`.
//!
//! The load-bearing test is [`the_split_path_reproduces_a_one_shot_signature`]:
//! whatever this module returns must equal what the library produces signing in
//! one step, or moving signing out of the host has quietly changed what gets
//! broadcast.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use tinywallet::wire::{
    AttachRequest, PublicKey, Scheme, Signature, SigningRequest, TransactionSpec, Utxo,
};
use tinywallet::{Chain, tx};

use super::{attach_signature, build_unsigned, hex};

/// The BIP-39 test vector mnemonic. Never use it for real funds.
const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";

fn evm_key() -> Vec<u8> {
    tinywallet::key::derive(Chain::Evm, VECTOR, "m/44'/60'/0'/0/0")
        .unwrap()
        .secret_bytes()
        .to_vec()
}

/// The compressed SEC1 public key for a secret.
fn compressed_public(secret: &[u8]) -> String {
    use bitcoin::secp256k1::{PublicKey as SecpPublic, Secp256k1, SecretKey};
    let secret = SecretKey::from_slice(secret).unwrap();
    hex(&SecpPublic::from_secret_key(&Secp256k1::new(), &secret).serialize())
}

fn evm_spec() -> TransactionSpec {
    TransactionSpec::Evm {
        to: "0x3535353535353535353535353535353535353535".to_string(),
        value_wei: "1000000000000000000".to_string(),
        data_hex: "0x".to_string(),
        nonce: 9,
        gas_limit: 21_000,
        gas_price_wei: "20000000000".to_string(),
        chain_id: 1,
    }
}

/// Sign a prehashed digest the way a host would.
fn host_sign(digest_hex: &str, key: &[u8]) -> Signature {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
    let mut digest = [0u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&digest_hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    let secret = SecretKey::from_slice(key).unwrap();
    let recoverable =
        Secp256k1::signing_only().sign_ecdsa_recoverable(&Message::from_digest(digest), &secret);
    let (recovery_id, compact) = recoverable.serialize_compact();
    Signature::Secp256k1 {
        rs_hex: hex(&compact),
        recovery_id: u8::try_from(recovery_id.to_i32()).unwrap(),
    }
}

#[test]
fn the_split_path_reproduces_a_one_shot_signature() {
    // The whole justification for the module: signing through it must produce
    // exactly what signing in-process produces.
    let key = evm_key();
    let spec = evm_spec();

    let unsigned = build_unsigned(&SigningRequest {
        transaction: spec.clone(),
        public_key: PublicKey {
            key_hex: compressed_public(&key),
        },
    })
    .unwrap();
    assert_eq!(unsigned.payloads.len(), 1);
    assert_eq!(unsigned.payloads[0].scheme, Scheme::Secp256k1Prehash);

    let signature = host_sign(&unsigned.payloads[0].bytes_hex, &key);
    let signed = attach_signature(&AttachRequest {
        transaction: spec,
        public_key: PublicKey {
            key_hex: compressed_public(&key),
        },
        signatures: vec![signature],
    })
    .unwrap();

    let expected = tx::evm::LegacyTransaction {
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some("0x3535353535353535353535353535353535353535".to_string()),
        value: 1_000_000_000_000_000_000,
        data: Vec::new(),
        chain_id: 1,
    }
    .sign(&key)
    .unwrap();

    assert_eq!(signed.raw, format!("0x{}", hex(&expected)));
    assert_eq!(
        signed.txid,
        Some(tx::evm::LegacyTransaction::hash_of(&expected))
    );
}

#[test]
fn a_bitcoin_request_returns_one_payload_per_selected_input() {
    // Bitcoin is the only chain needing more than one signature, and the
    // count and order are the contract the host signs against.
    let key = tinywallet::key::derive(Chain::Btc, VECTOR, "m/84'/0'/0'/0/0").unwrap();
    let spec = TransactionSpec::Btc {
        from: key.address().to_string(),
        to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        amount_sat: 150_000,
        fee_sat: 2_000,
        utxos: vec![
            Utxo {
                txid: "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605"
                    .to_string(),
                vout: 0,
                value: 60_000,
            },
            Utxo {
                txid: "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605"
                    .to_string(),
                vout: 1,
                value: 70_000,
            },
            Utxo {
                txid: "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605"
                    .to_string(),
                vout: 2,
                value: 80_000,
            },
        ],
    };

    let unsigned = build_unsigned(&SigningRequest {
        transaction: spec,
        public_key: PublicKey {
            key_hex: compressed_public(key.secret_bytes()),
        },
    })
    .unwrap();

    assert!(
        unsigned.payloads.len() > 1,
        "the fixture must select several inputs"
    );
    for payload in &unsigned.payloads {
        assert_eq!(payload.scheme, Scheme::Secp256k1Prehash);
        assert_eq!(payload.bytes_hex.len(), 64, "a sighash is 32 bytes");
    }
}

#[test]
fn a_solana_payload_is_the_message_not_a_digest() {
    // ed25519 hashes internally. A host that pre-hashes produces a signature
    // the network rejects, so the scheme tag has to say so.
    let key = tinywallet::key::derive(Chain::Solana, VECTOR, "m/44'/501'/0'/0'").unwrap();
    let unsigned = build_unsigned(&SigningRequest {
        transaction: TransactionSpec::Solana {
            from: key.address().to_string(),
            to: "11111111111111111111111111111111".to_string(),
            lamports: 1_000_000_000,
            recent_blockhash: "11111111111111111111111111111111".to_string(),
        },
        public_key: PublicKey {
            key_hex: hex(key.secret_bytes()),
        },
    })
    .unwrap();

    assert_eq!(unsigned.payloads[0].scheme, Scheme::Ed25519);
    assert!(
        unsigned.payloads[0].bytes_hex.len() > 64,
        "the payload is the whole message, not a 32-byte digest"
    );
}

#[test]
fn the_chain_comes_from_the_transaction_rather_than_a_separate_field() {
    // This replaces a test that fed a request whose `chain` tag contradicted
    // its transaction. That state is no longer expressible: the requests carry
    // no `chain`, so `TransactionSpec` is the single source of truth and the
    // disagreement cannot be constructed. What is worth pinning instead is
    // that the mapping is right for every variant.
    use tinywallet::wire::Utxo;

    let cases = [
        (
            TransactionSpec::Btc {
                from: String::new(),
                to: String::new(),
                amount_sat: 0,
                fee_sat: 0,
                utxos: Vec::<Utxo>::new(),
            },
            Chain::Btc,
        ),
        (evm_spec(), Chain::Evm),
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
                transfer: tinywallet::wire::TronTransfer::Native { amount_sun: 0 },
            },
            Chain::Tron,
        ),
    ];

    for (spec, expected) in cases {
        assert_eq!(spec.chain(), expected);
    }
}

#[test]
fn an_ed25519_signature_is_refused_for_a_secp256k1_chain() {
    let error = attach_signature(&AttachRequest {
        transaction: evm_spec(),
        public_key: PublicKey {
            key_hex: compressed_public(&evm_key()),
        },
        signatures: vec![Signature::Ed25519 {
            signature_hex: "ab".repeat(64),
        }],
    })
    .unwrap_err();

    let rendered = format!("{error:?}");
    assert!(rendered.contains("InvalidInput"), "{rendered}");
}

#[test]
fn a_wrong_signature_count_is_refused_rather_than_truncated() {
    let error = attach_signature(&AttachRequest {
        transaction: evm_spec(),
        public_key: PublicKey {
            key_hex: compressed_public(&evm_key()),
        },
        signatures: vec![],
    })
    .unwrap_err();

    let rendered = format!("{error:?}");
    assert!(rendered.contains("InvalidInput"), "{rendered}");
}

#[test]
fn a_tron_transaction_whose_txid_does_not_match_its_bytes_is_refused() {
    // The defence against a compromised node: it must not be possible to get a
    // signature over bytes whose recomputed id disagrees with what was claimed.
    let error = build_unsigned(&SigningRequest {
        transaction: TransactionSpec::Tron {
            raw_data_hex: "0a02b1f12208".to_string() + &"ab".repeat(64),
            expected_to: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string(),
            expected_txid: "00".repeat(32),
            transfer: tinywallet::wire::TronTransfer::Native { amount_sun: 0 },
        },
        public_key: PublicKey {
            key_hex: compressed_public(&evm_key()),
        },
    })
    .unwrap_err();

    let rendered = format!("{error:?}");
    assert!(rendered.contains("InvalidInput"), "{rendered}");
}

#[test]
fn a_tron_transaction_paying_a_decoy_recipient_is_refused_on_the_signing_side() {
    // The case that motivated moving this module off `verify_transfer`: the
    // requested address IS present in `raw_data`, but as an unrelated trailing
    // field, while `to_address` pays someone else. A byte-run search over the
    // hex is satisfied by the decoy and would have signed it.
    //
    // The host checks this too, but the check that matters is the one on the
    // side holding the key — a host is exactly what a caller could be lying to.
    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                b |= 0x80;
            }
            out.push(b);
            if v == 0 {
                return out;
            }
        }
    }
    fn tagged(number: u64, wire: u64) -> Vec<u8> {
        varint((number << 3) | wire)
    }
    fn bytes_field(number: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = tagged(number, 2);
        out.extend(varint(payload.len() as u64));
        out.extend(payload);
        out
    }
    fn addr(a: &str) -> Vec<u8> {
        let h = tinywallet::address::tron::to_hex(a).unwrap();
        (0..h.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
            .collect()
    }

    const REQUESTED: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
    const ATTACKER: &str = "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH";

    // TransferContract paying the attacker, for the requested amount.
    let mut payload = bytes_field(2, &addr(ATTACKER));
    payload.extend({
        let mut f = tagged(3, 0);
        f.extend(varint(1_000_000));
        f
    });
    let mut any = bytes_field(1, b"type.googleapis.com/protocol.TransferContract");
    any.extend(bytes_field(2, &payload));
    let mut contract = {
        let mut f = tagged(1, 0);
        f.extend(varint(1));
        f
    };
    contract.extend(bytes_field(2, &any));
    let mut raw = bytes_field(11, &contract);
    // The decoy: the requested recipient, somewhere harmless.
    raw.extend(bytes_field(99, &addr(REQUESTED)));

    let raw_data_hex = hex(&raw);
    let expected_txid = tx::tron::recompute_txid(&raw_data_hex).unwrap();
    let transfer = tinywallet::wire::TronTransfer::Native {
        amount_sun: 1_000_000,
    };

    // The old check would have passed this.
    assert!(
        tx::tron::verify_transfer(&raw_data_hex, REQUESTED, &expected_txid, &transfer).is_ok(),
        "precondition: the byte-run search is fooled by the decoy"
    );

    let error = build_unsigned(&SigningRequest {
        transaction: TransactionSpec::Tron {
            raw_data_hex,
            expected_to: REQUESTED.to_string(),
            expected_txid,
            transfer,
        },
        public_key: PublicKey {
            key_hex: compressed_public(&evm_key()),
        },
    })
    .unwrap_err();

    let rendered = format!("{error:?}");
    assert!(rendered.contains("InvalidInput"), "{rendered}");
    assert!(
        rendered.contains("does not pay the requested recipient"),
        "{rendered}"
    );
}

#[test]
fn the_exported_names_are_the_published_ones() {
    // A host resolves the module by these strings; changing either is a
    // breaking change that no type system catches.
    assert_eq!(super::BUS_NAME, "ai.tinyhumans.tinywallet.Wallet");
    assert_eq!(super::OBJECT_PATH, "/ai/tinyhumans/tinywallet/Wallet");
}

#[test]
fn base64_matches_its_specification_for_every_padding_case() {
    // Hand-rolled, so the three chunk remainders each need a vector.
    assert_eq!(super::base64(b""), "");
    assert_eq!(super::base64(b"f"), "Zg==");
    assert_eq!(super::base64(b"fo"), "Zm8=");
    assert_eq!(super::base64(b"foo"), "Zm9v");
    assert_eq!(super::base64(b"foob"), "Zm9vYg==");
    assert_eq!(super::base64(b"fooba"), "Zm9vYmE=");
    assert_eq!(super::base64(b"foobar"), "Zm9vYmFy");
}

// ---------------------------------------------------------------------------
// The confidential flow
// ---------------------------------------------------------------------------

use tinywallet::wire::{ExportRequest, SecretMaterial, SignRequest};

use super::{derive_account, export_key, sign_transaction};

fn secret(chain: Chain, path: &str) -> SecretMaterial {
    SecretMaterial {
        mnemonic: VECTOR.to_string(),
        derivation_path: path.to_string(),
        chain,
    }
}

#[test]
fn the_one_shot_path_agrees_with_the_split_path_byte_for_byte() {
    // The load-bearing test for this flow, and the counterpart to
    // `the_split_path_reproduces_a_one_shot_signature`. Moving the key into
    // this module must not change a single byte of what gets broadcast; if it
    // does, funds move differently than the host's own tests believe.
    let spec = evm_spec();
    let key = evm_key();

    // Split: host derives, module builds, host signs, module assembles.
    let public_key = PublicKey {
        key_hex: compressed_public(&key),
    };
    let unsigned = build_unsigned(&SigningRequest {
        transaction: spec.clone(),
        public_key: public_key.clone(),
    })
    .unwrap();
    let split = attach_signature(&AttachRequest {
        transaction: spec.clone(),
        public_key,
        signatures: unsigned
            .payloads
            .iter()
            .map(|payload| host_sign(&payload.bytes_hex, &key))
            .collect(),
    })
    .unwrap();

    // One-shot: the module does all of it from the phrase alone.
    let one_shot = sign_transaction(&SignRequest {
        secret: secret(Chain::Evm, "m/44'/60'/0'/0/0"),
        transaction: spec,
    })
    .unwrap();

    assert_eq!(one_shot, split);
}

#[test]
fn a_solana_transfer_signs_the_same_way_through_both_paths() {
    // Solana is the ed25519 arm, and the only chain whose payload is the
    // message rather than a digest — so the secp256k1 case passing says
    // nothing about it.
    let spec = TransactionSpec::Solana {
        from: tinywallet::key::derive(Chain::Solana, VECTOR, "m/44'/501'/0'/0'")
            .unwrap()
            .address()
            .to_string(),
        to: "11111111111111111111111111111113".to_string(),
        lamports: 1_000,
        recent_blockhash: "11111111111111111111111111111114".to_string(),
    };

    let derived = tinywallet::key::derive(Chain::Solana, VECTOR, "m/44'/501'/0'/0'").unwrap();
    let signing = ed25519_dalek::SigningKey::from_bytes(
        &<[u8; 32]>::try_from(derived.secret_bytes()).unwrap(),
    );
    let public_key = PublicKey {
        key_hex: hex(&signing.verifying_key().to_bytes()),
    };
    let unsigned = build_unsigned(&SigningRequest {
        transaction: spec.clone(),
        public_key: public_key.clone(),
    })
    .unwrap();
    let signatures = unsigned
        .payloads
        .iter()
        .map(|payload| {
            use ed25519_dalek::Signer;
            let bytes = super::decode_hex(&payload.bytes_hex).unwrap();
            Signature::Ed25519 {
                signature_hex: hex(&signing.sign(&bytes).to_bytes()),
            }
        })
        .collect();
    let split = attach_signature(&AttachRequest {
        transaction: spec.clone(),
        public_key,
        signatures,
    })
    .unwrap();

    let one_shot = sign_transaction(&SignRequest {
        secret: secret(Chain::Solana, "m/44'/501'/0'/0'"),
        transaction: spec,
    })
    .unwrap();

    assert_eq!(one_shot, split);
}

#[test]
fn a_derivation_chain_that_disagrees_with_the_transaction_is_refused() {
    // Without this check a Solana phrase walked with EVM rules would sign a
    // real EVM transaction from an address the user has never seen. The
    // request is internally plausible, so nothing downstream would object.
    let error = sign_transaction(&SignRequest {
        secret: secret(Chain::Solana, "m/44'/501'/0'/0'"),
        transaction: evm_spec(),
    })
    .unwrap_err();

    match error {
        super::Failure::InvalidInput(message) => {
            assert!(message.contains("chain"), "{message}");
        }
        super::Failure::BuildFailed(message) => {
            panic!("expected InvalidInput, got BuildFailed({message})")
        }
    }

    // And the matching pair is accepted, so the test cannot pass by refusing
    // everything.
    assert!(
        sign_transaction(&SignRequest {
            secret: secret(Chain::Evm, "m/44'/60'/0'/0/0"),
            transaction: evm_spec(),
        })
        .is_ok()
    );
}

#[test]
fn deriving_an_account_reports_the_published_vector_address_and_no_key() {
    // Pinned against the BIP-39 vector rather than against another call into
    // the same derivation code, which would agree with itself however wrong it
    // was.
    let account = derive_account(&secret(Chain::Evm, "m/44'/60'/0'/0/0")).unwrap();
    assert_eq!(
        account.address,
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );

    // A compressed SEC1 public key, and emphatically not the secret: 33 bytes
    // starting 02 or 03, and different from the 32-byte private key.
    assert_eq!(account.public_key.key_hex.len(), 66);
    assert!(
        account.public_key.key_hex.starts_with("02")
            || account.public_key.key_hex.starts_with("03")
    );
    assert_ne!(account.public_key.key_hex, hex(&evm_key()));
}

#[test]
fn an_exported_key_is_the_derived_key_for_the_address_it_names() {
    let exported = export_key(&ExportRequest {
        secret: secret(Chain::Evm, "m/44'/60'/0'/0/0"),
    })
    .unwrap();
    assert_eq!(exported.secret_key_hex, hex(&evm_key()));
    assert_eq!(
        exported.address,
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
}

#[test]
fn neither_a_phrase_nor_an_exported_key_survives_being_formatted() {
    // A derived `Debug` would put a live recovery phrase into every log line
    // and panic message that ever formatted a request. That is the leak this
    // whole arrangement exists to prevent, arriving through the back door — so
    // it is asserted rather than left to review.
    let material = secret(Chain::Evm, "m/44'/60'/0'/0/0");
    let rendered = format!("{material:?}");
    assert!(!rendered.contains("abandon"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // The non-secret fields stay legible, or the redaction has cost the
    // diagnostics it was meant to preserve.
    assert!(rendered.contains("m/44'/60'/0'/0/0"), "{rendered}");

    let exported = export_key(&ExportRequest { secret: material }).unwrap();
    let rendered = format!("{exported:?}");
    assert!(!rendered.contains(&exported.secret_key_hex), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");
}

#[test]
fn a_rejected_phrase_is_not_quoted_back_in_the_error() {
    // An error that echoed the phrase would write it wherever the error went,
    // undoing the confidential delivery that carried it here.
    let error = sign_transaction(&SignRequest {
        secret: SecretMaterial {
            mnemonic: "clearly not a valid bip39 phrase at all".to_string(),
            derivation_path: "m/44'/60'/0'/0/0".to_string(),
            chain: Chain::Evm,
        },
        transaction: evm_spec(),
    })
    .unwrap_err();

    let rendered = format!("{error:?}");
    assert!(!rendered.contains("clearly not a valid"), "{rendered}");
}
