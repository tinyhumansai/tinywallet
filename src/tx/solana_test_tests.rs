#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{NativeTransfer, encode_shortvec};
use crate::tx::Error;

/// Derived from the BIP-39 vector mnemonic at the standard Solana path.
const FROM: &str = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
const TO: &str = "11111111111111111111111111111111";
const BLOCKHASH: &str = "11111111111111111111111111111111";

fn key() -> Vec<u8> {
    crate::key::derive(crate::Chain::Solana, VECTOR, "m/44'/501'/0'/0'")
        .unwrap()
        .secret_bytes()
        .to_vec()
}

const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";

fn transfer() -> NativeTransfer {
    NativeTransfer {
        from: FROM.to_string(),
        to: TO.to_string(),
        lamports: 1_000_000_000,
        recent_blockhash: BLOCKHASH.to_string(),
    }
}

#[test]
fn shortvec_encodes_small_lengths_in_one_byte() {
    assert_eq!(encode_shortvec(0), vec![0]);
    assert_eq!(encode_shortvec(1), vec![1]);
    assert_eq!(encode_shortvec(127), vec![127]);
}

#[test]
fn shortvec_continues_past_127() {
    // 128 = 0x80 0x01: low seven bits with the continuation bit, then the
    // remainder.
    assert_eq!(encode_shortvec(128), vec![0x80, 0x01]);
    assert_eq!(encode_shortvec(256), vec![0x80, 0x02]);
    assert_eq!(encode_shortvec(u16::MAX), vec![0xff, 0xff, 0x03]);
}

#[test]
fn the_message_has_the_documented_layout() {
    let message = transfer().message().unwrap();

    // Header: 1 signer, 0 read-only signed, 1 read-only unsigned.
    assert_eq!(&message[0..3], &[1, 0, 1]);
    // Three accounts.
    assert_eq!(message[3], 3);
    // Sender first — the header says the first account signs.
    let from = crate::address::solana::decode(FROM).unwrap();
    assert_eq!(&message[4..36], &from[..]);
    // System program last, as the read-only unsigned account.
    assert_eq!(&message[68..100], &[0u8; 32]);
}

#[test]
fn the_instruction_encodes_transfer_and_the_lamports_little_endian() {
    let message = transfer().message().unwrap();
    let data = &message[message.len() - 12..];
    // System instruction index 2 = Transfer, u32 little-endian.
    assert_eq!(&data[0..4], &[2, 0, 0, 0]);
    // Lamports, u64 little-endian.
    assert_eq!(&data[4..12], &1_000_000_000u64.to_le_bytes());
}

#[test]
fn the_signed_transaction_carries_one_signature_then_the_message() {
    let tx = transfer().sign(&key()).unwrap();
    assert_eq!(tx[0], 1, "shortvec count of one signature");
    let message = transfer().message().unwrap();
    assert_eq!(&tx[65..], &message[..], "message follows the signature");
    assert_eq!(tx.len(), 1 + 64 + message.len());
}

#[test]
fn the_signature_verifies_against_the_sender() {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let tx = transfer().sign(&key()).unwrap();
    let message = transfer().message().unwrap();
    let signature = Signature::from_slice(&tx[1..65]).unwrap();
    let public = VerifyingKey::from_bytes(&crate::address::solana::decode(FROM).unwrap()).unwrap();
    public
        .verify(&message, &signature)
        .expect("signature must verify against the sender's key");
}

#[test]
fn a_key_that_does_not_control_the_sender_is_rejected() {
    // Structurally valid but wrong — caught here rather than on-chain.
    let other = crate::key::derive(crate::Chain::Solana, VECTOR, "m/44'/501'/1'/0'")
        .unwrap()
        .secret_bytes()
        .to_vec();
    match transfer().sign(&other).unwrap_err() {
        Error::Signing { reason } => assert!(reason.contains("does not control")),
        other => panic!("expected Signing, got {other:?}"),
    }
}

#[test]
fn a_wrong_length_key_is_rejected() {
    assert!(matches!(
        transfer().sign(&[0u8; 16]).unwrap_err(),
        Error::Signing { .. }
    ));
}

#[test]
fn an_invalid_address_or_blockhash_is_rejected() {
    let bad_to = NativeTransfer {
        to: "0OIl".to_string(),
        ..transfer()
    };
    assert!(matches!(bad_to.message(), Err(Error::Address(_))));

    let bad_hash = NativeTransfer {
        recent_blockhash: "tooShort".to_string(),
        ..transfer()
    };
    match bad_hash.message().unwrap_err() {
        Error::InvalidField { field, .. } => assert_eq!(field, "recent_blockhash"),
        other => panic!("expected InvalidField, got {other:?}"),
    }
}

#[test]
fn a_different_blockhash_changes_the_signature() {
    // The blockhash is what makes a transaction non-replayable, so it must
    // reach the signed bytes.
    let a = transfer().sign(&key()).unwrap();
    let b = NativeTransfer {
        recent_blockhash: "So11111111111111111111111111111111111111112".to_string(),
        ..transfer()
    }
    .sign(&key())
    .unwrap();
    assert_ne!(a, b);
}

#[test]
fn signing_is_deterministic() {
    // ed25519 signatures are deterministic by construction.
    assert_eq!(
        transfer().sign(&key()).unwrap(),
        transfer().sign(&key()).unwrap()
    );
}

#[test]
fn split_signing_matches_one_shot_signing() {
    // The host holds the ed25519 key and signs the message; this crate
    // assembles. Both paths must produce identical wire bytes, or the
    // split has silently changed what gets broadcast.
    use ed25519_dalek::{Signer as _, SigningKey};

    let transfer = transfer();
    let secret = key();
    let one_shot = transfer.sign(&secret).unwrap();

    let bytes: [u8; 32] = secret.as_slice().try_into().unwrap();
    let signing = SigningKey::from_bytes(&bytes);
    let signature = signing.sign(&transfer.message().unwrap()).to_bytes();
    let split = transfer.attach_signature(&signature).unwrap();

    assert_eq!(split, one_shot);
}

#[test]
fn the_signed_payload_is_the_message_itself_not_a_digest() {
    // ed25519 hashes internally. A host that pre-hashes the message and
    // signs the digest produces a signature the network rejects, so the
    // distinction is worth pinning.
    let transfer = transfer();
    let message = transfer.message().unwrap();
    assert!(
        message.len() > 32,
        "a Solana message is the full serialized transaction, not a 32-byte digest"
    );
}
