//! Tests for the hand-built Solana wire format.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use curve25519_dalek::edwards::CompressedEdwardsY;

use super::{
    SYSTEM_PROGRAM_ID, associated_token_account, b58_to_pubkey, build_native_transfer_message,
    build_spl_transfer_message, decode_shortvec, encode_shortvec, pubkey_to_b58, token_program_id,
};

#[test]
fn shortvec_encodes_small_and_large_values() {
    assert_eq!(encode_shortvec(0), vec![0]);
    assert_eq!(encode_shortvec(1), vec![1]);
    assert_eq!(encode_shortvec(127), vec![127]);
    assert_eq!(encode_shortvec(128), vec![0x80, 1]);
    assert_eq!(encode_shortvec(16_383), vec![0xff, 0x7f]);
    assert_eq!(encode_shortvec(16_384), vec![0x80, 0x80, 1]);
}

#[test]
fn shortvec_round_trips() {
    for v in [0u16, 1, 127, 128, 16_383, 16_384, 65_535] {
        let enc = encode_shortvec(v);
        let (decoded, len) = decode_shortvec(&enc).unwrap();
        assert_eq!(decoded, v, "value {v} round-trips");
        assert_eq!(len, enc.len(), "consumed length matches for {v}");
    }
}

#[test]
fn malformed_shortvecs_are_rejected() {
    assert_eq!(decode_shortvec(&[0x80, 0x80]).unwrap_err(), "shortvec truncated");
    assert_eq!(decode_shortvec(&[]).unwrap_err(), "shortvec truncated");
    assert_eq!(decode_shortvec(&[0x80, 0x80, 0x80, 0x01]).unwrap_err(), "shortvec too long");
    // 0xff 0xff 0x7f decodes to 2^21 - 1, which does not fit a u16.
    assert_eq!(decode_shortvec(&[0xff, 0xff, 0x7f]).unwrap_err(), "shortvec exceeds u16 range");
}

#[test]
fn pubkeys_round_trip_through_base58_and_reject_the_wrong_length() {
    let addr = "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";
    let key = b58_to_pubkey(addr).unwrap();
    assert_eq!(pubkey_to_b58(&key), addr);
    assert_eq!(b58_to_pubkey("tooShort").unwrap_err(), "expected 32-byte pubkey, got 6");
    assert!(b58_to_pubkey("0OIl").unwrap_err().starts_with("invalid base58 '0OIl'"));
}

#[test]
fn the_token_program_id_is_the_well_known_key() {
    assert_eq!(
        pubkey_to_b58(&token_program_id().unwrap()),
        "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
    );
}

#[test]
fn a_native_transfer_message_has_the_documented_layout() {
    let from = [1u8; 32];
    let to = [2u8; 32];
    let bh = [3u8; 32];
    let msg = build_native_transfer_message(from, to, 1_000_000, bh);
    // header: 1 required signature, 0 readonly signed, 1 readonly unsigned.
    assert_eq!(&msg[..3], &[1u8, 0u8, 1u8]);
    // shortvec(3) then three keys.
    assert_eq!(msg[3], 3);
    assert_eq!(&msg[4..36], &from);
    assert_eq!(&msg[36..68], &to);
    assert_eq!(&msg[68..100], &SYSTEM_PROGRAM_ID);
    assert_eq!(&msg[100..132], &bh);
    // One instruction on the system program (index 2) touching accounts 0 and 1.
    assert_eq!(msg[132], 1);
    assert_eq!(msg[133], 2);
    assert_eq!(&msg[134..137], &[2, 0, 1]);
    // Transfer discriminator plus 8 little-endian amount bytes.
    assert_eq!(msg[137], 12);
    assert_eq!(&msg[138..142], &[2u8, 0u8, 0u8, 0u8]);
    assert_eq!(u64::from_le_bytes(msg[142..150].try_into().unwrap()), 1_000_000);
    assert_eq!(msg.len(), 150);
}

#[test]
fn an_spl_transfer_message_uses_the_token_program_and_the_right_accounts() {
    let msg =
        build_spl_transfer_message([1u8; 32], [2u8; 32], [3u8; 32], 42, [4u8; 32]).unwrap();
    // Four account keys: owner, source ATA, destination ATA, token program.
    assert_eq!(msg[3], 4);
    assert_eq!(&msg[4 + 96..4 + 128], &token_program_id().unwrap());
    // The instruction: token program (index 3), accounts src, dst, owner.
    let ins = 4 + 128 + 32;
    assert_eq!(msg[ins], 1);
    assert_eq!(msg[ins + 1], 3);
    assert_eq!(&msg[ins + 2..ins + 6], &[3, 1, 2, 0]);
    // SPL Transfer = 3, then the amount.
    assert_eq!(msg[ins + 6], 9);
    assert_eq!(msg[ins + 7], 3);
    assert_eq!(u64::from_le_bytes(msg[ins + 8..ins + 16].try_into().unwrap()), 42);
}

#[test]
fn an_associated_token_account_is_a_deterministic_off_curve_address() {
    // A program-derived address must not be a valid public key, or the ATA
    // program's contract is violated.
    let owner = b58_to_pubkey("HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk").unwrap();
    let mint = b58_to_pubkey("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v").unwrap();
    let a = associated_token_account(&owner, &mint).unwrap();
    let b = associated_token_account(&owner, &mint).unwrap();
    assert_eq!(a, b, "ATA derivation must be deterministic");
    assert!(CompressedEdwardsY(a).decompress().is_none(), "ATA must be off-curve");
    let other = associated_token_account(&[9u8; 32], &mint).unwrap();
    assert_ne!(a, other, "a different owner has a different ATA");
}
