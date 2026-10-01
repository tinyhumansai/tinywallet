//! Tests for the Solana chain module, driven against canned JSON-RPC answers
//! and a signer that really signs.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Verifier as _;
use serde_json::{Value, json};
use tinywallet_bus::wire::Signature;

use super::wire::{b58_to_pubkey, encode_shortvec, token_program_id};
use super::{
    execute_solana_quote, lookup_tx, native_balance, sign_and_broadcast_versioned, tx_receipt,
    tx_status, validate_solana_address,
};
use crate::crypto::defaults::SolanaCluster;
use crate::crypto::execution::{PreparedKind, PreparedStatus, TxState};
use crate::crypto::wallet::WalletChain;
use crate::test_support::{FakeSigner, Rig, SignerCall, prepared_quote, sample_address};

const SIG: &str =
    "5xS9pXmqVz8R1nuRZTfsdsAxBdBFmtnAtuYbCsmK5DYzGn5vR4VqWGmiR5McLnYx8oFqLdo62q4qiUZpQyR4Hkn3";
const BLOCKHASH: &str = "GHtXQBsoZHVnNFa9YevAzFr17DJjgHXk3ycTKD5xD3Zi";
const USDC: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const RECIPIENT: &str = "Vote111111111111111111111111111111111111111";

fn script_node(rig: &Rig) {
    rig.transport
        .on_rpc(
            "getLatestBlockhash",
            json!({"context": {"slot": 0}, "value": {"blockhash": BLOCKHASH, "lastValidBlockHeight": 0u64}}),
        )
        .on_rpc("sendTransaction", json!(SIG));
}

fn sol_quote(kind: PreparedKind) -> crate::crypto::execution::PreparedTransaction {
    let mut quote = prepared_quote("q_sol", WalletChain::Solana, kind);
    quote.to_address = RECIPIENT.to_string();
    quote.amount_raw = "1000".to_string();
    if kind == PreparedKind::TokenTransfer {
        quote.token_address = Some(USDC.to_string());
        quote.amount_raw = "1000000".to_string();
    }
    quote
}

/// The wire transaction the engine passed to `sendTransaction`.
fn broadcast_wire(rig: &Rig) -> Vec<u8> {
    let params = rig.transport.first_rpc("sendTransaction").unwrap();
    B64.decode(params[0].as_str().unwrap()).unwrap()
}

// ── addresses and balance ────────────────────────────────────────────────

#[test]
fn a_known_pubkey_validates_and_a_short_string_does_not() {
    let addr = "9WzDXwBbmkg8ZTbNMqUxvQRAyrZzDsGYdLVL9zYtAWWM";
    assert_eq!(validate_solana_address(addr).unwrap(), addr);
    let err = validate_solana_address("tooShort").unwrap_err();
    assert!(err.contains("32 bytes"), "got: {err}");
}

#[test]
fn the_test_mnemonic_derives_the_pinned_solana_address() {
    // SLIP-0010 ed25519 hardened derivation at m/44'/501'/0'/0' from the
    // standard mnemonic, pinned so a regression in derivation flips this
    // before it ships. This is the address every fixture in the crate uses.
    let key = FakeSigner::solana_key();
    let addr = super::wire::pubkey_to_b58(&key.verifying_key().to_bytes());
    assert_eq!(addr, sample_address(WalletChain::Solana));
}

#[tokio::test]
async fn balance_reads_lamports() {
    let rig = Rig::new();
    rig.transport.on_rpc(
        "getBalance",
        json!({"context": {"slot": 0}, "value": 1_000_000u64}),
    );
    let addr = sample_address(WalletChain::Solana);
    assert_eq!(native_balance(&rig.engine, addr).await.unwrap(), 1_000_000);
    assert_eq!(
        rig.transport.first_rpc("getBalance").unwrap(),
        json!([addr])
    );
    assert!(native_balance(&rig.engine, "tooShort").await.is_err());
}

// ── quotes ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_native_transfer_is_signed_by_the_wallet_and_broadcast() {
    let rig = Rig::new();
    script_node(&rig);
    let result = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap();
    assert_eq!(result.status, PreparedStatus::Broadcasted);
    assert_eq!(result.transaction_hash, SIG);
    assert_eq!(
        result.explorer_url.as_deref(),
        Some(format!("https://solscan.io/tx/{SIG}").as_str())
    );

    // Two RPC calls: the blockhash, then the broadcast.
    let methods: Vec<String> = rig
        .transport
        .rpc_calls()
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    assert_eq!(methods, ["getLatestBlockhash", "sendTransaction"]);

    // The broadcast wire is one signature slot plus the message, and the
    // signature verifies against the wallet's key.
    let wire = broadcast_wire(&rig);
    assert_eq!(wire[0], 1, "exactly one signature");
    let (sig, message) = wire[1..].split_at(64);
    let key = FakeSigner::solana_key().verifying_key();
    let signature = ed25519_dalek::Signature::from_slice(sig).unwrap();
    key.verify(message, &signature)
        .expect("the broadcast signature is valid over the message");
    assert!(
        rig.signer
            .calls()
            .contains(&SignerCall::Derive(WalletChain::Solana))
    );
}

#[tokio::test]
async fn a_devnet_transfer_links_to_the_devnet_explorer() {
    let rig = Rig::new();
    rig.endpoints.set_cluster(SolanaCluster::Devnet);
    script_node(&rig);
    let result = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap();
    assert_eq!(
        result.explorer_url.as_deref(),
        Some(format!("https://solscan.io/tx/{SIG}?cluster=devnet").as_str())
    );
}

#[tokio::test]
async fn an_spl_transfer_carries_the_token_program_and_checks_the_destination_ata() {
    let rig = Rig::new();
    script_node(&rig);
    rig.transport.on_rpc(
        "getAccountInfo",
        json!({"context": {"slot": 0}, "value": {"lamports": 2_039_280u64, "owner": "Tokenkeg", "data": ["", "base64"]}}),
    );
    let result = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::TokenTransfer))
        .await
        .unwrap();
    assert_eq!(result.status, PreparedStatus::Broadcasted);
    let methods: Vec<String> = rig
        .transport
        .rpc_calls()
        .into_iter()
        .map(|(m, _)| m)
        .collect();
    assert_eq!(
        methods,
        ["getLatestBlockhash", "getAccountInfo", "sendTransaction"]
    );
    let wire = broadcast_wire(&rig);
    let message = &wire[1 + 64..];
    let token_program = token_program_id().unwrap();
    assert!(
        message.windows(32).any(|w| w == token_program),
        "expected the token program in account_keys"
    );
}

#[tokio::test]
async fn an_spl_transfer_is_refused_when_the_destination_ata_is_missing() {
    let rig = Rig::new();
    script_node(&rig);
    rig.transport.on_rpc(
        "getAccountInfo",
        json!({"context": {"slot": 0}, "value": null}),
    );
    let err = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::TokenTransfer))
        .await
        .unwrap_err();
    assert!(
        err.contains("SPL preflight") && err.contains("Associated Token Account does not exist"),
        "got: {err}"
    );
    assert!(
        rig.transport.first_rpc("sendTransaction").is_none(),
        "nothing is broadcast"
    );
    assert!(
        !rig.signer
            .calls()
            .iter()
            .any(|c| matches!(c, SignerCall::Message(..))),
        "nothing is signed"
    );
}

#[tokio::test]
async fn an_spl_quote_without_a_mint_is_refused() {
    let rig = Rig::new();
    script_node(&rig);
    let mut quote = sol_quote(PreparedKind::TokenTransfer);
    quote.token_address = None;
    assert_eq!(
        execute_solana_quote(&rig.engine, quote).await.unwrap_err(),
        "SPL transfer missing token_address (mint)"
    );
}

#[tokio::test]
async fn a_mismatched_derived_key_is_refused_before_any_rpc() {
    let rig = Rig::new();
    rig.signer
        .derive_as("Vote111111111111111111111111111111111111111");
    let err = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert!(
        err.starts_with("Solana key derivation mismatch: derived Vote"),
        "{err}"
    );
    assert_eq!(rig.transport.calls().len(), 0);
}

#[tokio::test]
async fn quote_input_is_validated() {
    let rig = Rig::new();
    let mut bad_amount = sol_quote(PreparedKind::NativeTransfer);
    bad_amount.amount_raw = "many".to_string();
    assert!(
        execute_solana_quote(&rig.engine, bad_amount)
            .await
            .unwrap_err()
            .starts_with("invalid Solana amount 'many'")
    );
    let mut bad_to = sol_quote(PreparedKind::NativeTransfer);
    bad_to.to_address = "nope".to_string();
    assert!(execute_solana_quote(&rig.engine, bad_to).await.is_err());
    let mut bad_from = sol_quote(PreparedKind::NativeTransfer);
    bad_from.from_address = "nope".to_string();
    assert!(execute_solana_quote(&rig.engine, bad_from).await.is_err());
}

#[tokio::test]
async fn signer_failures_are_surfaced_verbatim() {
    let rig = Rig::new();
    rig.signer
        .fail_derive("failed to derive the Solana account: module unavailable");
    let err = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        "failed to derive the Solana account: module unavailable"
    );

    let rig = Rig::new();
    script_node(&rig);
    rig.signer
        .fail_message("failed to sign the Solana message: module unavailable");
    let err = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert_eq!(err, "failed to sign the Solana message: module unavailable");
}

#[tokio::test]
async fn a_wrong_kind_or_malformed_signature_from_the_signer_is_refused() {
    let cases: [(Signature, &str); 4] = [
        (
            Signature::Secp256k1 {
                rs_hex: "00".repeat(64),
                recovery_id: 0,
            },
            "the wallet module returned a non-ed25519 Solana signature",
        ),
        (
            Signature::Ed25519 {
                signature_hex: "ab".repeat(10),
            },
            "the wallet module returned a malformed Solana signature",
        ),
        (
            Signature::Ed25519 {
                signature_hex: "abc".to_string(),
            },
            "odd-length hex from the wallet module",
        ),
        (
            Signature::Ed25519 {
                signature_hex: "zz".repeat(64),
            },
            "invalid hex from the wallet module: ",
        ),
    ];
    for (reply, expected) in cases {
        let rig = Rig::new();
        script_node(&rig);
        rig.signer.reply_message(reply);
        let err = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
            .await
            .unwrap_err();
        assert!(err.starts_with(expected), "{err}");
        assert!(rig.transport.first_rpc("sendTransaction").is_none());
    }
}

#[tokio::test]
async fn a_non_ascii_signature_is_an_error_not_a_panic() {
    let rig = Rig::new();
    script_node(&rig);
    rig.signer.reply_message(Signature::Ed25519 {
        signature_hex: "é".repeat(64),
    });
    let err = execute_solana_quote(&rig.engine, sol_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert!(err.contains("from the wallet module"), "{err}");
}

// ── versioned transactions ───────────────────────────────────────────────

/// A minimal legacy transaction with `signer` as the sole required signer and
/// an empty signature slot.
fn unsigned_legacy(signer: &[u8; 32]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend([1u8, 0u8, 0u8]);
    message.extend(encode_shortvec(1));
    message.extend(signer);
    message.extend([0u8; 32]);
    message.extend(encode_shortvec(0));
    let mut wire = Vec::new();
    wire.extend(encode_shortvec(1));
    wire.extend([0u8; 64]);
    wire.extend(&message);
    wire
}

#[tokio::test]
async fn a_versioned_transaction_gets_our_signature_in_our_slot() {
    let rig = Rig::new();
    script_node(&rig);
    let signer = b58_to_pubkey(sample_address(WalletChain::Solana)).unwrap();
    let wire = unsigned_legacy(&signer);
    let result = sign_and_broadcast_versioned(&rig.engine, &format!("0x{}", hex::encode(&wire)))
        .await
        .unwrap();
    assert_eq!(result.transaction_hash, SIG);
    assert_eq!(
        result.fee_raw, None,
        "Solana's fee is only known once confirmed"
    );
    assert!(result.explorer_url.is_some());

    let sent = broadcast_wire(&rig);
    assert_eq!(sent[0], 1);
    let signature = ed25519_dalek::Signature::from_slice(&sent[1..65]).unwrap();
    FakeSigner::solana_key()
        .verifying_key()
        .verify(&wire[65..], &signature)
        .expect("the message bytes were signed");
    assert_eq!(&sent[65..], &wire[65..], "the message is untouched");
}

#[tokio::test]
async fn a_devnet_versioned_transaction_links_to_the_devnet_explorer() {
    let rig = Rig::new();
    rig.endpoints.set_cluster(SolanaCluster::Devnet);
    script_node(&rig);
    let signer = b58_to_pubkey(sample_address(WalletChain::Solana)).unwrap();
    let wire = unsigned_legacy(&signer);
    let result = sign_and_broadcast_versioned(&rig.engine, &format!("0x{}", hex::encode(&wire)))
        .await
        .unwrap();
    assert_eq!(
        result.explorer_url.as_deref(),
        Some(format!("https://solscan.io/tx/{SIG}?cluster=devnet").as_str())
    );
}

#[tokio::test]
async fn a_versioned_transaction_we_are_not_a_signer_of_is_refused() {
    let rig = Rig::new();
    let wire = unsigned_legacy(&[7u8; 32]);
    let err = sign_and_broadcast_versioned(&rig.engine, &hex::encode(&wire))
        .await
        .unwrap_err();
    assert!(err.contains("not a required signer"), "got: {err}");
    assert!(
        !rig.signer
            .calls()
            .iter()
            .any(|c| matches!(c, SignerCall::Message(..)))
    );
}

#[tokio::test]
async fn a_v0_message_is_signed_with_its_version_prefix_included() {
    let rig = Rig::new();
    script_node(&rig);
    let signer = b58_to_pubkey(sample_address(WalletChain::Solana)).unwrap();
    let mut wire = unsigned_legacy(&signer);
    // Turn the message into v0: prefix 0x80, then the same header/keys/etc.
    wire.insert(1 + 64, 0x80);
    sign_and_broadcast_versioned(&rig.engine, &hex::encode(&wire))
        .await
        .unwrap();
    let message_signed = rig.signer.calls().into_iter().find_map(|c| match c {
        SignerCall::Message(_, m) => Some(m),
        _ => None,
    });
    assert_eq!(
        message_signed.unwrap(),
        wire[65..].to_vec(),
        "the version prefix is part of what is signed"
    );
}

#[tokio::test]
async fn malformed_versioned_blobs_are_rejected_with_specific_messages() {
    let rig = Rig::new();
    let signer = [7u8; 32];
    let good = unsigned_legacy(&signer);
    let cases: Vec<(String, &str)> = vec![
        ("zz".to_string(), "invalid Solana transaction hex blob"),
        (String::new(), "shortvec truncated"),
        // Declares 1 signature but stops before the message.
        (
            hex::encode(&good[..40]),
            "Solana tx blob truncated before message",
        ),
        // Signature slots present, message empty.
        (hex::encode(&good[..65]), "Solana tx blob has empty message"),
        (
            hex::encode(&good[..65 + 2]),
            "Solana message header truncated",
        ),
        // Zero required signatures.
        (
            {
                let mut b = good.clone();
                b[65] = 0;
                hex::encode(b)
            },
            "Solana message declares zero required signatures",
        ),
        // Account key region cut short.
        (
            hex::encode(&good[..65 + 3 + 1 + 10]),
            "Solana account keys region truncated",
        ),
    ];
    for (blob, expected) in cases {
        let err = sign_and_broadcast_versioned(&rig.engine, &blob)
            .await
            .unwrap_err();
        assert!(err.contains(expected), "{blob}: {err}");
    }
}

#[tokio::test]
async fn a_signer_slot_beyond_the_declared_signatures_is_refused() {
    let rig = Rig::new();
    let signer = b58_to_pubkey(sample_address(WalletChain::Solana)).unwrap();
    // Two required signers but only one signature slot; we are the second.
    let mut message = Vec::new();
    message.extend([2u8, 0u8, 0u8]);
    message.extend(encode_shortvec(2));
    message.extend([9u8; 32]);
    message.extend(signer);
    message.extend([0u8; 32]);
    message.extend(encode_shortvec(0));
    let mut wire = Vec::new();
    wire.extend(encode_shortvec(1));
    wire.extend([0u8; 64]);
    wire.extend(&message);
    let err = sign_and_broadcast_versioned(&rig.engine, &hex::encode(&wire))
        .await
        .unwrap_err();
    assert_eq!(err, "Solana signer index exceeds signature slot count");
}

// ── reads ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn status_maps_finalized_pending_failed_and_unknown() {
    let rig = Rig::new();
    rig.transport
        .on_rpc("getSignatureStatuses", json!({"context": {"slot": 0}, "value": [{"slot": 123u64, "confirmations": null, "err": null}]}))
        .on_rpc("getSignatureStatuses", json!({"context": {"slot": 0}, "value": [{"slot": 124u64, "confirmations": 4u64, "err": null}]}))
        .on_rpc("getSignatureStatuses", json!({"context": {"slot": 0}, "value": [{"slot": 125u64, "confirmations": null, "err": {"InstructionError": [0, "Custom"]}}]}))
        .on_rpc("getSignatureStatuses", json!({"context": {"slot": 0}, "value": [null]}));
    let finalized = tx_status(&rig.engine, "s").await.unwrap();
    assert_eq!(
        (finalized.state, finalized.block_number),
        (TxState::Confirmed, Some(123))
    );
    let pending = tx_status(&rig.engine, "s").await.unwrap();
    assert_eq!(
        (pending.state, pending.confirmations),
        (TxState::Pending, Some(4))
    );
    assert_eq!(
        tx_status(&rig.engine, "s").await.unwrap().state,
        TxState::Failed
    );
    assert_eq!(
        tx_status(&rig.engine, "s").await.unwrap().state,
        TxState::NotFound
    );
    let params = rig.transport.first_rpc("getSignatureStatuses").unwrap();
    assert_eq!(params, json!([["s"], {"searchTransactionHistory": true}]));
}

#[tokio::test]
async fn receipts_report_success_fee_and_slot() {
    let rig = Rig::new();
    rig.transport
        .on_rpc(
            "getTransaction",
            json!({"slot": 9u64, "meta": {"err": null, "fee": 5000u64}}),
        )
        .on_rpc(
            "getTransaction",
            json!({"slot": 9u64, "meta": {"err": {"x": 1}, "fee": 5000u64}}),
        )
        .on_rpc("getTransaction", json!({"slot": 9u64}))
        .on_rpc("getTransaction", Value::Null);
    let ok = tx_receipt(&rig.engine, "s").await.unwrap();
    assert_eq!(
        (ok.found, ok.success, ok.block_number),
        (true, Some(true), Some(9))
    );
    assert_eq!(ok.fee_raw.as_deref(), Some("5000"));
    assert_eq!(
        tx_receipt(&rig.engine, "s").await.unwrap().success,
        Some(false)
    );
    assert_eq!(
        tx_receipt(&rig.engine, "s").await.unwrap().success,
        None,
        "no meta, no verdict"
    );
    assert!(!tx_receipt(&rig.engine, "s").await.unwrap().found);
}

#[tokio::test]
async fn lookup_passes_the_transaction_through() {
    let rig = Rig::new();
    rig.transport
        .on_rpc("getTransaction", json!({"slot": 1u64}))
        .on_rpc("getTransaction", Value::Null);
    let found = lookup_tx(&rig.engine, "s").await.unwrap();
    assert!(found.found);
    assert_eq!(found.raw["slot"], 1);
    assert!(!lookup_tx(&rig.engine, "s").await.unwrap().found);
    assert_eq!(
        rig.transport.first_rpc("getTransaction").unwrap(),
        json!(["s", {"maxSupportedTransactionVersion": 0, "encoding": "json"}])
    );
}
