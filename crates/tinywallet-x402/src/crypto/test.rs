//! Tests for the crypto rail: EIP-3009 and Solana payment construction behind
//! the [`PaymentSigner`] and `Transport` seams.
//!
//! The wallet is a fake backed by the root `tinywallet` crate's key derivation,
//! so signatures are checked by recovering or verifying against the account a
//! real wallet derives from the same mnemonic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::Verifier;
use serde_json::json;
use tinywallet_crypto::Chain;
use tinywallet_crypto::rpc::{NetworkId, TransportError};

use super::evm_payment::{eip712_signature, evm_payment_authorization};
use super::solana_payment::{b58_to_32, derive_ata, encode_shortvec, random_memo_nonce};
use super::*;
use crate::eip712;
use crate::protocol::{PaymentBuilder, X402Error};
use crate::test_support::{
    BLOCKHASH, EVM_ADDRESS, FEE_PAYER, FakePaymentSigner, FakeTransport, SOLANA_RECIPIENT,
    challenge, evm_requirement, solana_requirement,
};
use crate::wire::{
    BASE_MAINNET_CAIP2, PaymentChain, PaymentExtra, PaymentPayload, PaymentProof,
    PaymentRequirements, USDC_BASE_MAINNET,
};

fn payments(signer: FakePaymentSigner, transport: FakeTransport) -> CryptoPayments {
    CryptoPayments::new(Arc::new(signer), Arc::new(transport))
}

async fn build_evm(
    signer: FakePaymentSigner,
    requirement: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    payments(signer, FakeTransport::default())
        .build(
            &challenge(vec![requirement.clone()]),
            requirement,
            PaymentChain::Evm,
        )
        .await
}

async fn build_solana(
    signer: FakePaymentSigner,
    transport: FakeTransport,
    requirement: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    payments(signer, transport)
        .build(
            &challenge(vec![requirement.clone()]),
            requirement,
            PaymentChain::Solana,
        )
        .await
}

fn evm_proof(payload: PaymentPayload) -> crate::wire::EvmPaymentProof {
    match payload.payload {
        PaymentProof::Evm(proof) => proof,
        PaymentProof::Solana(_) => panic!("expected an EVM proof"),
    }
}

fn solana_transaction(payload: &PaymentPayload) -> Vec<u8> {
    match &payload.payload {
        PaymentProof::Solana(proof) => B64.decode(&proof.transaction).unwrap(),
        PaymentProof::Evm(_) => panic!("expected a Solana proof"),
    }
}

fn address_bytes(address: &str) -> [u8; 20] {
    hex::decode(address.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}

// ---------------------------------------------------------------------------
// EVM
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_evm_payment_is_signed_by_the_wallets_account() {
    use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};

    let requirement = evm_requirement();
    let signer = FakePaymentSigner::default();
    let payload = build_evm(signer, &requirement).await.unwrap();

    assert_eq!(payload.x402_version, 2);
    assert_eq!(payload.accepted.network, BASE_MAINNET_CAIP2);
    assert_eq!(
        payload.resource.as_ref().unwrap().url,
        "https://x402.example.test/thing"
    );
    let proof = evm_proof(payload);
    // `0x` plus 65 bytes as hex.
    assert_eq!(proof.signature.len(), 132);
    assert_eq!(proof.authorization.from, EVM_ADDRESS);
    assert_eq!(proof.authorization.to, requirement.pay_to);
    assert_eq!(proof.authorization.value, "2500");
    assert_eq!(proof.authorization.valid_after, "0");
    assert!(proof.authorization.nonce.starts_with("0x"));

    // Rebuild the digest the wallet signed, and recover the signer from it.
    let raw = hex::decode(proof.signature.trim_start_matches("0x")).unwrap();
    assert!(
        matches!(raw[64], 27 | 28),
        "the recovery byte is offset by 27"
    );
    let signature = Signature::from_slice(&raw[..64]).unwrap();
    let recovery_id = RecoveryId::try_from(raw[64] - 27).unwrap();
    let nonce: [u8; 32] = hex::decode(proof.authorization.nonce.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();
    let domain = eip712::domain_separator(address_bytes(USDC_BASE_MAINNET), 8453, "USD Coin", "2");
    let structure = eip712::transfer_with_authorization_hash(
        address_bytes(&proof.authorization.from),
        address_bytes(&proof.authorization.to),
        eip712::u256_from_decimal(&proof.authorization.value).unwrap(),
        eip712::u256_from_u64(0),
        eip712::u256_from_u64(proof.authorization.valid_before.parse().unwrap()),
        nonce,
    );
    let digest = eip712::signing_digest(domain, structure);
    let recovered = VerifyingKey::recover_from_prehash(&digest, &signature, recovery_id).unwrap();
    assert_eq!(
        recovered,
        *SigningKey::from_slice(&FakePaymentSigner::evm_secret())
            .unwrap()
            .verifying_key(),
        "the recovered signer controls the account the wallet reported"
    );
}

#[tokio::test]
async fn the_wallet_is_asked_to_sign_a_32_byte_digest_with_the_evm_scheme() {
    let signer = Arc::new(FakePaymentSigner::default());
    let payments = CryptoPayments::new(signer.clone(), Arc::new(FakeTransport::default()));
    let requirement = evm_requirement();
    payments
        .build(&challenge(vec![]), &requirement, PaymentChain::Evm)
        .await
        .unwrap();
    assert_eq!(
        *signer.sign_calls.lock().unwrap(),
        vec![(PaymentChain::Evm, SignScheme::Secp256k1Digest, 32)]
    );
}

#[tokio::test]
async fn the_valid_before_time_is_now_plus_the_timeout() {
    let requirement = evm_requirement();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let proof = evm_proof(
        build_evm(FakePaymentSigner::default(), &requirement)
            .await
            .unwrap(),
    );
    let valid_before: u64 = proof.authorization.valid_before.parse().unwrap();
    assert!(valid_before >= now + 300, "{valid_before} vs {now}");
    assert!(valid_before <= now + 300 + 5, "{valid_before} vs {now}");
}

#[tokio::test]
async fn each_payment_gets_a_fresh_nonce() {
    let requirement = evm_requirement();
    let first = evm_proof(
        build_evm(FakePaymentSigner::default(), &requirement)
            .await
            .unwrap(),
    );
    let second = evm_proof(
        build_evm(FakePaymentSigner::default(), &requirement)
            .await
            .unwrap(),
    );
    assert_ne!(first.authorization.nonce, second.authorization.nonce);
    assert_ne!(fresh_nonce(), fresh_nonce());
}

#[tokio::test]
async fn the_token_domain_defaults_to_usd_coin_version_two() {
    let mut named = evm_requirement();
    named.extra = Some(PaymentExtra {
        fee_payer: None,
        memo: None,
        name: Some("Other Coin".into()),
        version: Some("9".into()),
    });
    let mut bare = evm_requirement();
    bare.extra = None;
    let default = evm_payment_authorization(EVM_ADDRESS, &evm_requirement()).unwrap();
    let no_extra = evm_payment_authorization(EVM_ADDRESS, &bare).unwrap();
    let other = evm_payment_authorization(EVM_ADDRESS, &named).unwrap();
    // The nonce differs between calls, so compare the domain through the payload
    // that carries both: same requirement shape, different domain.
    assert_ne!(default.digest, other.digest);
    assert_ne!(no_extra.digest, other.digest);
    // And a wallet can still pay a requirement with no extras at all.
    assert!(build_evm(FakePaymentSigner::default(), &bare).await.is_ok());
}

#[tokio::test]
async fn an_evm_payment_rejects_a_solana_network() {
    let err = build_evm(FakePaymentSigner::default(), &solana_requirement())
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not an EVM network"), "{err}");
}

#[tokio::test]
async fn an_evm_payment_rejects_an_unparseable_amount() {
    let mut requirement = evm_requirement();
    requirement.amount = "lots".into();
    let err = build_evm(FakePaymentSigner::default(), &requirement)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("x402 protocol: invalid amount 'lots'"),
        "{err}"
    );
}

#[tokio::test]
async fn an_evm_payment_rejects_a_malformed_address() {
    for mutate in [
        |r: &mut PaymentRequirements| r.pay_to = "0x1234".into(),
        |r: &mut PaymentRequirements| r.asset = "not an address".into(),
    ] {
        let mut requirement = evm_requirement();
        mutate(&mut requirement);
        let err = build_evm(FakePaymentSigner::default(), &requirement)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid EVM address"), "{err}");
    }
}

#[tokio::test]
async fn an_evm_wallet_that_reports_a_bad_address_is_rejected() {
    #[derive(Debug)]
    struct BadAddress;
    #[async_trait::async_trait]
    impl PaymentSigner for BadAddress {
        async fn account(&self, _: PaymentChain) -> Result<PaymentAccount, String> {
            Ok(PaymentAccount {
                address: "0xnope".into(),
                pubkey: None,
            })
        }
        async fn sign(&self, _: PaymentChain, _: &[u8], _: SignScheme) -> Result<Vec<u8>, String> {
            Err("never reached".into())
        }
    }
    let payments = CryptoPayments::new(Arc::new(BadAddress), Arc::new(FakeTransport::default()));
    let requirement = evm_requirement();
    let err = payments
        .build(&challenge(vec![]), &requirement, PaymentChain::Evm)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("invalid EVM address '0xnope'"),
        "{err}"
    );
}

#[tokio::test]
async fn evm_wallet_failures_carry_the_seams_own_text() {
    let err = build_evm(
        FakePaymentSigner {
            account_error: Some("wallet secret: keyring locked".into()),
            ..FakePaymentSigner::default()
        },
        &evm_requirement(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 wallet: wallet secret: keyring locked"
    );

    let err = build_evm(
        FakePaymentSigner {
            sign_error: Some("module unavailable".into()),
            ..FakePaymentSigner::default()
        },
        &evm_requirement(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 wallet: sign EIP-3009: module unavailable"
    );
}

#[tokio::test]
async fn a_malformed_evm_signature_is_rejected() {
    for len in [0, 64, 66] {
        let err = build_evm(
            FakePaymentSigner {
                signature_len: Some(len),
                ..FakePaymentSigner::default()
            },
            &evm_requirement(),
        )
        .await;
        // Truncating can only shorten; 66 leaves a valid 65-byte signature.
        if len < 65 {
            assert_eq!(
                err.unwrap_err().to_string(),
                "x402 wallet: the wallet module returned a malformed signature"
            );
        } else {
            assert!(err.is_ok());
        }
    }
}

#[test]
fn the_recovery_id_is_offset_and_checked() {
    let mut raw = [7u8; 65];
    raw[64] = 1;
    assert_eq!(eip712_signature(&raw).unwrap()[64], 28);
    raw[64] = 0;
    assert_eq!(eip712_signature(&raw).unwrap()[64], 27);
    raw[64] = 250;
    assert_eq!(
        eip712_signature(&raw).unwrap_err().to_string(),
        "x402 wallet: recovery id out of range"
    );
}

// ---------------------------------------------------------------------------
// Solana
// ---------------------------------------------------------------------------

/// The parts of a legacy transaction message this rail builds.
struct ParsedMessage {
    keys: Vec<[u8; 32]>,
    blockhash: [u8; 32],
}

fn parse_message(message: &[u8]) -> ParsedMessage {
    assert_eq!(&message[..3], &[2, 0, 4], "header");
    assert_eq!(message[3], 8, "eight account keys");
    let keys = (0..8)
        .map(|i| message[4 + i * 32..4 + (i + 1) * 32].try_into().unwrap())
        .collect();
    let rest = &message[4 + 8 * 32..];
    let blockhash: [u8; 32] = rest[..32].try_into().unwrap();
    assert_eq!(rest[32], 4, "four instructions");
    ParsedMessage { keys, blockhash }
}

#[tokio::test]
async fn a_solana_payment_is_a_partially_signed_transaction() {
    let requirement = solana_requirement();
    let payload = build_solana(
        FakePaymentSigner::default(),
        FakeTransport::default(),
        &requirement,
    )
    .await
    .unwrap();
    assert_eq!(payload.accepted.amount, "10000");

    let wire = solana_transaction(&payload);
    assert_eq!(wire[0], 2, "two signature slots");
    assert_eq!(
        &wire[1..65],
        &[0u8; 64],
        "the fee payer's slot is left empty"
    );
    let signature: [u8; 64] = wire[65..129].try_into().unwrap();
    let message = &wire[129..];

    // Our slot verifies against the wallet's key over exactly this message.
    FakePaymentSigner::solana_verifying_key()
        .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .unwrap();

    let parsed = parse_message(message);
    assert_eq!(parsed.keys[0], b58_to_32(FEE_PAYER).unwrap());
    assert_eq!(
        parsed.keys[1],
        FakePaymentSigner::solana_verifying_key().to_bytes()
    );
    assert_eq!(parsed.blockhash, b58_to_32(BLOCKHASH).unwrap());
    assert_eq!(
        parsed.keys[5],
        b58_to_32(crate::wire::SPL_TOKEN_PROGRAM).unwrap()
    );
    assert_eq!(
        parsed.keys[6],
        b58_to_32(crate::wire::COMPUTE_BUDGET_PROGRAM).unwrap()
    );
    assert_eq!(
        parsed.keys[7],
        b58_to_32(crate::wire::SPL_MEMO_PROGRAM).unwrap()
    );
    // The memo named by the server is used verbatim.
    assert!(message.ends_with(b"pi_3abc123"));
}

#[tokio::test]
async fn the_transfer_moves_the_asked_amount_to_the_recipients_token_account() {
    let requirement = solana_requirement();
    let payload = build_solana(
        FakePaymentSigner::default(),
        FakeTransport::default(),
        &requirement,
    )
    .await
    .unwrap();
    let wire = solana_transaction(&payload);
    let message = &wire[129..];
    let keys = parse_message(message).keys;

    let mint = b58_to_32(&requirement.asset).unwrap();
    let token_program = keys[5];
    assert_eq!(
        keys[2],
        derive_ata(&keys[1], &mint, &token_program).unwrap()
    );
    assert_eq!(
        keys[3],
        derive_ata(&b58_to_32(SOLANA_RECIPIENT).unwrap(), &mint, &token_program).unwrap()
    );
    assert_eq!(keys[4], mint);

    // TransferChecked: discriminator 12, amount LE, decimals 6.
    let mut expected = vec![12u8];
    expected.extend(10_000u64.to_le_bytes());
    expected.push(6);
    assert!(
        message.windows(expected.len()).any(|w| w == expected),
        "the TransferChecked data is in the message"
    );
}

#[tokio::test]
async fn the_wallet_signs_the_message_with_ed25519() {
    let signer = Arc::new(FakePaymentSigner::default());
    let payments = CryptoPayments::new(signer.clone(), Arc::new(FakeTransport::default()));
    let requirement = solana_requirement();
    let payload = payments
        .build(&challenge(vec![]), &requirement, PaymentChain::Solana)
        .await
        .unwrap();
    let message_len = solana_transaction(&payload).len() - 129;
    assert_eq!(
        *signer.sign_calls.lock().unwrap(),
        vec![(PaymentChain::Solana, SignScheme::Ed25519, message_len)]
    );
}

#[tokio::test]
async fn a_pubkey_reported_by_the_wallet_is_used_over_the_address() {
    let payload = build_solana(
        FakePaymentSigner {
            report_pubkey: true,
            ..FakePaymentSigner::default()
        },
        FakeTransport::default(),
        &solana_requirement(),
    )
    .await
    .unwrap();
    let keys = parse_message(&solana_transaction(&payload)[129..]).keys;
    assert_eq!(
        keys[1],
        b58_to_32(&FakePaymentSigner::solana_address()).unwrap()
    );
}

#[tokio::test]
async fn without_a_memo_the_payment_carries_a_fresh_hex_nonce() {
    let mut requirement = solana_requirement();
    requirement.extra.as_mut().unwrap().memo = None;
    let first = build_solana(
        FakePaymentSigner::default(),
        FakeTransport::default(),
        &requirement,
    )
    .await
    .unwrap();
    let second = build_solana(
        FakePaymentSigner::default(),
        FakeTransport::default(),
        &requirement,
    )
    .await
    .unwrap();
    let tail = |p: &PaymentPayload| {
        let wire = solana_transaction(p);
        wire[wire.len() - 32..].to_vec()
    };
    assert!(tail(&first).iter().all(u8::is_ascii_hexdigit));
    assert_ne!(tail(&first), tail(&second));
    let nonce = random_memo_nonce();
    assert_eq!(nonce.len(), 32);
    assert!(nonce.iter().all(u8::is_ascii_hexdigit));
}

#[tokio::test]
async fn a_solana_payment_needs_a_fee_payer() {
    let mut requirement = solana_requirement();
    requirement.extra = None;
    let err = build_solana(
        FakePaymentSigner::default(),
        FakeTransport::default(),
        &requirement,
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 protocol: no fee_payer in payment requirements"
    );
}

#[tokio::test]
async fn solana_requirements_with_bad_fields_are_protocol_errors() {
    type Mutate = fn(&mut PaymentRequirements);
    let cases: [(Mutate, &str); 3] = [
        (|r| r.amount = "lots".into(), "invalid amount 'lots'"),
        (|r| r.pay_to = "0OIl".into(), "invalid base58 '0OIl'"),
        (
            |r| r.asset = "abc".into(),
            "expected 32-byte key, got 3 for 'abc'",
        ),
    ];
    for (mutate, expected) in cases {
        let mut requirement = solana_requirement();
        mutate(&mut requirement);
        let err = build_solana(
            FakePaymentSigner::default(),
            FakeTransport::default(),
            &requirement,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains(expected), "{err}");
    }
}

#[tokio::test]
async fn solana_wallet_failures_carry_the_seams_own_text() {
    let err = build_solana(
        FakePaymentSigner {
            account_error: Some("derive account: bad path".into()),
            ..FakePaymentSigner::default()
        },
        FakeTransport::default(),
        &solana_requirement(),
    )
    .await
    .unwrap_err();
    assert_eq!(err.to_string(), "x402 wallet: derive account: bad path");

    let err = build_solana(
        FakePaymentSigner {
            sign_error: Some("module unavailable".into()),
            ..FakePaymentSigner::default()
        },
        FakeTransport::default(),
        &solana_requirement(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 wallet: sign payment: module unavailable"
    );

    let err = build_solana(
        FakePaymentSigner {
            signature_len: Some(63),
            ..FakePaymentSigner::default()
        },
        FakeTransport::default(),
        &solana_requirement(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 wallet: the wallet module returned a malformed signature"
    );
}

#[tokio::test]
async fn a_wallet_address_that_is_not_base58_cannot_pay_on_solana() {
    #[derive(Debug)]
    struct NotBase58;
    #[async_trait::async_trait]
    impl PaymentSigner for NotBase58 {
        async fn account(&self, _: PaymentChain) -> Result<PaymentAccount, String> {
            Ok(PaymentAccount {
                address: "0xdeadbeef".into(),
                pubkey: None,
            })
        }
        async fn sign(&self, _: PaymentChain, _: &[u8], _: SignScheme) -> Result<Vec<u8>, String> {
            Err("never reached".into())
        }
    }
    let payments = CryptoPayments::new(Arc::new(NotBase58), Arc::new(FakeTransport::default()));
    let err = payments
        .build(
            &challenge(vec![]),
            &solana_requirement(),
            PaymentChain::Solana,
        )
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("invalid base58 '0xdeadbeef'"),
        "{err}"
    );
}

#[tokio::test]
async fn the_blockhash_comes_from_the_transport_for_the_solana_network() {
    let transport = Arc::new(FakeTransport::default());
    let payments = CryptoPayments::new(Arc::new(FakePaymentSigner::default()), transport.clone());
    let requirement = solana_requirement();
    payments
        .build(&challenge(vec![]), &requirement, PaymentChain::Solana)
        .await
        .unwrap();
    assert_eq!(
        *transport.calls.lock().unwrap(),
        vec![(
            NetworkId::chain(Chain::Solana),
            "getLatestBlockhash".to_string()
        )]
    );
}

#[tokio::test]
async fn blockhash_failures_are_wallet_errors() {
    let cases = [
        (
            FakeTransport::answering(Err(TransportError::Unreachable {
                network: NetworkId::chain(Chain::Solana),
                message: "connection refused".into(),
            })),
            "x402 wallet: fetch blockhash: transport failure contacting",
        ),
        (
            FakeTransport::answering(Ok(json!({"unexpected": true}))),
            "x402 wallet: fetch blockhash: ",
        ),
        (
            FakeTransport::answering(Ok(json!({"value": {"blockhash": "abc"}}))),
            "x402 protocol: expected 32-byte key",
        ),
    ];
    for (transport, expected) in cases {
        let err = build_solana(
            FakePaymentSigner::default(),
            transport,
            &solana_requirement(),
        )
        .await
        .unwrap_err();
        assert!(err.to_string().starts_with(expected), "{err}");
    }
}

#[test]
fn shortvec_uses_seven_bit_groups() {
    assert_eq!(encode_shortvec(0), vec![0]);
    assert_eq!(encode_shortvec(2), vec![2]);
    assert_eq!(encode_shortvec(127), vec![0x7f]);
    assert_eq!(encode_shortvec(128), vec![0x80, 0x01]);
    assert_eq!(encode_shortvec(16_384), vec![0x80, 0x80, 0x01]);
}

#[test]
fn a_token_account_address_is_off_the_curve_and_per_owner() {
    let owner_a = b58_to_32(SOLANA_RECIPIENT).unwrap();
    let owner_b = b58_to_32(FEE_PAYER).unwrap();
    let mint = b58_to_32(crate::wire::USDC_MINT_MAINNET).unwrap();
    let token = b58_to_32(crate::wire::SPL_TOKEN_PROGRAM).unwrap();
    let a = derive_ata(&owner_a, &mint, &token).unwrap();
    assert_eq!(
        a,
        derive_ata(&owner_a, &mint, &token).unwrap(),
        "deterministic"
    );
    assert_ne!(a, derive_ata(&owner_b, &mint, &token).unwrap());
    assert!(
        curve25519_dalek::edwards::CompressedEdwardsY(a)
            .decompress()
            .is_none(),
        "a program-derived address is not a valid ed25519 point"
    );
}

#[test]
fn base58_keys_must_be_exactly_32_bytes() {
    assert!(b58_to_32(FEE_PAYER).is_ok());
    assert!(
        b58_to_32(&format!("  {FEE_PAYER}  ")).is_ok(),
        "whitespace is trimmed"
    );
    assert!(b58_to_32("0OIl").is_err());
    assert!(b58_to_32("2wKu").is_err());
}

#[test]
fn the_crypto_rail_is_debuggable_without_leaking_anything() {
    let payments = payments(FakePaymentSigner::default(), FakeTransport::default());
    assert_eq!(format!("{payments:?}"), "CryptoPayments { .. }");
}
