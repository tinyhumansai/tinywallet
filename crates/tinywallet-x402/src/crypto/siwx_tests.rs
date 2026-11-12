//! Tests for the `sign-in-with-x` proof: the EIP-4361 message, its EIP-191
//! signature, the header, and every refusal.
//!
//! The expected messages and signatures were produced by the x402 reference
//! client's own libraries: `@signinwithethereum/siwe` `prepareMessage()` (what
//! the reference's `formatSIWEMessage` calls) and viem `signMessage` /
//! `hashMessage`, with the BIP-39 vector account.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Utc};
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};

use super::*;
use crate::test_support::{EVM_ADDRESS, FakePaymentSigner};
use crate::wire::{PaymentRequired, SiwxInfo};

const TWITR_SIWX: &str = include_str!("../wire/fixtures/twitr-siwx-challenge.json");
const TWITR_URL: &str = "https://twitr.sh/api/x-accounts/start";

const SIWE_FULL: &str = "twitr.sh wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\nSign in to connect an account\n\nURI: https://twitr.sh/api/x-accounts/start\nVersion: 1\nChain ID: 8453\nNonce: c3dae5e13c973fa183371bf7fa769206\nIssued At: 2026-11-12T19:40:12.348Z\nExpiration Time: 2026-11-12T19:45:12.348Z\nResources:\n- https://twitr.sh/api/x-accounts/start";
const SIWE_FULL_SIGNATURE: &str = "0xe1b40232340ee327925f48ff33c416ff59a03fc3938e769334ebfeed1bba39d87e8108ac7bf0cd35186fbfec0bcfcc3213fa44115b39ea65cd61abdc564668c91b";
const SIWE_BARE: &str = "twitr.sh wants you to sign in with your Ethereum account:\n0x9858EfFD232B4033E47d90003D41EC34EcaEda94\n\n\nURI: https://twitr.sh/api/x-accounts/start\nVersion: 1\nChain ID: 84532\nNonce: abcdef0123456789\nIssued At: 2026-11-12T19:40:12.348Z\nNot Before: 2026-11-12T19:40:00.000Z\nRequest ID: req-1";
const SIWE_BARE_DIGEST: &str = "c053a0ec57ae652fdf2b9dbeebcf598e4632366244a283b9cac23053f6b55e8b";

/// Inside the fixture's validity window.
fn now() -> DateTime<Utc> {
    "2026-11-12T19:41:00Z".parse().unwrap()
}

fn twitr() -> PaymentRequired {
    serde_json::from_str(TWITR_SIWX).unwrap()
}

fn twitr_info() -> SiwxInfo {
    serde_json::from_value(twitr().extensions["sign-in-with-x"]["info"].clone()).unwrap()
}

/// `twitr()` with `edit` applied to its raw `sign-in-with-x` extension.
fn twitr_with(edit: impl FnOnce(&mut Value)) -> PaymentRequired {
    let mut challenge = twitr();
    edit(challenge.extensions.get_mut("sign-in-with-x").unwrap());
    challenge
}

fn recover(digest: [u8; 32], signature_hex: &str) -> VerifyingKey {
    let bytes = hex::decode(signature_hex.trim_start_matches("0x")).unwrap();
    let signature = Signature::from_slice(&bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(bytes[64] - 27).unwrap();
    VerifyingKey::recover_from_prehash(&digest, &signature, recovery).unwrap()
}

async fn sign(challenge: &PaymentRequired, url: &str) -> Result<SiwxProof, X402Error> {
    sign_in_with_x_at(&FakePaymentSigner::default(), challenge, url, now()).await
}

#[test]
fn the_message_is_the_reference_siwe_text() {
    assert_eq!(siwe_message(&twitr_info(), 8453, EVM_ADDRESS), SIWE_FULL);
}

#[test]
fn optional_fields_are_laid_out_as_the_reference_does() {
    let mut info = twitr_info();
    info.statement = None;
    info.nonce = "abcdef0123456789".into();
    info.expiration_time = None;
    info.not_before = Some("2026-11-12T19:40:00.000Z".into());
    info.request_id = Some("req-1".into());
    info.resources = None;
    let message = siwe_message(&info, 84532, EVM_ADDRESS);
    assert_eq!(message, SIWE_BARE);
    assert_eq!(hex::encode(eip191_digest(&message)), SIWE_BARE_DIGEST);
}

#[tokio::test]
async fn the_twitr_challenge_is_signed_exactly_as_the_reference_client_signs_it() {
    let signer = FakePaymentSigner::default();
    let proof = sign_in_with_x_at(&signer, &twitr(), TWITR_URL, now()).await.unwrap();

    assert_eq!(proof.address, EVM_ADDRESS);
    assert_eq!(proof.chain_id, "eip155:8453");
    let payload: Value = serde_json::from_slice(&B64.decode(&proof.header_value).unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({
            "domain": "twitr.sh",
            "address": EVM_ADDRESS,
            "statement": "Sign in to connect an account",
            "uri": TWITR_URL,
            "version": "1",
            "chainId": "eip155:8453",
            "type": "eip191",
            "nonce": "c3dae5e13c973fa183371bf7fa769206",
            "issuedAt": "2026-11-12T19:40:12.348Z",
            "expirationTime": "2026-11-12T19:45:12.348Z",
            "resources": [TWITR_URL],
            "signature": SIWE_FULL_SIGNATURE
        })
    );
    // Recovered independently of the reference: EIP-191 over the SIWE text.
    assert_eq!(
        recover(eip191_digest(SIWE_FULL), SIWE_FULL_SIGNATURE),
        *SigningKey::from_slice(&FakePaymentSigner::evm_secret())
            .unwrap()
            .verifying_key()
    );
    assert_eq!(signer.sign_calls.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn base_is_preferred_whatever_order_the_server_lists_chains_in() {
    let challenge = twitr_with(|siwx| {
        siwx["supportedChains"] = json!([
            {"chainId": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "type": "ed25519"},
            {"chainId": "eip155:84532", "type": "eip191"},
            {"chainId": "eip155:8453", "type": "eip191"}
        ]);
    });
    assert_eq!(sign(&challenge, TWITR_URL).await.unwrap().chain_id, "eip155:8453");

    let challenge = twitr_with(|siwx| {
        siwx["supportedChains"] = json!([
            {"chainId": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "type": "ed25519"},
            {"chainId": "eip155:1", "type": "eip1271"},
            {"chainId": "eip155:84532", "type": "eip191"}
        ]);
    });
    assert_eq!(sign(&challenge, TWITR_URL).await.unwrap().chain_id, "eip155:84532");
}

/// Every way a challenge can ask for something this must not sign.
#[tokio::test]
async fn a_challenge_outside_the_rules_is_refused_before_signing() {
    let refusals: Vec<(&str, PaymentRequired, &str)> = vec![
        ("no extension", {
            let mut c = twitr();
            c.extensions.clear();
            c
        }, TWITR_URL),
        ("domain of another host", twitr(), "https://evil.example/api/x-accounts/start"),
        ("plain http request", twitr(), "http://twitr.sh/api/x-accounts/start"),
        ("domain mismatch", twitr_with(|s| s["info"]["domain"] = "evil.example".into()), TWITR_URL),
        ("uri on another host", twitr_with(|s| s["info"]["uri"] = "https://evil.example/x".into()), TWITR_URL),
        ("uri over http", twitr_with(|s| s["info"]["uri"] = "http://twitr.sh/x".into()), TWITR_URL),
        ("resource on another host", twitr_with(|s| s["info"]["resources"] = json!(["https://evil.example/r"])), TWITR_URL),
        ("resource not a URI", twitr_with(|s| s["info"]["resources"] = json!(["not a uri"])), TWITR_URL),
        ("expired", twitr_with(|s| s["info"]["expirationTime"] = "2026-11-12T19:40:59Z".into()), TWITR_URL),
        ("no expiry", twitr_with(|s| { s["info"].as_object_mut().unwrap().remove("expirationTime"); }), TWITR_URL),
        ("issued in the future", twitr_with(|s| s["info"]["issuedAt"] = "2026-11-12T20:41:00Z".into()), TWITR_URL),
        ("issuedAt not a date", twitr_with(|s| s["info"]["issuedAt"] = "yesterday".into()), TWITR_URL),
        ("notBefore not a date", twitr_with(|s| s["info"]["notBefore"] = "soon\nURI: x".into()), TWITR_URL),
        ("statement with a line break", twitr_with(|s| s["info"]["statement"] = "hi\nURI: https://evil.example".into()), TWITR_URL),
        ("requestId with a line break", twitr_with(|s| s["info"]["requestId"] = "a\nb".into()), TWITR_URL),
        ("short nonce", twitr_with(|s| s["info"]["nonce"] = "abc".into()), TWITR_URL),
        ("nonce with punctuation", twitr_with(|s| s["info"]["nonce"] = "abcdefgh!".into()), TWITR_URL),
        ("another version", twitr_with(|s| s["info"]["version"] = "2".into()), TWITR_URL),
        ("no EVM chain", twitr_with(|s| s["supportedChains"] = json!([{"chainId": "solana:x", "type": "ed25519"}])), TWITR_URL),
        ("no eip191 chain", twitr_with(|s| s["supportedChains"] = json!([{"chainId": "eip155:8453", "type": "eip1271"}])), TWITR_URL),
        ("malformed chain id", twitr_with(|s| s["supportedChains"] = json!([{"chainId": "eip155:base", "type": "eip191"}])), TWITR_URL),
        ("not an object", twitr_with(|s| *s = json!("sign me")), TWITR_URL),
    ];
    for (case, challenge, url) in refusals {
        let signer = FakePaymentSigner::default();
        let error = sign_in_with_x_at(&signer, &challenge, url, now())
            .await
            .unwrap_err();
        assert!(matches!(error, X402Error::SignInRefused { .. }), "{case}: {error}");
        assert!(signer.sign_calls.lock().unwrap().is_empty(), "{case}: signed");
    }
}

#[tokio::test]
async fn a_wallet_failure_is_a_wallet_error() {
    let signer = FakePaymentSigner {
        sign_error: Some("locked".into()),
        ..FakePaymentSigner::default()
    };
    let error = sign_in_with_x_at(&signer, &twitr(), TWITR_URL, now())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "x402 wallet: sign sign-in-with-x: locked");
}

#[test]
fn the_refusal_message_is_pinned() {
    assert_eq!(
        X402Error::SignInRefused {
            reason: "expired".into()
        }
        .to_string(),
        "x402 sign-in-with-x refused: expired"
    );
}
