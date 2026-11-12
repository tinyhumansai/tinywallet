//! Tests for the EVM `upto` payment: the Permit2 permit, its signature, and
//! the `eip2612GasSponsoring` extension.
//!
//! The expected digests and signatures were produced by the x402 reference
//! client's own libraries (viem `hashTypedData` / `signTypedData` over the
//! reference type definitions) with the BIP-39 vector account; see
//! `eip712/permit2_tests.rs`. k256 and viem both sign with RFC 6979, so the
//! whole signature, not only the signer, must match.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use tinywallet_crypto::rpc::{NetworkId, TransportError};

use super::*;
use crate::crypto::CryptoPayments;
use crate::eip712;
use crate::protocol::PaymentBuilder;
use crate::test_support::{EVM_ADDRESS, FakePaymentSigner, FakeTransport};
use crate::wire::{PaymentProof, PaymentRequired};

const TWITR_UPTO: &str = include_str!("../wire/fixtures/twitr-upto-challenge.json");
/// The Permit2 nonce of the reference vector.
const NONCE: &str = "33247007178036348590600198031289925668252061821958005840077069883511451257277";
/// The deadline of the reference vector, reached with twitr's 300 s timeout.
const DEADLINE: u64 = 1_740_672_154;
const NOW: u64 = DEADLINE - 300;
const UPTO_SIGNATURE: &str = "0x9ab5dff608f9cde97db904773e2cca5188d24d47119bd64766bd80998e6750c453d5a9f9cdcd54a48bc189686de69d61d6a5b8a0922ff5520f8c0af5746015a21b";
const PERMIT2_CALLDATA_TAIL: &str =
    "000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3";

fn twitr() -> PaymentRequired {
    serde_json::from_str(TWITR_UPTO).unwrap()
}

fn word(value: u64) -> Value {
    json!(format!("0x{value:064x}"))
}

type TransportResult = tinywallet_crypto::rpc::TransportResult<Value>;

fn transport(replies: Vec<TransportResult>) -> FakeTransport {
    let transport = FakeTransport::default();
    transport.responses.lock().unwrap().extend(replies);
    transport
}

async fn build(
    challenge: &PaymentRequired,
    transport: &FakeTransport,
) -> Result<PaymentPayload, X402Error> {
    build_upto_payment_at(
        &FakePaymentSigner::default(),
        transport,
        challenge,
        &challenge.accepts[0],
        eip712::u256_from_decimal(NONCE).unwrap(),
        NOW,
    )
    .await
}

fn recover(digest: [u8; 32], signature_hex: &str) -> VerifyingKey {
    let bytes = hex::decode(signature_hex.trim_start_matches("0x")).unwrap();
    let signature = Signature::from_slice(&bytes[..64]).unwrap();
    let recovery = RecoveryId::from_byte(bytes[64] - 27).unwrap();
    VerifyingKey::recover_from_prehash(&digest, &signature, recovery).unwrap()
}

fn payer_key() -> VerifyingKey {
    *SigningKey::from_slice(&FakePaymentSigner::evm_secret())
        .unwrap()
        .verifying_key()
}

fn permit2(payload: &PaymentPayload) -> &crate::wire::Permit2PaymentProof {
    match &payload.payload {
        PaymentProof::Permit2(proof) => proof,
        other => panic!("expected a Permit2 proof, got {other:?}"),
    }
}

#[test]
fn the_terms_hash_to_the_reference_digest() {
    let terms = upto_terms(
        EVM_ADDRESS,
        &twitr().accepts[0],
        eip712::u256_from_decimal(NONCE).unwrap(),
        NOW,
    )
    .unwrap();
    assert_eq!(
        hex::encode(terms.digest()),
        "8e8c28bb23e744c0eb81bdfab664afc6c046d317a33873fdf0ffa275ecee94f9"
    );
}

#[tokio::test]
async fn the_twitr_challenge_yields_the_reference_payload() {
    // Allowance already covers the amount, so no permit is signed.
    let transport = transport(vec![Ok(word(1_000_000))]);
    let challenge = twitr();
    let payload = build(&challenge, &transport).await.unwrap();

    assert_eq!(payload.x402_version, 2);
    assert_eq!(
        payload.resource.as_ref().unwrap().url,
        challenge.resource.url
    );
    assert_eq!(
        serde_json::to_value(&payload.accepted).unwrap(),
        serde_json::from_str::<Value>(TWITR_UPTO).unwrap()["accepts"][0],
        "the server must find its own requirement in `accepted`"
    );
    let proof = permit2(&payload);
    assert_eq!(proof.signature, UPTO_SIGNATURE);
    assert_eq!(
        serde_json::to_value(&proof.permit2_authorization).unwrap(),
        json!({
            "from": EVM_ADDRESS,
            "permitted": {"token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "amount": "3600"},
            "spender": "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002",
            "nonce": NONCE,
            "deadline": DEADLINE.to_string(),
            "witness": {
                "to": "0xb5194A98DbDBb7028B585Db26B972e7F0F3f826A",
                "facilitator": "0x4c934c63C786157Fefd990945b25eA60a0FB0205",
                "validAfter": "0"
            }
        })
    );
}

#[tokio::test]
async fn sufficient_allowance_echoes_the_server_extensions_without_a_permit() {
    let transport = transport(vec![Ok(word(3600))]);
    let challenge = twitr();
    let payload = build(&challenge, &transport).await.unwrap();

    assert_eq!(
        Value::Object(payload.extensions.clone()),
        Value::Object(challenge.extensions.clone()),
        "the reference client echoes the server's extensions unchanged"
    );
    let calls = transport.calls.lock().unwrap();
    assert_eq!(calls.len(), 1, "only the allowance is read");
    assert_eq!(calls[0], (NetworkId::evm(8453), "eth_call".to_string()));
    let params = transport.params.lock().unwrap();
    assert_eq!(
        params[0][0]["to"],
        "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    );
    let data = params[0][0]["data"].as_str().unwrap();
    assert!(data.starts_with("0xdd62ed3e") && data.ends_with(PERMIT2_CALLDATA_TAIL));
    assert_eq!(params[0][1], "latest");
}

#[tokio::test]
async fn insufficient_allowance_adds_a_signed_eip2612_permit_for_permit2() {
    let transport = transport(vec![Ok(word(0)), Ok(word(7))]);
    let challenge = twitr();
    let payload = build(&challenge, &transport).await.unwrap();

    let sponsoring = &payload.extensions["eip2612GasSponsoring"];
    assert_eq!(
        sponsoring["schema"], challenge.extensions["eip2612GasSponsoring"]["schema"],
        "the server declaration is kept and the client info merged over it"
    );
    assert!(payload.extensions.contains_key("bazaar"));
    let info = &sponsoring["info"];
    assert_eq!(info["from"], EVM_ADDRESS);
    assert_eq!(info["asset"], "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913");
    assert_eq!(
        info["spender"],
        "0x000000000022D473030F116dDEE9F6B43aC78BA3"
    );
    assert_eq!(
        info["amount"], "3600",
        "the proxy requires value == permitted.amount"
    );
    assert_eq!(info["nonce"], "7");
    assert_eq!(info["deadline"], DEADLINE.to_string());
    assert_eq!(info["version"], "1");
    assert_eq!(
        info["description"],
        challenge.extensions["eip2612GasSponsoring"]["info"]["description"]
    );
    assert_eq!(
        info["signature"],
        "0x706f8899c02a49c682945a1d4f208446276be6493c33d74742aa53d2eb88807a5502da544b4a8053c3e67202aa115aaa78cdfbf2f1e780a8aa7245bc6e115cf41b",
        "the reference client's EIP-2612 signature for the same terms"
    );

    let permit = eip712::Eip2612Permit {
        owner: evm_address_bytes(EVM_ADDRESS).unwrap(),
        spender: eip712::PERMIT2,
        value: eip712::u256_from_u64(3600),
        nonce: eip712::u256_from_u64(7),
        deadline: eip712::u256_from_u64(DEADLINE),
    };
    let domain = eip712::domain_separator(
        evm_address_bytes("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913").unwrap(),
        8453,
        "USD Coin",
        "2",
    );
    assert_eq!(
        recover(
            eip712::signing_digest(domain, permit.struct_hash()),
            info["signature"].as_str().unwrap()
        ),
        payer_key()
    );
    let params = transport.params.lock().unwrap();
    let nonce_call = params[1][0]["data"].as_str().unwrap();
    assert!(nonce_call.starts_with("0x7ecebe00"));
}

#[tokio::test]
async fn an_unreadable_allowance_still_signs_the_permit() {
    let unreachable = Err(TransportError::Unreachable {
        network: NetworkId::evm(8453),
        message: "down".into(),
    });
    let transport = transport(vec![unreachable, Ok(word(0))]);
    let payload = build(&twitr(), &transport).await.unwrap();
    assert_eq!(
        payload.extensions["eip2612GasSponsoring"]["info"]["nonce"],
        "0"
    );
}

#[tokio::test]
async fn an_unreadable_token_nonce_fails_the_payment() {
    let transport = transport(vec![Ok(word(0)), Ok(json!({"not": "a word"}))]);
    let error = build(&twitr(), &transport).await.unwrap_err();
    assert!(
        matches!(&error, X402Error::Wallet(message) if message.contains("EIP-2612 nonce")),
        "{error}"
    );
}

#[tokio::test]
async fn no_permit_is_read_or_signed_unless_the_server_sponsors_it() {
    let mut challenge = twitr();
    challenge.extensions.remove("eip2612GasSponsoring");
    let transport = FakeTransport::default();
    let payload = build(&challenge, &transport).await.unwrap();
    assert!(transport.calls.lock().unwrap().is_empty());
    assert!(!payload.extensions.contains_key("eip2612GasSponsoring"));
    assert!(payload.extensions.contains_key("bazaar"));
}

#[tokio::test]
async fn no_permit_is_signed_without_the_token_domain() {
    let mut challenge = twitr();
    let extra = challenge.accepts[0].extra.as_mut().unwrap();
    extra.version = None;
    let transport = FakeTransport::default();
    let payload = build(&challenge, &transport).await.unwrap();
    assert!(transport.calls.lock().unwrap().is_empty());
    assert!(
        payload.extensions["eip2612GasSponsoring"]["info"]
            .get("signature")
            .is_none()
    );
}

#[tokio::test]
async fn a_bad_facilitator_or_recipient_is_a_protocol_error() {
    for (field, value) in [("facilitator", "0x1234"), ("payTo", "nope")] {
        let mut challenge = twitr();
        let requirement = &mut challenge.accepts[0];
        match field {
            "facilitator" => {
                requirement.extra.as_mut().unwrap().facilitator_address = Some(value.into());
            }
            _ => requirement.pay_to = value.into(),
        }
        let error = build(&challenge, &FakeTransport::default())
            .await
            .unwrap_err();
        assert!(matches!(error, X402Error::Protocol(_)), "{field}: {error}");
    }
    let mut challenge = twitr();
    challenge.accepts[0]
        .extra
        .as_mut()
        .unwrap()
        .facilitator_address = None;
    let error = build(&challenge, &FakeTransport::default())
        .await
        .unwrap_err();
    assert!(error.to_string().contains("facilitatorAddress"), "{error}");
}

#[tokio::test]
async fn the_deadline_is_capped_like_an_eip3009_authorization() {
    let mut challenge = twitr();
    challenge.accepts[0].max_timeout_seconds = 86_400;
    let payload = build(&challenge, &transport(vec![Ok(word(u64::MAX))]))
        .await
        .unwrap();
    assert_eq!(
        permit2(&payload).permit2_authorization.deadline,
        (NOW + 300).to_string()
    );
}

#[tokio::test]
async fn crypto_payments_pays_an_upto_requirement_with_a_permit2_proof() {
    let transport = std::sync::Arc::new(transport(vec![Ok(word(u64::MAX))]));
    let payments =
        CryptoPayments::new(std::sync::Arc::new(FakePaymentSigner::default()), transport);
    let challenge = twitr();
    let build = payments
        .build_with_metadata(&challenge, &challenge.accepts[0], PaymentChain::Evm)
        .await
        .unwrap();
    let proof = permit2(&build.payload);
    let deadline: i64 = proof.permit2_authorization.deadline.parse().unwrap();
    assert_eq!(
        build.authorization_valid_until,
        chrono::DateTime::from_timestamp(deadline, 0)
    );
    assert_ne!(proof.permit2_authorization.nonce, NONCE, "a fresh nonce");
    let terms = upto_terms(
        EVM_ADDRESS,
        &challenge.accepts[0],
        eip712::u256_from_decimal(&proof.permit2_authorization.nonce).unwrap(),
        u64::try_from(deadline).unwrap() - 300,
    )
    .unwrap();
    assert_eq!(recover(terms.digest(), &proof.signature), payer_key());
}

#[tokio::test]
async fn the_builder_refuses_a_transfer_method_other_than_permit2() {
    // Selection already skips these; the builder is reachable directly through
    // `pay_challenge_header`, so it checks again.
    let mut challenge = twitr();
    challenge.accepts[0].extra.as_mut().unwrap().asset_transfer_method = Some("eip3009".into());
    let error = build(&challenge, &FakeTransport::default()).await.unwrap_err();
    assert!(
        matches!(&error, X402Error::Protocol(m) if m.contains("assetTransferMethod")),
        "{error}"
    );

    let mut absent = twitr();
    absent.accepts[0].extra.as_mut().unwrap().asset_transfer_method = None;
    assert!(build(&absent, &transport(vec![Ok(word(u64::MAX))])).await.is_ok());
}
