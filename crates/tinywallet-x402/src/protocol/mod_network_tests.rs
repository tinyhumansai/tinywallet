//! Tests for paying a challenge on a caller-pinned network.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{HeaderMap, HeaderValue};

use super::*;
use crate::crypto::{CryptoPayments, PaymentSigner};
use crate::ledger::{self, SpendingBudget};
use crate::test_support::{
    FakePaymentSigner, FakeTransport, challenge, challenge_header, evm_requirement,
    solana_requirement,
};
use crate::wire::{BASE_MAINNET_CAIP2, PaymentPayload, PaymentProof};

const REQUEST_URL: &str = "https://x402.example.test/a";

fn headers(accepts: Vec<crate::wire::PaymentRequirements>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let value = challenge_header(&challenge(accepts));
    headers.insert("payment-required", HeaderValue::from_str(&value).unwrap());
    headers
}

fn payments() -> CryptoPayments {
    let signer: Arc<dyn PaymentSigner> = Arc::new(FakePaymentSigner::default());
    CryptoPayments::new(signer, Arc::new(FakeTransport::default()))
}

#[tokio::test]
async fn a_pinned_network_is_paid_even_when_another_is_preferred() {
    let _guard = ledger::TEST_LOCK.lock().await;
    ledger::init_global(
        ledger::LedgerStorage::memory(),
        "test-session",
        SpendingBudget::default(),
    )
    .unwrap();

    let result = handle_402_and_pay_on_network(
        &payments(),
        &headers(vec![solana_requirement(), evm_requirement()]),
        REQUEST_URL,
        Some(BASE_MAINNET_CAIP2),
        |_, requirement, chain, _| async move {
            assert_eq!(requirement.network, BASE_MAINNET_CAIP2);
            assert_eq!(chain, PaymentChain::Evm);
            Ok(())
        },
    )
    .await
    .unwrap();

    assert_eq!(result.network, BASE_MAINNET_CAIP2);
    assert_eq!(result.amount_atomic, 2_500);
    let payload: PaymentPayload =
        serde_json::from_slice(&B64.decode(&result.header_value).unwrap()).unwrap();
    assert!(matches!(payload.payload, PaymentProof::Evm(_)));
    drop(result);
    ledger::reset_global();
}

#[tokio::test]
async fn a_pin_the_challenge_cannot_meet_holds_and_signs_nothing() {
    let _guard = ledger::TEST_LOCK.lock().await;
    ledger::init_global(
        ledger::LedgerStorage::memory(),
        "test-session",
        SpendingBudget::default(),
    )
    .unwrap();
    let signer = Arc::new(FakePaymentSigner::default());
    let builder = CryptoPayments::new(signer.clone(), Arc::new(FakeTransport::default()));

    let error = handle_402_and_pay_on_network(
        &builder,
        &headers(vec![solana_requirement()]),
        REQUEST_URL,
        Some("eip155"),
        |_, _, _, _| async { panic!("nothing may be approved") },
    )
    .await
    .unwrap_err();

    assert_eq!(
        error.to_string(),
        "no supported payment option on eip155 in 402 challenge"
    );
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::reserved_atomic).unwrap(),
        0
    );
    assert!(signer.sign_calls.lock().unwrap().is_empty());
    ledger::reset_global();
}
