//! Tests for the 402 protocol: header codec, challenge selection, the budgeted
//! `handle_402_and_pay`, and the retrying [`X402Client`] against a loopback
//! server.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use reqwest::header::{HeaderMap, HeaderValue};
use tinywallet_crypto::rpc::Transport;

use super::*;
use crate::crypto::{CryptoPayments, PaymentSigner};
use crate::ledger::{self, PaymentRecord, PaymentStatus, SpendingBudget};
use crate::test_support::{
    FakePaymentSigner, FakeTransport, RecordedRequest, ServerConfig, TestServer, challenge,
    challenge_header, evm_requirement, solana_requirement,
};
use crate::wire::{
    PaymentChain, PaymentPayload, PaymentProof, PaymentRequired, PaymentRequirements,
    SettlementResponse, SolanaPaymentProof, X402_VERSION,
};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A request on the origin the fixture challenge names as its resource.
const REQUEST_URL: &str = "https://x402.example.test/a";

/// A builder that answers with a fixed proof and remembers what it was asked.
#[derive(Default)]
struct StubBuilder {
    fail_with: Option<String>,
    chains: Mutex<Vec<PaymentChain>>,
    finalized_height: Option<u64>,
}

#[async_trait]
impl PaymentBuilder for StubBuilder {
    async fn build(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        self.chains.lock().unwrap().push(chain);
        if let Some(message) = &self.fail_with {
            return Err(X402Error::Wallet(message.clone()));
        }
        Ok(PaymentPayload {
            x402_version: X402_VERSION,
            resource: Some(challenge.resource.clone()),
            accepted: requirement.clone(),
            payload: PaymentProof::Solana(SolanaPaymentProof {
                transaction: "stub-tx".into(),
            }),
            extensions: serde_json::Map::new(),
        })
    }

    async fn finalized_solana_block_height(&self) -> Result<Option<u64>, X402Error> {
        Ok(self.finalized_height)
    }
}

struct LegacyMetadataBuilder;

#[async_trait]
impl PaymentBuilder for LegacyMetadataBuilder {
    async fn build(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        let payload = match chain {
            PaymentChain::Evm => PaymentProof::Evm(crate::wire::EvmPaymentProof {
                signature: "0x00".into(),
                authorization: crate::wire::EvmAuthorization {
                    from: "from".into(),
                    to: "to".into(),
                    value: "1".into(),
                    valid_after: "0".into(),
                    valid_before: "1800000000".into(),
                    nonce: "0x00".into(),
                },
            }),
            PaymentChain::Solana => PaymentProof::Solana(SolanaPaymentProof {
                transaction: "stub-tx".into(),
            }),
        };
        Ok(PaymentPayload {
            x402_version: X402_VERSION,
            resource: Some(challenge.resource.clone()),
            accepted: requirement.clone(),
            payload,
            extensions: serde_json::Map::new(),
        })
    }
}

#[tokio::test]
async fn legacy_payment_builders_keep_safe_default_metadata() {
    let builder = LegacyMetadataBuilder;
    let evm = builder
        .build_with_metadata(&challenge(vec![]), &evm_requirement(), PaymentChain::Evm)
        .await
        .unwrap();
    assert_eq!(
        evm.authorization_valid_until,
        chrono::DateTime::from_timestamp(1_800_000_000, 0)
    );
    assert_eq!(evm.solana_last_valid_block_height, None);

    let solana = builder
        .build_with_metadata(
            &challenge(vec![]),
            &solana_requirement(),
            PaymentChain::Solana,
        )
        .await
        .unwrap();
    assert_eq!(solana.authorization_valid_until, None);
    assert_eq!(solana.solana_last_valid_block_height, None);
    assert_eq!(builder.finalized_solana_block_height().await.unwrap(), None);
}

fn headers_with(name: &'static str, value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(name, HeaderValue::from_str(value).unwrap());
    headers
}

fn challenge_headers(challenge: &PaymentRequired) -> HeaderMap {
    headers_with("payment-required", &challenge_header(challenge))
}

fn settlement(success: bool, transaction: &str) -> String {
    B64.encode(
        serde_json::to_vec(&SettlementResponse {
            success,
            transaction: transaction.into(),
            network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
            payer: None,
            error_reason: (!success).then(|| "insufficient_funds".to_string()),
            amount: None,
            extensions: serde_json::Map::new(),
        })
        .unwrap(),
    )
}

fn crypto_payments(signer: FakePaymentSigner) -> Arc<dyn PaymentBuilder> {
    let signer: Arc<dyn PaymentSigner> = Arc::new(signer);
    let transport: Arc<dyn Transport> = Arc::new(FakeTransport::default());
    Arc::new(CryptoPayments::new(signer, transport))
}

fn client_with(builder: Arc<dyn PaymentBuilder>) -> X402Client {
    X402Client::new(reqwest::Client::new(), builder)
}

fn get(_client: &X402Client, url: &str) -> reqwest::Request {
    reqwest::Client::new().get(url).build().unwrap()
}

fn init_ledger(budget: SpendingBudget) -> ledger::LedgerStorage {
    let storage = ledger::LedgerStorage::memory();
    ledger::init_global(storage.clone(), "test-session", budget).unwrap();
    storage
}

fn settled(amount: u64) -> PaymentRecord {
    PaymentRecord {
        id: "settled".into(),
        url: "https://x402.example.test".into(),
        asset: "USDC".into(),
        amount_atomic: amount,
        amount_display: String::new(),
        recipient: "r".into(),
        network: "n".into(),
        tx_signature: None,
        status: PaymentStatus::Settled,
        timestamp: chrono::Utc::now(),
        authorization_valid_until: None,
        solana_last_valid_block_height: None,
        authorization_expired_at: None,
        authorization_expiry_observed_height: None,
        session_id: "test-session".into(),
        thread_id: None,
        scheme: None,
    }
}

#[tokio::test]
async fn solana_refresh_uses_height_evidence_and_preserves_pending_value() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let mut pending = settled(100_000);
    pending.id = "refresh-solana".into();
    pending.status = PaymentStatus::Pending;
    pending.timestamp = chrono::Utc::now();
    pending.solana_last_valid_block_height = Some(9);
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(pending))
        .unwrap()
        .unwrap();

    refresh_solana_authorizations(&StubBuilder::default())
        .await
        .unwrap();
    assert_eq!(
        ledger::with_ledger(|ledger| ledger.usable_pending_count(chrono::Utc::now())).unwrap(),
        1
    );

    refresh_solana_authorizations(&StubBuilder {
        finalized_height: Some(10),
        ..StubBuilder::default()
    })
    .await
    .unwrap();
    let latest = ledger::with_ledger(|ledger| ledger.payment("refresh-solana").cloned())
        .unwrap()
        .unwrap();
    assert_eq!(latest.status, PaymentStatus::Pending);
    assert_eq!(latest.solana_last_valid_block_height, Some(9));
    assert_eq!(latest.authorization_expiry_observed_height, Some(10));
    assert!(latest.authorization_expired_at.is_some());
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::outstanding_atomic).unwrap(),
        100_000
    );
    ledger::reset_global();
}

struct ReceiptDuringHeightRefresh;

#[async_trait]
impl PaymentBuilder for ReceiptDuringHeightRefresh {
    async fn build(
        &self,
        _challenge: &PaymentRequired,
        _requirement: &PaymentRequirements,
        _chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        unreachable!("refresh-only fixture never builds a payment")
    }

    async fn finalized_solana_block_height(&self) -> Result<Option<u64>, X402Error> {
        ledger::with_ledger_mut(|ledger| {
            let mut record = ledger.payment("receipt-during-refresh").unwrap().clone();
            record.status = PaymentStatus::Settled;
            record.timestamp += chrono::Duration::seconds(1);
            record.tx_signature = Some("trusted-receipt".into());
            ledger.try_record_payment(record)
        })
        .unwrap()
        .unwrap();
        Ok(Some(10))
    }
}

#[tokio::test]
async fn a_receipt_arriving_during_height_refresh_cannot_be_overwritten() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let mut pending = settled(100_000);
    pending.id = "receipt-during-refresh".into();
    pending.status = PaymentStatus::Pending;
    pending.solana_last_valid_block_height = Some(9);
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(pending))
        .unwrap()
        .unwrap();

    refresh_solana_authorizations(&ReceiptDuringHeightRefresh)
        .await
        .unwrap();
    let latest =
        ledger::with_ledger(|ledger| ledger.payment("receipt-during-refresh").unwrap().clone())
            .unwrap();
    assert_eq!(latest.status, PaymentStatus::Settled);
    assert_eq!(latest.tx_signature.as_deref(), Some("trusted-receipt"));
    assert_eq!(latest.authorization_expired_at, None);
    assert_eq!(
        ledger::with_ledger(|ledger| ledger.recent_payments(2).len()).unwrap(),
        2
    );
    ledger::reset_global();
}

struct ReopenLedgerDuringHeightRefresh {
    storage: ledger::LedgerStorage,
}

#[async_trait]
impl PaymentBuilder for ReopenLedgerDuringHeightRefresh {
    async fn build(
        &self,
        _challenge: &PaymentRequired,
        _requirement: &PaymentRequirements,
        _chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        unreachable!("refresh-only fixture never builds a payment")
    }

    async fn finalized_solana_block_height(&self) -> Result<Option<u64>, X402Error> {
        // Reopening the same storage restores the exact same latest payment
        // record, but it is a distinct in-memory ledger instance. Evidence
        // requested for the old instance must not mutate the replacement.
        ledger::init_global(
            self.storage.clone(),
            "test-session",
            SpendingBudget::default(),
        )
        .unwrap();
        Ok(Some(10))
    }
}

#[tokio::test]
async fn stale_height_evidence_cannot_mutate_a_reopened_ledger() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let dir = init_ledger(SpendingBudget::default());
    let mut pending = settled(100_000);
    pending.id = "reopened-ledger-refresh".into();
    pending.status = PaymentStatus::Pending;
    pending.solana_last_valid_block_height = Some(9);
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(pending))
        .unwrap()
        .unwrap();
    let issued_at =
        ledger::with_ledger(|ledger| ledger.payment("reopened-ledger-refresh").unwrap().timestamp)
            .unwrap();

    refresh_solana_authorizations(&ReopenLedgerDuringHeightRefresh { storage: dir })
        .await
        .unwrap();

    let latest = ledger::with_ledger(|ledger| {
        let current = ledger.payment("reopened-ledger-refresh").unwrap();
        assert_eq!(current.timestamp, issued_at);
        assert_eq!(current.authorization_expired_at, None);
        assert_eq!(current.authorization_expiry_observed_height, None);
        ledger.recent_payments(2).len()
    })
    .unwrap();
    assert_eq!(
        latest, 1,
        "stale refresh evidence must not append to replacement"
    );
    ledger::reset_global();
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

#[test]
fn a_challenge_is_read_from_the_v2_header() {
    let c = challenge(vec![solana_requirement()]);
    let parsed = parse_402_headers(&challenge_headers(&c)).unwrap();
    assert_eq!(parsed.accepts.len(), 1);
    assert_eq!(parsed.resource.url, "https://x402.example.test/thing");
}

#[test]
fn a_challenge_is_read_from_the_v1_header_spelling() {
    let c = challenge(vec![evm_requirement()]);
    let headers = headers_with("x-payment-required", &challenge_header(&c));
    assert_eq!(parse_402_headers(&headers).unwrap().accepts.len(), 1);
}

#[test]
fn a_mislabelled_version_is_still_read() {
    let mut c = challenge(vec![evm_requirement()]);
    c.x402_version = 1;
    assert_eq!(
        parse_402_headers(&challenge_headers(&c))
            .unwrap()
            .x402_version,
        1
    );
}

#[test]
fn a_missing_challenge_header_is_reported() {
    let err = parse_402_headers(&HeaderMap::new()).unwrap_err();
    assert!(matches!(err, X402Error::NoPaymentHeader));
    assert_eq!(
        err.to_string(),
        "402 response missing PAYMENT-REQUIRED header"
    );
}

#[test]
fn a_challenge_header_that_is_not_utf8_is_a_protocol_error() {
    let mut headers = HeaderMap::new();
    headers.insert(
        "payment-required",
        HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap(),
    );
    let err = parse_402_headers(&headers).unwrap_err().to_string();
    assert!(
        err.starts_with("x402 protocol: PAYMENT-REQUIRED header not valid UTF-8"),
        "{err}"
    );
}

#[test]
fn a_challenge_header_that_is_not_base64_is_a_protocol_error() {
    let err = parse_402_headers(&headers_with("payment-required", "***"))
        .unwrap_err()
        .to_string();
    assert!(
        err.starts_with("x402 protocol: PAYMENT-REQUIRED base64 decode"),
        "{err}"
    );
}

#[test]
fn a_challenge_header_that_is_not_json_is_a_protocol_error() {
    let headers = headers_with("payment-required", &B64.encode("not json"));
    let err = parse_402_headers(&headers).unwrap_err().to_string();
    assert!(
        err.starts_with("x402 protocol: PAYMENT-REQUIRED JSON parse"),
        "{err}"
    );
}

#[test]
fn a_settlement_response_is_decoded_with_its_failure_reason() {
    let ok = parse_settlement_response(&settlement(true, "4vJ9")).unwrap();
    assert!(ok.success);
    assert_eq!(ok.transaction, "4vJ9");
    let failed = parse_settlement_response(&format!(" {} ", settlement(false, ""))).unwrap();
    assert_eq!(failed.error_reason.as_deref(), Some("insufficient_funds"));
}

#[test]
fn an_unreadable_settlement_response_says_why() {
    assert!(
        parse_settlement_response("***")
            .unwrap_err()
            .starts_with("PAYMENT-RESPONSE base64 decode")
    );
    assert!(
        parse_settlement_response(&B64.encode("{"))
            .unwrap_err()
            .starts_with("PAYMENT-RESPONSE JSON parse")
    );
}

#[test]
fn a_payment_is_encoded_as_base64_json() {
    let payment = PaymentPayload {
        x402_version: X402_VERSION,
        resource: None,
        accepted: solana_requirement(),
        payload: PaymentProof::Solana(SolanaPaymentProof {
            transaction: "tx".into(),
        }),
        extensions: serde_json::Map::new(),
    };
    let encoded = encode_payment(&payment).unwrap();
    let back: PaymentPayload = serde_json::from_slice(&B64.decode(encoded).unwrap()).unwrap();
    assert_eq!(back.accepted.amount, "10000");
}

#[test]
fn every_error_has_its_pinned_message() {
    let cases = [
        (
            X402Error::NoPaymentOption,
            "no supported payment option (Solana exact, EVM exact or EVM upto) in 402 challenge",
        ),
        (
            X402Error::NoPaymentOptionOnNetwork {
                network: "eip155:8453".into(),
            },
            "no supported payment option on eip155:8453 in 402 challenge",
        ),
        (
            X402Error::AmountExceedsCap {
                requested: 9,
                cap: 5,
            },
            "x402 amount 9 exceeds per-request cap 5",
        ),
        (
            X402Error::BudgetExceeded {
                period: "daily",
                current: 4,
                cap: 5,
            },
            "x402 daily budget exceeded: 4/5 atomic units",
        ),
        (X402Error::Protocol("bad".into()), "x402 protocol: bad"),
        (X402Error::Wallet("locked".into()), "x402 wallet: locked"),
    ];
    for (error, message) in cases {
        assert_eq!(error.to_string(), message);
    }
}

// ---------------------------------------------------------------------------
// Challenge selection
// ---------------------------------------------------------------------------

#[test]
fn handle_402_prefers_solana_and_falls_back_to_evm() {
    let both = challenge(vec![evm_requirement(), solana_requirement()]);
    let (_, idx, chain) = handle_402(&challenge_headers(&both)).unwrap();
    assert_eq!((idx, chain), (1, PaymentChain::Solana));

    let evm_only = challenge(vec![evm_requirement()]);
    let (_, idx, chain) = handle_402(&challenge_headers(&evm_only)).unwrap();
    assert_eq!((idx, chain), (0, PaymentChain::Evm));
}

#[test]
fn handle_402_rejects_a_challenge_with_nothing_payable() {
    let mut upto = evm_requirement();
    upto.scheme = "upto".into();
    let err = handle_402(&challenge_headers(&challenge(vec![upto]))).unwrap_err();
    assert!(matches!(err, X402Error::NoPaymentOption));
    assert!(matches!(
        handle_402(&HeaderMap::new()).unwrap_err(),
        X402Error::NoPaymentHeader
    ));
}

#[tokio::test]
async fn the_chain_of_a_bare_requirement_follows_its_network_prefix() {
    let builder = StubBuilder::default();
    let c = challenge(vec![]);
    let header = pay_challenge_header(&builder, &c, &evm_requirement())
        .await
        .unwrap();
    pay_challenge_header(&builder, &c, &solana_requirement())
        .await
        .unwrap();
    assert!(B64.decode(header).is_ok());
    assert_eq!(
        *builder.chains.lock().unwrap(),
        vec![PaymentChain::Evm, PaymentChain::Solana]
    );

    let failing = StubBuilder {
        fail_with: Some("no wallet".into()),
        ..StubBuilder::default()
    };
    let err = pay_challenge_header(&failing, &c, &evm_requirement())
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "x402 wallet: no wallet");
}

// ---------------------------------------------------------------------------
// handle_402_and_pay: the budgeted path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn paying_needs_an_initialised_ledger() {
    let _guard = ledger::TEST_LOCK.lock().await;
    ledger::reset_global();
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let err = handle_402_and_pay(&StubBuilder::default(), &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 wallet: x402 payment ledger not initialized"
    );
}

#[tokio::test]
async fn a_payment_within_budget_yields_the_header_and_ledger_metadata() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let builder = StubBuilder::default();
    let headers = challenge_headers(&challenge(vec![evm_requirement(), solana_requirement()]));

    let result = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap();

    assert_eq!(result.amount_atomic, 10_000, "Solana is preferred");
    assert_eq!(result.recipient, crate::test_support::SOLANA_RECIPIENT);
    assert_eq!(result.network, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp");
    assert_eq!(result.url, "https://x402.example.test/a");
    let payload: PaymentPayload =
        serde_json::from_slice(&B64.decode(&result.header_value).unwrap()).unwrap();
    assert!(matches!(payload.payload, PaymentProof::Solana(_)));
    assert_eq!(*builder.chains.lock().unwrap(), vec![PaymentChain::Solana]);
    ledger::reset_global();
}

#[tokio::test]
async fn approval_runs_after_budget_reservation_and_denial_releases_it() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let builder = StubBuilder::default();
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let error = handle_402_and_pay_authorized(
        &builder,
        &headers,
        "https://x402.example.test/a",
        |url, requirement, chain, amount| async move {
            assert_eq!(url, "https://x402.example.test/a");
            assert_eq!(requirement.pay_to, crate::test_support::SOLANA_RECIPIENT);
            assert_eq!(chain, PaymentChain::Solana);
            assert_eq!(amount, 10_000);
            assert_eq!(
                ledger::with_ledger(ledger::PaymentLedger::reserved_atomic).unwrap(),
                10_000,
                "the module must hold the amount before asking the host to approve"
            );
            Err("fixture refused approval".to_string())
        },
    )
    .await
    .unwrap_err();

    assert_eq!(error.to_string(), "x402 wallet: fixture refused approval");
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::reserved_atomic).unwrap(),
        0,
        "a refusal must release the reservation"
    );
    assert!(builder.chains.lock().unwrap().is_empty());

    let _dir = init_ledger(SpendingBudget {
        per_request_max_atomic: 9_999,
        daily_max_atomic: 1_000_000,
        monthly_max_atomic: 1_000_000,
    });
    let approved = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback = approved.clone();
    let error = handle_402_and_pay_authorized(
        &builder,
        &headers,
        "https://x402.example.test/a",
        move |_, _, _, _| async move {
            callback.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .await
    .unwrap_err();
    assert!(matches!(error, X402Error::AmountExceedsCap { .. }));
    assert!(!approved.load(std::sync::atomic::Ordering::SeqCst));
    ledger::reset_global();
}

#[tokio::test]
async fn a_challenge_naming_another_origin_is_refused_before_anything_is_held() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let builder = StubBuilder::default();
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let asked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let callback = asked.clone();
    let error = handle_402_and_pay_authorized(
        &builder,
        &headers,
        "https://evil.example.test/a",
        move |_, _, _, _| async move {
            callback.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        },
    )
    .await
    .unwrap_err();

    assert!(matches!(error, X402Error::Protocol(_)), "{error}");
    assert!(!asked.load(std::sync::atomic::Ordering::SeqCst));
    assert!(builder.chains.lock().unwrap().is_empty());
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::reserved_atomic).unwrap(),
        0
    );
    ledger::reset_global();
}

#[tokio::test]
async fn an_unparseable_amount_is_a_protocol_error() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let mut requirement = solana_requirement();
    requirement.amount = "lots".into();
    let headers = challenge_headers(&challenge(vec![requirement]));
    let err = handle_402_and_pay(&StubBuilder::default(), &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert!(
        err.to_string()
            .starts_with("x402 protocol: invalid amount 'lots'")
    );
    ledger::reset_global();
}

#[tokio::test]
async fn each_budget_limit_refuses_with_its_own_error() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let builder = StubBuilder::default();

    // Per request: the challenge costs 10_000.
    let _dir = init_ledger(SpendingBudget {
        per_request_max_atomic: 9_999,
        daily_max_atomic: 1_000_000,
        monthly_max_atomic: 1_000_000,
    });
    let err = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 amount 10000 exceeds per-request cap 9999"
    );

    // Daily: 995_000 settled today plus 10_000 is over 1_000_000.
    let _dir = init_ledger(SpendingBudget {
        per_request_max_atomic: 50_000,
        daily_max_atomic: 1_000_000,
        monthly_max_atomic: 100_000_000,
    });
    ledger::with_ledger_mut(|l| l.record_payment(settled(995_000))).unwrap();
    let err = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 daily budget exceeded: 995000/1000000 atomic units"
    );

    // Monthly: the daily cap is out of the way, the monthly one is not.
    let _dir = init_ledger(SpendingBudget {
        per_request_max_atomic: 50_000,
        daily_max_atomic: 100_000_000,
        monthly_max_atomic: 1_000_000,
    });
    ledger::with_ledger_mut(|l| l.record_payment(settled(995_000))).unwrap();
    let err = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 monthly budget exceeded: 995000/1000000 atomic units"
    );
    assert!(
        builder.chains.lock().unwrap().is_empty(),
        "nothing is signed for a refused payment"
    );
    ledger::reset_global();
}

/// A builder that takes a moment to sign, as a real wallet does, so concurrent
/// payments overlap between the budget check and the signature.
struct SlowBuilder(StubBuilder);

#[async_trait]
impl PaymentBuilder for SlowBuilder {
    async fn build(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        self.0.build(challenge, requirement, chain).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn parallel_payments_cannot_overspend_the_daily_cap() {
    let _guard = ledger::TEST_LOCK.lock().await;
    // Each Solana challenge costs 10_000; the day allows exactly three.
    let _dir = init_ledger(SpendingBudget {
        per_request_max_atomic: 10_000,
        daily_max_atomic: 30_000,
        monthly_max_atomic: 1_000_000,
    });
    let builder = Arc::new(SlowBuilder(StubBuilder::default()));
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));

    let handles: Vec<_> = (0..12)
        .map(|_| {
            let builder = Arc::clone(&builder);
            let headers = headers.clone();
            tokio::spawn(async move { handle_402_and_pay(&*builder, &headers, REQUEST_URL).await })
        })
        .collect();
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }

    let paid = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(paid, 3, "exactly the payments the cap allows may be signed");
    assert_eq!(builder.0.chains.lock().unwrap().len(), 3, "and only those");
    for refused in results.iter().filter_map(|r| r.as_ref().err()) {
        assert!(
            matches!(
                refused,
                X402Error::BudgetExceeded {
                    period: "daily",
                    ..
                }
            ),
            "{refused}"
        );
    }
    ledger::reset_global();
}

#[tokio::test]
async fn a_payment_holds_its_amount_until_its_result_is_dropped() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget {
        per_request_max_atomic: 10_000,
        daily_max_atomic: 10_000,
        monthly_max_atomic: 1_000_000,
    });
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let builder = StubBuilder::default();

    let first = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap();
    assert_eq!(first.reservation.amount(), 10_000);
    let err = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 daily budget exceeded: 10000/10000 atomic units",
        "the first payment's hold counts even before it is recorded"
    );

    drop(first);
    assert!(
        handle_402_and_pay(&builder, &headers, REQUEST_URL)
            .await
            .is_ok()
    );
    ledger::reset_global();
}

#[tokio::test]
async fn a_failed_signature_releases_the_hold() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let failing = StubBuilder {
        fail_with: Some("locked".into()),
        ..StubBuilder::default()
    };

    handle_402_and_pay(&failing, &headers, REQUEST_URL)
        .await
        .unwrap_err();

    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::reserved_atomic).unwrap(),
        0
    );
    ledger::reset_global();
}

#[tokio::test]
async fn a_wallet_failure_is_passed_through() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let builder = StubBuilder {
        fail_with: Some("wallet secret: locked".into()),
        ..StubBuilder::default()
    };
    let headers = challenge_headers(&challenge(vec![solana_requirement()]));
    let err = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "x402 wallet: wallet secret: locked");
    ledger::reset_global();
}

// ---------------------------------------------------------------------------
// X402Client against a loopback server
// ---------------------------------------------------------------------------

fn paid_config(accepts: Vec<PaymentRequirements>) -> ServerConfig {
    ServerConfig {
        challenge: Some(challenge(accepts)),
        receipt: Some(settlement(true, "4vJ9YFuPzUgdLkWYJf3Kqf")),
        body: "the paid content".into(),
        ..ServerConfig::default()
    }
}

#[tokio::test]
async fn a_response_that_is_not_a_402_is_returned_untouched() {
    let server = TestServer::start(ServerConfig::default()).await;
    let client = client_with(Arc::new(StubBuilder::default()));
    let response = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "content");
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn a_402_is_paid_and_retried_with_the_same_request() {
    let server = TestServer::start(paid_config(vec![evm_requirement()])).await;
    let client = client_with(crypto_payments(FakePaymentSigner::default()));
    let request = reqwest::Client::new()
        .post(&server.url)
        .header("x-custom", "kept")
        .body("the body")
        .build()
        .unwrap();

    let response = client.try_paid_request(request, Some(5_000)).await.unwrap();

    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "the paid content");
    let seen: Vec<RecordedRequest> = server.seen();
    assert_eq!(seen.len(), 2);
    assert!(seen[0].payment_signature().is_none());
    let retry = &seen[1];
    assert_eq!(retry.method, reqwest::Method::POST);
    assert_eq!(retry.body, "the body");
    assert_eq!(retry.headers.get("x-custom").unwrap(), "kept");
    let payload: PaymentPayload =
        serde_json::from_slice(&B64.decode(retry.payment_signature().unwrap()).unwrap()).unwrap();
    match payload.payload {
        PaymentProof::Evm(evm) => assert_eq!(evm.authorization.value, "2500"),
        other => panic!("expected an EVM proof, got {other:?}"),
    }
}

#[tokio::test]
async fn a_solana_402_is_paid_with_a_signed_transaction() {
    let server = TestServer::start(paid_config(vec![solana_requirement()])).await;
    let client = client_with(crypto_payments(FakePaymentSigner::default()));
    let response = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let sig = server.seen()[1].payment_signature().unwrap();
    let payload: PaymentPayload = serde_json::from_slice(&B64.decode(sig).unwrap()).unwrap();
    assert!(matches!(payload.payload, PaymentProof::Solana(_)));
}

#[tokio::test]
async fn a_challenge_above_the_cap_is_refused_before_paying() {
    let server = TestServer::start(paid_config(vec![solana_requirement()])).await;
    let builder = Arc::new(StubBuilder::default());
    let client = client_with(builder.clone());
    let err = client
        .try_paid_request(get(&client, &server.url), Some(9_999))
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 amount 10000 exceeds per-request cap 9999"
    );
    assert!(builder.chains.lock().unwrap().is_empty());
    assert_eq!(server.seen().len(), 1, "no retry was sent");
}

/// A request whose body is a stream: it cannot be cloned, so it cannot be sent
/// a second time.
fn streaming_post(url: &str) -> reqwest::Request {
    reqwest::Client::new()
        .post(url)
        .body(reqwest::Body::wrap(http_body_util::Full::new(
            axum::body::Bytes::from("streamed"),
        )))
        .build()
        .unwrap()
}

#[tokio::test]
async fn a_streaming_body_is_refused_before_anything_is_paid() {
    let server = TestServer::start(paid_config(vec![solana_requirement()])).await;
    let builder = Arc::new(StubBuilder::default());
    let client = client_with(builder.clone());

    let err = client
        .try_paid_request(streaming_post(&server.url), None)
        .await
        .unwrap_err();

    assert!(matches!(err, X402Error::NonReplayableBody), "{err}");
    assert_eq!(
        err.to_string(),
        "x402 request body cannot be replayed for the paid retry; use a buffered body"
    );
    assert!(
        builder.chains.lock().unwrap().is_empty(),
        "nothing was signed"
    );
    assert_eq!(server.seen().len(), 1, "no paid retry was sent");
}

#[tokio::test]
async fn a_streaming_body_is_fine_when_no_payment_is_asked_for() {
    let server = TestServer::start(ServerConfig::default()).await;
    let client = client_with(Arc::new(StubBuilder::default()));
    let response = client
        .try_paid_request(streaming_post(&server.url), None)
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "content");
    assert_eq!(server.seen()[0].body, "streamed");
}

#[tokio::test]
async fn a_402_without_a_payable_option_or_header_is_an_error() {
    let mut upto = evm_requirement();
    upto.scheme = "upto".into();
    let server = TestServer::start(paid_config(vec![upto])).await;
    let client = client_with(Arc::new(StubBuilder::default()));
    let err = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap_err();
    assert!(matches!(err, X402Error::NoPaymentOption));

    let server = TestServer::start(ServerConfig {
        omit_challenge_header: true,
        ..paid_config(vec![evm_requirement()])
    })
    .await;
    let err = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap_err();
    assert!(matches!(err, X402Error::NoPaymentHeader));
}

#[tokio::test]
async fn an_unparseable_amount_stops_the_client() {
    let mut requirement = solana_requirement();
    requirement.amount = "lots".into();
    let server = TestServer::start(paid_config(vec![requirement])).await;
    let client = client_with(Arc::new(StubBuilder::default()));
    let err = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap_err();
    assert!(err.to_string().starts_with("x402 protocol: invalid amount"));
}

#[tokio::test]
async fn a_builder_failure_stops_the_client() {
    let server = TestServer::start(paid_config(vec![solana_requirement()])).await;
    let client = client_with(Arc::new(StubBuilder {
        fail_with: Some("no wallet".into()),
        ..StubBuilder::default()
    }));
    let err = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "x402 wallet: no wallet");
}

#[tokio::test]
async fn every_receipt_shape_still_returns_the_paid_response() {
    let receipts = [
        Some(settlement(false, "")),
        Some("***".to_string()),
        Some(String::new()),
        None,
    ];
    for receipt in receipts {
        let server = TestServer::start(ServerConfig {
            receipt,
            ..paid_config(vec![solana_requirement()])
        })
        .await;
        let client = client_with(Arc::new(StubBuilder::default()));
        let response = client
            .try_paid_request(get(&client, &server.url), None)
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
    }
}

#[tokio::test]
async fn a_dead_server_is_a_transport_error() {
    // Bind and drop a listener so the port is known to be closed.
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let client = client_with(Arc::new(StubBuilder::default()));
    let err = client
        .try_paid_request(get(&client, &format!("http://127.0.0.1:{port}")), None)
        .await
        .unwrap_err();
    assert!(matches!(err, X402Error::Transport(_)));
    assert!(err.to_string().starts_with("x402 transport: "));
}

#[tokio::test]
async fn a_server_that_hangs_up_on_the_retry_is_a_transport_error() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let mut on_this_origin = challenge(vec![solana_requirement()]);
    on_this_origin.resource.url = format!("{url}/thing");
    let header = challenge_header(&on_this_origin);
    tokio::spawn(async move {
        // First connection: answer the 402 and close.
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        let reply = format!(
            "HTTP/1.1 402 Payment Required\r\nPAYMENT-REQUIRED: {header}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        socket.write_all(reply.as_bytes()).await.unwrap();
        drop(socket);
        // Second connection: hang up without a word.
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket);
    });

    let client = client_with(Arc::new(StubBuilder::default()));
    let err = client
        .try_paid_request(get(&client, &url), None)
        .await
        .unwrap_err();
    assert!(matches!(err, X402Error::Transport(_)), "{err}");
}

#[test]
fn the_client_and_a_payment_result_are_debuggable() {
    let client = client_with(Arc::new(StubBuilder::default()));
    assert!(format!("{client:?}").starts_with("X402Client"));
}

// ---------------------------------------------------------------------------
// The network / asset allowlist
// ---------------------------------------------------------------------------

fn requirement_on(network: &str, asset: &str) -> PaymentRequirements {
    let mut requirement = evm_requirement();
    requirement.network = network.into();
    requirement.asset = asset.into();
    requirement
}

#[test]
fn handle_402_accepts_usdc_on_a_known_testnet() {
    let c = challenge(vec![requirement_on(
        crate::wire::BASE_SEPOLIA_CAIP2,
        crate::wire::USDC_BASE_SEPOLIA,
    )]);
    let (_, idx, chain) = handle_402(&challenge_headers(&c)).unwrap();
    assert_eq!((idx, chain), (0, PaymentChain::Evm));
}

#[test]
fn handle_402_skips_an_unsupported_option_for_a_supported_one() {
    let bogus = requirement_on("eip155:137", "0xdeadbeef");
    let c = challenge(vec![bogus, evm_requirement()]);
    let (_, idx, _) = handle_402(&challenge_headers(&c)).unwrap();
    assert_eq!(idx, 1);
}

#[test]
fn handle_402_refuses_an_unknown_network() {
    let c = challenge(vec![requirement_on("eip155:137", "0xdeadbeef")]);
    let err = handle_402(&challenge_headers(&c)).unwrap_err();
    assert!(
        matches!(&err, X402Error::UnsupportedNetwork { network } if network == "eip155:137"),
        "{err}"
    );
    assert_eq!(
        err.to_string(),
        "x402 network eip155:137 is not supported; payments are accepted only in USDC on known networks"
    );
}

#[test]
fn handle_402_refuses_an_asset_that_is_not_usdc() {
    let c = challenge(vec![requirement_on(
        crate::wire::SOLANA_MAINNET_CAIP2,
        "NotUsdcMint1111111111111111111111111111111",
    )]);
    let err = handle_402(&challenge_headers(&c)).unwrap_err();
    assert!(matches!(err, X402Error::UnsupportedAsset { .. }), "{err}");
    assert_eq!(
        err.to_string(),
        "x402 asset NotUsdcMint1111111111111111111111111111111 is not the USDC accepted on \
         solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
    );
}

#[tokio::test]
async fn an_unsupported_challenge_reserves_and_signs_nothing() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let builder = StubBuilder::default();
    let headers = challenge_headers(&challenge(vec![requirement_on("eip155:137", "0xbad")]));

    let err = handle_402_and_pay(&builder, &headers, REQUEST_URL)
        .await
        .unwrap_err();

    assert!(matches!(err, X402Error::UnsupportedNetwork { .. }));
    assert!(builder.chains.lock().unwrap().is_empty());
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::reserved_atomic).unwrap(),
        0
    );
    ledger::reset_global();
}

#[tokio::test]
async fn the_client_refuses_to_pay_an_unsupported_asset() {
    let server = TestServer::start(paid_config(vec![requirement_on(
        crate::wire::BASE_MAINNET_CAIP2,
        "0x0000000000000000000000000000000000000001",
    )]))
    .await;
    let builder = Arc::new(StubBuilder::default());
    let client = client_with(builder.clone());

    let err = client
        .try_paid_request(get(&client, &server.url), None)
        .await
        .unwrap_err();

    assert!(matches!(err, X402Error::UnsupportedAsset { .. }), "{err}");
    assert!(builder.chains.lock().unwrap().is_empty());
    assert_eq!(server.seen().len(), 1, "no paid retry was sent");
}

#[tokio::test]
async fn a_bare_requirement_is_checked_before_it_is_signed() {
    let builder = StubBuilder::default();
    let c = challenge(vec![]);
    let err = pay_challenge_header(&builder, &c, &requirement_on("cosmos:hub", "uatom"))
        .await
        .unwrap_err();
    assert!(matches!(err, X402Error::UnsupportedNetwork { .. }), "{err}");
    assert!(builder.chains.lock().unwrap().is_empty());
}
