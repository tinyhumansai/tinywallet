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

/// A builder that answers with a fixed proof and remembers what it was asked.
#[derive(Default)]
struct StubBuilder {
    fail_with: Option<String>,
    chains: Mutex<Vec<PaymentChain>>,
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

fn init_ledger(budget: SpendingBudget) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    ledger::init_global(dir.path(), "test-session", budget);
    dir
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
        session_id: "test-session".into(),
    }
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
            "no supported payment option (Solana exact or EVM exact) in 402 challenge",
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
    let err = handle_402_and_pay(&StubBuilder::default(), &headers, "https://x")
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

    let result = handle_402_and_pay(&builder, &headers, "https://x402.example.test/a")
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
async fn an_unparseable_amount_is_a_protocol_error() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let _dir = init_ledger(SpendingBudget::default());
    let mut requirement = solana_requirement();
    requirement.amount = "lots".into();
    let headers = challenge_headers(&challenge(vec![requirement]));
    let err = handle_402_and_pay(&StubBuilder::default(), &headers, "u")
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
    let err = handle_402_and_pay(&builder, &headers, "u")
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
    let err = handle_402_and_pay(&builder, &headers, "u")
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
    let err = handle_402_and_pay(&builder, &headers, "u")
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
            tokio::spawn(async move { handle_402_and_pay(&*builder, &headers, "u").await })
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
            matches!(refused, X402Error::BudgetExceeded { period: "daily", .. }),
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

    let first = handle_402_and_pay(&builder, &headers, "u").await.unwrap();
    assert_eq!(first.reservation.amount(), 10_000);
    let err = handle_402_and_pay(&builder, &headers, "u")
        .await
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "x402 daily budget exceeded: 10000/10000 atomic units",
        "the first payment's hold counts even before it is recorded"
    );

    drop(first);
    assert!(handle_402_and_pay(&builder, &headers, "u").await.is_ok());
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

    handle_402_and_pay(&failing, &headers, "u")
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
    let err = handle_402_and_pay(&builder, &headers, "u")
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
        PaymentProof::Solana(_) => panic!("expected an EVM proof"),
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
    let header = challenge_header(&challenge(vec![solana_requirement()]));
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
