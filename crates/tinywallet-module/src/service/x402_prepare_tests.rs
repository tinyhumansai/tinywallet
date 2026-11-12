//! Tests for `X402PreparePayment` options: the caller's network pin, and
//! paying an `upto` challenge with its EIP-2612 gas-sponsoring permit.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::service::x402::tests::{PaymentApprovalHost, secret};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tinywallet_bus::wire::{X402CloseRequest, X402ConfigureRequest, X402PreparePaymentRequest};

/// A challenge offering Solana (the module's preference) and Ethereum USDC.
fn solana_and_evm_challenge() -> String {
    BASE64.encode(
        serde_json::to_vec(&serde_json::json!({
            "x402Version": 2,
            "resource": {"url": "https://wallet.fixture.test/resource"},
            "accepts": [{
                "scheme": "exact",
                "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
                "amount": "100",
                "asset": "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
                "payTo": "9xQeWvG816bUx9EPfEZ6bJvT4G7M1S8qNnXvZ4QxS5V",
                "maxTimeoutSeconds": 60,
                "extra": {"feePayer": "9xQeWvG816bUx9EPfEZ6bJvT4G7M1S8qNnXvZ4QxS5V"}
            }, {
                "scheme": "exact",
                "network": "eip155:1",
                "amount": "100",
                "asset": "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                "payTo": "0x3535353535353535353535353535353535353535",
                "maxTimeoutSeconds": 60
            }]
        }))
        .unwrap(),
    )
}

/// A wallet with a configured x402 service, served by an approving host.
struct Fixture {
    wallet: crate::service::Wallet,
    handle: tinywallet_bus::wire::X402ServiceHandle,
    authorizations: Arc<AtomicUsize>,
    rpc_requests: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
    payment_requests: Arc<std::sync::Mutex<Vec<tinywallet_bus::wire::AuthorizeX402PaymentRequest>>>,
    broker_task: tokio::task::JoinHandle<tinybus::Result<()>>,
    /// The host's and the module's bus connections, kept open for the test.
    _connections: (tinybus::Connection, tinybus::Connection),
    _workspace: tempfile::TempDir,
}

impl Fixture {
    async fn start() -> Self {
        let bus = tinybus::transport::memory::MemoryBus::new();
        let broker_task = tinybus::broker::Broker::new().spawn(bus.clone());
        let host = tinybus::Connection::connect(bus.connect().await.unwrap())
            .await
            .unwrap();
        let authorizations = Arc::new(AtomicUsize::new(0));
        let rpc_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        let payment_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
        host.serve_at(
            crate::service::HOST_OBJECT_PATH.try_into().unwrap(),
            PaymentApprovalHost {
                approved: Arc::new(AtomicBool::new(true)),
                authorizations: authorizations.clone(),
                pause: Arc::new(AtomicBool::new(false)),
                approval_started: Arc::new(tokio::sync::Notify::new()),
                release_approval: Arc::new(tokio::sync::Notify::new()),
                finalized_height: Arc::new(AtomicUsize::new(9)),
                rpc_requests: rpc_requests.clone(),
                payment_requests: payment_requests.clone(),
            },
        )
        .await
        .unwrap();
        host.request_name(crate::service::HOST_INTERFACE)
            .await
            .unwrap();
        let client = tinybus::Connection::connect(bus.connect().await.unwrap())
            .await
            .unwrap();
        let wallet = crate::service::Wallet {
            callbacks: Some(HostCallbacks::new(&client).unwrap()),
            ..crate::service::Wallet::default()
        };
        wallet
            .callbacks
            .as_ref()
            .unwrap()
            .set_test_ledger_storage(memory_ledger_storage());
        let workspace = tempfile::tempdir().unwrap();
        let handle = wallet
            .x402_configure(X402ConfigureRequest {
                config: X402ConfigResponse {
                    workspace_dir: workspace.path().display().to_string(),
                    session_id: "prepare-options".to_string(),
                    per_request_max_atomic: 10_000,
                    daily_max_atomic: 100_000,
                    monthly_max_atomic: 100_000,
                },
            })
            .await
            .unwrap();
        Self {
            wallet,
            handle,
            authorizations,
            rpc_requests,
            payment_requests,
            broker_task,
            _connections: (host, client),
            _workspace: workspace,
        }
    }

    fn prepare(&self, challenge: String, network: Option<&str>) -> X402PreparePaymentRequest {
        X402PreparePaymentRequest {
            service: self.handle.clone(),
            url: "https://wallet.fixture.test/resource".to_string(),
            payment_required: challenge,
            owner: None,
            secret: secret(tinywallet_bus::Chain::Evm),
            additional_secrets: vec![secret(tinywallet_bus::Chain::Solana)],
            network: network.map(Into::into),
        }
    }

    async fn close(self) {
        self.wallet
            .x402_close(X402CloseRequest {
                service: self.handle.clone(),
            })
            .await
            .unwrap();
        self.broker_task.abort();
    }
}

#[tokio::test]
async fn a_network_pin_chooses_the_paying_chain_and_refuses_an_absent_one() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let fixture = Fixture::start().await;
    let wallet = &fixture.wallet;
    let prepare = |network: Option<&str>| fixture.prepare(solana_and_evm_challenge(), network);

    let unpinned = wallet.x402_prepare_payment(prepare(None)).await.unwrap();
    assert!(
        unpinned.network.starts_with("solana:"),
        "Solana stays preferred"
    );
    for pin in ["eip155", "eip155:1"] {
        let pinned = wallet
            .x402_prepare_payment(prepare(Some(pin)))
            .await
            .unwrap();
        assert_eq!(pinned.network, "eip155:1", "{pin}");
    }

    let approvals_before = fixture.authorizations.load(Ordering::SeqCst);
    let error = wallet
        .x402_prepare_payment(prepare(Some("eip155:8453")))
        .await
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("no supported payment option on eip155:8453"),
        "{error:?}"
    );
    assert_eq!(
        fixture.authorizations.load(Ordering::SeqCst),
        approvals_before,
        "an unmet pin never reaches host approval"
    );
    fixture.close().await;
}

/// The twitr.sh volume-tool challenge, re-homed on the fixture origin.
fn upto_challenge() -> String {
    let mut challenge: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tinywallet-x402/src/wire/fixtures/twitr-upto-challenge.json"
    ))
    .unwrap();
    challenge["resource"]["url"] = "https://wallet.fixture.test/resource".into();
    BASE64.encode(serde_json::to_vec(&challenge).unwrap())
}

#[tokio::test]
async fn an_upto_challenge_is_authorized_and_held_at_its_ceiling() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let fixture = Fixture::start().await;

    let prepared = fixture
        .wallet
        .x402_prepare_payment(fixture.prepare(upto_challenge(), Some("eip155:8453")))
        .await
        .unwrap();

    assert_eq!(
        prepared.amount_atomic, 3600,
        "the host caps the signed ceiling"
    );
    assert_eq!(prepared.network, "eip155:8453");
    let approval = fixture.payment_requests.lock().unwrap()[0].clone();
    assert_eq!(approval.amount_atomic, 3600);
    let record = ledger::with_ledger(|ledger| ledger.payment(&prepared.payment_id).cloned())
        .unwrap()
        .unwrap();
    assert_eq!(record.scheme.as_deref(), Some("upto"));
    assert_eq!(record.amount_atomic, 3600);

    let payload: serde_json::Value =
        serde_json::from_slice(&BASE64.decode(&prepared.payment_header).unwrap()).unwrap();
    let authorization = &payload["payload"]["permit2Authorization"];
    assert_eq!(
        authorization["spender"],
        "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"
    );
    assert_eq!(
        authorization["witness"]["facilitator"],
        "0x4c934c63C786157Fefd990945b25eA60a0FB0205"
    );
    // The fixture host reports a zero Permit2 allowance, so the module reads
    // the token nonce over the host transport and signs an EIP-2612 permit.
    let info = &payload["extensions"]["eip2612GasSponsoring"]["info"];
    assert_eq!(info["nonce"], "0");
    assert_eq!(info["amount"], "3600");
    assert!(info["signature"].as_str().unwrap().starts_with("0x"));
    let calls: Vec<String> = fixture
        .rpc_requests
        .lock()
        .unwrap()
        .iter()
        .map(|(method, _)| method.clone())
        .collect();
    assert_eq!(calls.iter().filter(|m| *m == "eth_call").count(), 2);
    fixture.close().await;
}
