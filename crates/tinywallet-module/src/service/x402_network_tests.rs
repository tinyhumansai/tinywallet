//! Tests for the caller's network pin on `X402PreparePayment`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::service::x402::tests::{PaymentApprovalHost, secret};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};

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

#[tokio::test]
async fn a_network_pin_chooses_the_paying_chain_and_refuses_an_absent_one() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker_task = tinybus::broker::Broker::new().spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let authorizations = Arc::new(AtomicUsize::new(0));
    host.serve_at(
        crate::service::HOST_OBJECT_PATH.try_into().unwrap(),
        PaymentApprovalHost {
            approved: Arc::new(AtomicBool::new(true)),
            authorizations: authorizations.clone(),
            pause: Arc::new(AtomicBool::new(false)),
            approval_started: Arc::new(tokio::sync::Notify::new()),
            release_approval: Arc::new(tokio::sync::Notify::new()),
            finalized_height: Arc::new(AtomicUsize::new(9)),
            rpc_requests: Arc::new(std::sync::Mutex::new(Vec::new())),
            payment_requests: Arc::new(std::sync::Mutex::new(Vec::new())),
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
                session_id: "network-pin".to_string(),
                per_request_max_atomic: 1_000,
                daily_max_atomic: 100_000,
                monthly_max_atomic: 100_000,
            },
        })
        .await
        .unwrap();
    let prepare = |network: Option<&str>| X402PreparePaymentRequest {
        service: handle.clone(),
        url: "https://wallet.fixture.test/resource".to_string(),
        payment_required: solana_and_evm_challenge(),
        owner: None,
        secret: secret(tinywallet_bus::Chain::Evm),
        additional_secrets: vec![secret(tinywallet_bus::Chain::Solana)],
        network: network.map(Into::into),
    };

    let unpinned = wallet.x402_prepare_payment(prepare(None)).await.unwrap();
    assert!(unpinned.network.starts_with("solana:"), "Solana stays preferred");
    for pin in ["eip155", "eip155:1"] {
        let pinned = wallet.x402_prepare_payment(prepare(Some(pin))).await.unwrap();
        assert_eq!(pinned.network, "eip155:1", "{pin}");
    }

    let approvals_before = authorizations.load(std::sync::atomic::Ordering::SeqCst);
    let error = wallet
        .x402_prepare_payment(prepare(Some("eip155:8453")))
        .await
        .unwrap_err();
    assert!(
        format!("{error:?}").contains("no supported payment option on eip155:8453"),
        "{error:?}"
    );
    assert_eq!(
        authorizations.load(std::sync::atomic::Ordering::SeqCst),
        approvals_before,
        "an unmet pin never reaches host approval"
    );

    wallet
        .x402_close(X402CloseRequest { service: handle })
        .await
        .unwrap();
    broker_task.abort();
}
