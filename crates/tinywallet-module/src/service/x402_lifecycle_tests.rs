#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::service::x402::tests::{
    PaymentApprovalHost, secret, valid_challenge_header, valid_solana_challenge_header,
};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One MemoryBus scenario exercises the x402 service lifecycle and cancellation cleanup"
)]
async fn x402_service_lifecycle_records_approval_denial_and_cancellation() {
    use tinywallet_bus::wire::{
        X402CloseRequest, X402ConfigureRequest, X402PreparePaymentRequest,
        X402RecordPaymentRequest, X402SummaryRequest,
    };

    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker = tinybus::broker::Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let host = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let approved = Arc::new(AtomicBool::new(true));
    let authorizations = Arc::new(AtomicUsize::new(0));
    let pause = Arc::new(AtomicBool::new(false));
    let approval_started = Arc::new(tokio::sync::Notify::new());
    let release_approval = Arc::new(tokio::sync::Notify::new());
    let finalized_height = Arc::new(AtomicUsize::new(9));
    let rpc_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    host.serve_at(
        crate::service::HOST_OBJECT_PATH.try_into().unwrap(),
        PaymentApprovalHost {
            approved: approved.clone(),
            authorizations: authorizations.clone(),
            pause: pause.clone(),
            approval_started: approval_started.clone(),
            release_approval: release_approval.clone(),
            finalized_height: finalized_height.clone(),
            rpc_requests: rpc_requests.clone(),
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
    let callbacks = HostCallbacks::new(&client).unwrap();
    let wallet = Arc::new(crate::service::Wallet {
        callbacks: Some(callbacks),
        ..crate::service::Wallet::default()
    });
    let workspace = tempfile::tempdir().unwrap();
    wallet
        .callbacks
        .as_ref()
        .unwrap()
        .set_test_ledger_storage(memory_ledger_storage());
    let handle = wallet
        .x402_configure(X402ConfigureRequest {
            config: X402ConfigResponse {
                workspace_dir: workspace.path().display().to_string(),
                session_id: "wallet-service-lifecycle".to_string(),
                per_request_max_atomic: 1_000,
                daily_max_atomic: 2_000,
                monthly_max_atomic: 3_000,
            },
        })
        .await
        .unwrap();
    let replaced = wallet
        .x402_configure(X402ConfigureRequest {
            config: X402ConfigResponse {
                workspace_dir: workspace.path().display().to_string(),
                session_id: "wallet-service-lifecycle-replaced".to_string(),
                per_request_max_atomic: 1_000,
                daily_max_atomic: 2_000,
                monthly_max_atomic: 3_000,
            },
        })
        .await
        .unwrap();
    assert_ne!(handle.handle, replaced.handle);
    assert!(
        wallet
            .x402_spending_summary(X402SummaryRequest { service: handle })
            .await
            .is_err()
    );
    let handle = replaced;

    let prepared = wallet
        .x402_prepare_payment(X402PreparePaymentRequest {
            service: handle.clone(),
            url: "https://wallet.fixture.test/resource".to_string(),
            payment_required: valid_challenge_header(),
            owner: Some(tinywallet_bus::wire::QuoteOwner {
                thread_id: "fixture-thread".to_string(),
                client_id: "fixture-client".to_string(),
            }),
            additional_secrets: Vec::new(),
            secret: secret(tinywallet_bus::Chain::Evm),
            network: None,
        })
        .await
        .unwrap();
    assert_eq!(prepared.amount_atomic, 100);
    assert!(prepared.payment_header.starts_with("ey"));
    assert!(
        uuid::Uuid::parse_str(prepared.payment_id.strip_prefix("x402_").unwrap()).is_ok(),
        "payment handles must stay collision-safe across process restarts"
    );
    wallet
        .x402_close(X402CloseRequest {
            service: handle.clone(),
        })
        .await
        .unwrap();
    let handle = wallet
        .x402_configure(X402ConfigureRequest {
            config: X402ConfigResponse {
                workspace_dir: workspace.path().display().to_string(),
                session_id: "wallet-service-lifecycle-reopened".to_string(),
                per_request_max_atomic: 1_000,
                daily_max_atomic: 2_000,
                monthly_max_atomic: 3_000,
            },
        })
        .await
        .unwrap();
    let held = wallet
        .x402_spending_summary(X402SummaryRequest {
            service: handle.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        held.reserved_atomic, 100,
        "closing and reopening must preserve a signed authorization's budget hold"
    );

    wallet
        .x402_record_payment(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: prepared.payment_id.clone(),
            response_status: 503,
            settlement_response: None,
        })
        .await
        .unwrap();
    let unresolved = wallet
        .x402_spending_summary(X402SummaryRequest {
            service: handle.clone(),
        })
        .await
        .unwrap();
    assert_eq!(
        unresolved.reserved_atomic, 100,
        "an HTTP failure without settlement evidence cannot release a still-valid authorization"
    );

    wallet
        .x402_record_payment(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: prepared.payment_id.clone(),
            response_status: 200,
            settlement_response: Some(
                BASE64.encode(
                    serde_json::to_vec(&serde_json::json!({
                        "success": true,
                        "transaction": "0xsettled",
                        "network": "eip155:1"
                    }))
                    .unwrap(),
                ),
            ),
        })
        .await
        .unwrap();
    let settled = wallet
        .x402_spending_summary(X402SummaryRequest {
            service: handle.clone(),
        })
        .await
        .unwrap();
    assert_eq!(settled.daily_total_atomic, 100);
    assert_eq!(settled.reserved_atomic, 0);

    let prepare_solana = || X402PreparePaymentRequest {
        service: handle.clone(),
        url: "https://wallet.fixture.test/resource".to_string(),
        payment_required: valid_solana_challenge_header(),
        owner: None,
        additional_secrets: Vec::new(),
        secret: secret(tinywallet_bus::Chain::Solana),
        network: None,
    };
    let first_solana = wallet.x402_prepare_payment(prepare_solana()).await.unwrap();
    let first_record =
        ledger::with_ledger(|ledger| ledger.payment(&first_solana.payment_id).cloned())
            .unwrap()
            .unwrap();
    assert_eq!(first_record.solana_last_valid_block_height, Some(9));
    assert_eq!(first_record.authorization_expired_at, None);

    let second_solana = wallet.x402_prepare_payment(prepare_solana()).await.unwrap();
    assert_eq!(
        ledger::with_ledger(|ledger| ledger
            .payment(&first_solana.payment_id)
            .unwrap()
            .authorization_expired_at)
        .unwrap(),
        None,
        "a finalized height equal to lastValidBlockHeight is still usable"
    );
    finalized_height.store(10, Ordering::SeqCst);
    let _third_solana = wallet.x402_prepare_payment(prepare_solana()).await.unwrap();
    for payment_id in [&first_solana.payment_id, &second_solana.payment_id] {
        let latest = ledger::with_ledger(|ledger| ledger.payment(payment_id).cloned())
            .unwrap()
            .unwrap();
        assert_eq!(latest.authorization_expiry_observed_height, Some(10));
        assert_eq!(latest.status, PaymentStatus::Pending);
    }
    assert_eq!(
        wallet
            .x402_spending_summary(X402SummaryRequest {
                service: handle.clone(),
            })
            .await
            .unwrap()
            .reserved_atomic,
        300,
        "expired Solana proofs release future capacity but keep their durable value held"
    );
    {
        let rpc_calls = rpc_requests.lock().unwrap();
        assert!(rpc_calls.iter().any(|(method, params)| {
            method == "getLatestBlockhash"
                && params == &serde_json::json!([{"commitment": "finalized"}])
        }));
        assert!(rpc_calls.iter().any(|(method, params)| {
            method == "getBlockHeight"
                && params == &serde_json::json!([{"commitment": "finalized"}])
        }));
    }

    approved.store(false, Ordering::SeqCst);
    let denied = wallet
        .x402_prepare_payment(X402PreparePaymentRequest {
            service: handle.clone(),
            url: "https://wallet.fixture.test/resource".to_string(),
            payment_required: valid_challenge_header(),
            owner: None,
            additional_secrets: Vec::new(),
            secret: secret(tinywallet_bus::Chain::Evm),
            network: None,
        })
        .await
        .unwrap_err();
    assert!(denied.to_string().contains("X402OperationFailed"));
    assert_eq!(
        wallet
            .x402_spending_summary(X402SummaryRequest {
                service: handle.clone(),
            })
            .await
            .unwrap()
            .reserved_atomic,
        300,
        "denial releases only its fresh reservation, not prior unresolved proofs"
    );

    approved.store(true, Ordering::SeqCst);
    pause.store(true, Ordering::SeqCst);
    let pending_wallet = wallet.clone();
    let pending_handle = handle.clone();
    let task = tokio::spawn(async move {
        pending_wallet
            .x402_prepare_payment(X402PreparePaymentRequest {
                service: pending_handle,
                url: "https://wallet.fixture.test/resource".to_string(),
                payment_required: valid_challenge_header(),
                owner: None,
                additional_secrets: Vec::new(),
                secret: secret(tinywallet_bus::Chain::Evm),
                network: None,
            })
            .await
    });
    approval_started.notified().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    release_approval.notify_one();
    pause.store(false, Ordering::SeqCst);
    assert_eq!(
        wallet
            .x402_spending_summary(X402SummaryRequest {
                service: handle.clone(),
            })
            .await
            .unwrap()
            .reserved_atomic,
        300,
        "cancellation releases only its in-flight reservation"
    );

    wallet
        .x402_close(X402CloseRequest {
            service: handle.clone(),
        })
        .await
        .unwrap();
    assert!(
        wallet
            .x402_spending_summary(X402SummaryRequest { service: handle })
            .await
            .is_err()
    );

    let blocked_workspace = tempfile::tempdir().unwrap();
    wallet
        .callbacks
        .as_ref()
        .unwrap()
        .set_test_ledger_storage(failing_append_storage());
    let blocked_handle = wallet
        .x402_configure(X402ConfigureRequest {
            config: X402ConfigResponse {
                workspace_dir: blocked_workspace.path().display().to_string(),
                session_id: "unwritable-ledger".to_string(),
                per_request_max_atomic: 1_000,
                daily_max_atomic: 2_000,
                monthly_max_atomic: 3_000,
            },
        })
        .await
        .unwrap();
    let authorizations_before_unpersisted = authorizations.load(Ordering::SeqCst);
    let unpersisted = wallet
        .x402_prepare_payment(X402PreparePaymentRequest {
            service: blocked_handle.clone(),
            url: "https://wallet.fixture.test/resource".to_string(),
            payment_required: valid_challenge_header(),
            owner: None,
            additional_secrets: Vec::new(),
            secret: secret(tinywallet_bus::Chain::Evm),
            network: None,
        })
        .await;
    assert!(
        unpersisted.is_err(),
        "the signed header must not leave the module if durable budget accounting fails"
    );
    assert_eq!(
        authorizations.load(Ordering::SeqCst),
        authorizations_before_unpersisted + 1,
        "the fixture reaches the real approval and signing path before the durable-write refusal"
    );
    wallet
        .x402_close(X402CloseRequest {
            service: blocked_handle,
        })
        .await
        .unwrap();
    broker_task.abort();
}

/// In-memory storage whose payments stream refuses every append: the ledger
/// opens, holds budget, and then cannot durably record the authorization.
fn failing_append_storage() -> tinywallet_x402::ledger::LedgerStorage {
    use tinystoragedrivers_testkit::{Failing, FaultPlan};
    use tinystoragedrivers_types::{ErrorKind, Scope};

    let scoped = tinystoragedrivers_testkit::memory_storage(&Scope::new("x402-fail").unwrap());
    let faults = FaultPlan::new();
    faults.fail_operation_nth("streams.append", 1, ErrorKind::Backend);
    tinywallet_x402::ledger::LedgerStorage::new(
        Arc::clone(scoped.documents()),
        Arc::new(Failing::with_plan(Arc::clone(scoped.streams()), faults)),
    )
}

#[tokio::test]
async fn x402_configure_fails_closed_when_the_host_serves_no_storage() {
    use tinywallet_bus::wire::X402ConfigureRequest;

    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker = tinybus::broker::Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let client = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let wallet = Arc::new(crate::service::Wallet {
        callbacks: Some(HostCallbacks::new(&client).unwrap()),
        ..crate::service::Wallet::default()
    });

    let result = wallet
        .x402_configure(X402ConfigureRequest {
            config: X402ConfigResponse {
                workspace_dir: "/unused".to_string(),
                session_id: "no-storage".to_string(),
                per_request_max_atomic: 1,
                daily_max_atomic: 1,
                monthly_max_atomic: 1,
            },
        })
        .await;

    assert!(
        result.is_err(),
        "a ledger that cannot persist must not open"
    );
    broker_task.abort();
}
