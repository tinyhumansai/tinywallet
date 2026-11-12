#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tinywallet_bus::wire::{
    X402CloseRequest, X402ConfigureRequest, X402ListPaymentsRequest, X402PaymentStatus,
    X402SummaryRequest, X402UpdateBudgetRequest,
};

pub(crate) fn pending_record(
    id: &str,
    authorization_valid_until: Option<chrono::DateTime<chrono::Utc>>,
) -> PaymentRecord {
    PaymentRecord {
        id: id.to_string(),
        url: "https://example.invalid".to_string(),
        asset: "usdc".to_string(),
        amount_atomic: 1,
        amount_display: "1 atomic".to_string(),
        recipient: "recipient".to_string(),
        network: "eip155:1".to_string(),
        tx_signature: None,
        status: PaymentStatus::Pending,
        timestamp: chrono::Utc::now(),
        authorization_valid_until,
        solana_last_valid_block_height: None,
        authorization_expired_at: None,
        authorization_expiry_observed_height: None,
        session_id: "coverage-test".to_string(),
        thread_id: None,
        scheme: None,
    }
}

const VECTOR: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub(crate) fn secret(chain: tinywallet_bus::Chain) -> SecretMaterial {
    let derivation_path = match chain {
        tinywallet_bus::Chain::Solana => "m/44'/501'/0'/0'",
        _ => "m/44'/60'/0'/0/0",
    };
    SecretMaterial {
        mnemonic: VECTOR.to_string(),
        derivation_path: derivation_path.to_string(),
        chain,
    }
}

#[tokio::test]
async fn payment_signer_derives_and_signs_for_both_supported_rails() {
    let signer = ModulePaymentSigner;
    assert!(signer.account(PaymentChain::Evm).await.is_err());

    let (evm, evm_signature, solana, solana_signature) =
        crate::service::web3::with_x402_execution_context(
            None,
            vec![
                secret(tinywallet_bus::Chain::Evm),
                secret(tinywallet_bus::Chain::Solana),
            ],
            async {
                let evm = signer.account(PaymentChain::Evm).await.unwrap();
                let evm_signature = signer
                    .sign(PaymentChain::Evm, &[0x42; 32], SignScheme::Secp256k1Digest)
                    .await
                    .unwrap();
                let solana = signer.account(PaymentChain::Solana).await.unwrap();
                let solana_signature = signer
                    .sign(PaymentChain::Solana, b"fixture", SignScheme::Ed25519)
                    .await
                    .unwrap();
                (evm, evm_signature, solana, solana_signature)
            },
        )
        .await;

    assert!(evm.address.starts_with("0x"));
    assert_eq!(evm.pubkey, None);
    assert_eq!(evm_signature.len(), 65);
    assert_eq!(solana.address.len(), 44);
    assert_eq!(solana.pubkey.unwrap().len(), 32);
    assert_eq!(solana_signature.len(), 64);
}

#[tokio::test]
async fn payment_signer_rejects_chain_and_scheme_mismatches() {
    let signer = ModulePaymentSigner;
    let (wrong_chain, unsupported_scheme) = crate::service::web3::with_x402_execution_context(
        None,
        vec![secret(tinywallet_bus::Chain::Solana)],
        async {
            let wrong_chain = signer.account(PaymentChain::Evm).await.unwrap_err();
            let unsupported_scheme = signer
                .sign(PaymentChain::Evm, &[0; 32], SignScheme::Ed25519)
                .await
                .unwrap_err();
            (wrong_chain, unsupported_scheme)
        },
    )
    .await;
    assert!(wrong_chain.contains("does not match"));
    assert!(unsupported_scheme.contains("unsupported signing scheme"));
}

#[test]
fn wiping_a_secret_clears_its_phrase() {
    let mut secret = secret(tinywallet_bus::Chain::Evm);
    wipe(&mut secret);
    assert_eq!(secret.mnemonic, "");
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "One lifecycle fixture verifies handle validation, authorization retention, and record behavior"
)]
async fn ledger_lifecycle_rejects_stale_handles_and_malformed_challenges() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker = tinybus::broker::Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let callbacks = HostCallbacks::new(&connection).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let mut runtime = X402Runtime::new(
        callbacks,
        X402ConfigResponse {
            workspace_dir: workspace.path().display().to_string(),
            session_id: "coverage-test".to_string(),
            per_request_max_atomic: 100,
            daily_max_atomic: 100,
            monthly_max_atomic: 100,
        },
        memory_ledger_storage(),
    )
    .unwrap();
    assert!(format!("{runtime:?}").contains("X402Runtime"));
    let handle = runtime.handle();
    let duplicate_chain_secrets = runtime
        .prepare(X402PreparePaymentRequest {
            service: handle.clone(),
            url: "https://example.invalid".to_string(),
            payment_required: "unused".to_string(),
            owner: None,
            secret: secret(tinywallet_bus::Chain::Evm),
            network: None,
            additional_secrets: vec![secret(tinywallet_bus::Chain::Evm)],
        })
        .await
        .unwrap_err();
    assert!(duplicate_chain_secrets.contains("duplicate secrets for one chain"));

    let stale = X402ServiceHandle {
        handle: "stale".to_string(),
    };
    let invalid_service = runtime
        .prepare(X402PreparePaymentRequest {
            service: stale,
            url: "https://example.invalid".to_string(),
            payment_required: "bad\nheader".to_string(),
            owner: None,
            additional_secrets: Vec::new(),
            secret: secret(tinywallet_bus::Chain::Evm),
            network: None,
        })
        .await
        .unwrap_err();
    assert!(invalid_service.contains("handle is unavailable"));

    let invalid_header = runtime
        .prepare(X402PreparePaymentRequest {
            service: handle.clone(),
            url: "https://example.invalid".to_string(),
            payment_required: "bad\nheader".to_string(),
            owner: None,
            additional_secrets: Vec::new(),
            secret: secret(tinywallet_bus::Chain::Evm),
            network: None,
        })
        .await
        .unwrap_err();
    assert!(invalid_header.contains("invalid payment challenge header"));

    let missing_payment = runtime
        .record(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: "missing".to_string(),
            response_status: 500,
            settlement_response: None,
        })
        .unwrap_err();
    assert!(missing_payment.contains("missing"));
    ledger::with_ledger_mut(|ledger| {
        ledger.try_record_payment(pending_record("failed-payment", None))
    })
    .unwrap()
    .unwrap();
    runtime
        .record(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: "failed-payment".to_string(),
            response_status: 500,
            settlement_response: None,
        })
        .unwrap();
    let unresolved = runtime.summary(&handle).unwrap();
    assert_eq!(unresolved.reserved_atomic, 1);
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::pending_count).unwrap(),
        1
    );

    let expired_record = pending_record(
        "expired-payment",
        Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
    );
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(expired_record))
        .unwrap()
        .unwrap();
    let after_expiry = runtime.summary(&handle).unwrap();
    assert_eq!(after_expiry.reserved_atomic, 2);
    assert_eq!(
        ledger::with_ledger(|ledger| ledger.payment("expired-payment").unwrap().status).unwrap(),
        PaymentStatus::Pending,
        "expiry alone cannot prove an authorization did not settle before the deadline"
    );
    runtime
        .record(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: "expired-payment".to_string(),
            response_status: 500,
            settlement_response: None,
        })
        .unwrap();
    let summary = runtime.summary(&handle).unwrap();
    assert_eq!(summary.reserved_atomic, 2);
    assert_eq!(
        ledger::with_ledger(ledger::PaymentLedger::pending_count).unwrap(),
        2
    );

    let receipt = BASE64.encode(
        serde_json::to_vec(&serde_json::json!({
            "success": true,
            "transaction": "0xsettled",
            "network": "eip155:1"
        }))
        .unwrap(),
    );
    runtime
        .record(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: "expired-payment".to_string(),
            response_status: 503,
            settlement_response: Some(receipt),
        })
        .expect("trusted late settlement evidence still finalizes an expired handle");
    let summary = runtime.summary(&handle).unwrap();
    assert_eq!(summary.session_total_atomic, 1);
    assert_eq!(
        summary.reserved_atomic, 1,
        "the unresolved authorization stays held"
    );

    let mut legacy_expired = pending_record(
        "legacy-expired-payment",
        Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
    );
    legacy_expired.status = PaymentStatus::Failed;
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(legacy_expired))
        .unwrap()
        .unwrap();
    assert_eq!(runtime.summary(&handle).unwrap().reserved_atomic, 2);
    let legacy_receipt = BASE64.encode(
        serde_json::to_vec(&serde_json::json!({
            "success": true,
            "transaction": "0xlegacy-settled",
            "network": "eip155:1"
        }))
        .unwrap(),
    );
    runtime
        .record(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: "legacy-expired-payment".to_string(),
            response_status: 503,
            settlement_response: Some(legacy_receipt.clone()),
        })
        .unwrap();
    runtime
        .record(X402RecordPaymentRequest {
            service: handle.clone(),
            payment_id: "legacy-expired-payment".to_string(),
            response_status: 503,
            settlement_response: Some(legacy_receipt),
        })
        .expect("a lost reply after durable settlement is safe to replay");
    let summary = runtime.summary(&handle).unwrap();
    assert_eq!(summary.session_total_atomic, 2);
    assert_eq!(summary.reserved_atomic, 1);
    runtime.close(&handle).unwrap();
    broker_task.abort();
}

#[tokio::test]
async fn history_and_live_budget_operations_keep_the_configured_ledger() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker = tinybus::broker::Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let callbacks = HostCallbacks::new(&connection).unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let mut runtime = X402Runtime::new(
        callbacks,
        X402ConfigResponse {
            workspace_dir: workspace.path().display().to_string(),
            session_id: "history-budget-test".to_string(),
            per_request_max_atomic: 100,
            daily_max_atomic: 200,
            monthly_max_atomic: 300,
        },
        memory_ledger_storage(),
    )
    .unwrap();
    let handle = runtime.handle();

    for id in ["older", "newer"] {
        let mut record = pending_record(id, None);
        record.session_id = "history-budget-test".to_string();
        ledger::with_ledger_mut(|ledger| ledger.try_record_payment(record))
            .unwrap()
            .unwrap();
    }
    let list_request = X402ListPaymentsRequest {
        service: handle.clone(),
        limit: 1,
    };
    let history = runtime.list_payments(&list_request).unwrap();
    assert_eq!(history.payments.len(), 1);
    assert_eq!(history.payments[0].id, "newer");
    assert_eq!(history.payments[0].session_id, "history-budget-test");
    assert_eq!(history.payments[0].status, X402PaymentStatus::Pending);

    let update_request = X402UpdateBudgetRequest {
        service: handle.clone(),
        per_request_max_atomic: Some(11),
        daily_max_atomic: None,
        monthly_max_atomic: Some(33),
    };
    let updated = runtime.update_budget(&update_request).unwrap();
    assert_eq!(updated.per_request_max_atomic, 11);
    assert_eq!(updated.daily_max_atomic, 200);
    assert_eq!(updated.monthly_max_atomic, 33);
    assert_eq!(updated.reserved_atomic, 2);

    let detailed = runtime
        .detailed_summary(&X402SummaryRequest {
            service: handle.clone(),
        })
        .unwrap();
    assert_eq!(detailed.session_total_atomic, 0);
    assert_eq!(detailed.session_count, 0);
    assert_eq!(detailed.reserved_atomic, 2);
    runtime.close(&handle).unwrap();
    broker_task.abort();
}

#[tokio::test]
async fn x402_bus_methods_serve_history_budget_and_detailed_summary() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker_task = tinybus::broker::Broker::new().spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let callbacks = HostCallbacks::new(&connection).unwrap();
    let wallet = super::super::Wallet {
        callbacks: Some(callbacks),
        ..Default::default()
    };
    let workspace = tempfile::tempdir().unwrap();
    wallet
        .callbacks
        .as_ref()
        .unwrap()
        .set_test_ledger_storage(memory_ledger_storage());
    let service = wallet
        .x402_configure(X402ConfigureRequest {
            config: X402ConfigResponse {
                workspace_dir: workspace.path().display().to_string(),
                session_id: "bus-history-budget-test".to_string(),
                per_request_max_atomic: 100,
                daily_max_atomic: 200,
                monthly_max_atomic: 300,
            },
        })
        .await
        .unwrap();

    let history = wallet
        .x402_list_payments(X402ListPaymentsRequest {
            service: service.clone(),
            limit: 10,
        })
        .await
        .unwrap();
    assert_eq!(history.payments.len(), 0);

    let updated = wallet
        .x402_update_budget(X402UpdateBudgetRequest {
            service: service.clone(),
            per_request_max_atomic: Some(50),
            daily_max_atomic: None,
            monthly_max_atomic: Some(250),
        })
        .await
        .unwrap();
    assert_eq!(updated.per_request_max_atomic, 50);
    assert_eq!(updated.daily_max_atomic, 200);
    assert_eq!(updated.monthly_max_atomic, 250);

    let detailed = wallet
        .x402_spending_summary_detailed(X402SummaryRequest {
            service: service.clone(),
        })
        .await
        .unwrap();
    assert_eq!(detailed.session_count, 0);
    assert_eq!(detailed.daily_count, 0);
    assert_eq!(detailed.monthly_count, 0);
    wallet
        .x402_close(X402CloseRequest { service })
        .await
        .unwrap();
    broker_task.abort();
}

#[derive(Clone)]
pub(crate) struct PaymentApprovalHost {
    pub(crate) approved: Arc<AtomicBool>,
    pub(crate) authorizations: Arc<AtomicUsize>,
    pub(crate) pause: Arc<AtomicBool>,
    pub(crate) approval_started: Arc<tokio::sync::Notify>,
    pub(crate) release_approval: Arc<tokio::sync::Notify>,
    pub(crate) finalized_height: Arc<AtomicUsize>,
    pub(crate) rpc_requests: Arc<std::sync::Mutex<Vec<(String, serde_json::Value)>>>,
    pub(crate) payment_requests:
        Arc<std::sync::Mutex<Vec<tinywallet_bus::wire::AuthorizeX402PaymentRequest>>>,
}

#[tinybus::interface(name = "ai.tinyhumans.tinywallet.Host")]
impl PaymentApprovalHost {
    async fn authorize_x402_payment(
        &self,
        request: tinywallet_bus::wire::AuthorizeX402PaymentRequest,
    ) -> tinybus::Result<tinywallet_bus::wire::HostResponse> {
        self.authorizations.fetch_add(1, Ordering::SeqCst);
        self.payment_requests.lock().unwrap().push(request);
        if self.pause.swap(false, Ordering::SeqCst) {
            self.approval_started.notify_one();
            self.release_approval.notified().await;
        }
        Ok(tinywallet_bus::wire::HostResponse::Authorization(
            tinywallet_bus::wire::AuthorizationResult {
                approved: self.approved.load(Ordering::SeqCst),
                reason: Some("fixture approval decision".to_string()),
            },
        ))
    }

    #[expect(
        clippy::unused_async,
        clippy::unused_async_trait_impl,
        reason = "TinyBus host methods are async even when this local fixture returns immediately"
    )]
    async fn chain_transport(
        &self,
        request: tinywallet_bus::wire::ChainTransportRequest,
    ) -> tinybus::Result<tinywallet_bus::wire::HostResponse> {
        use tinywallet_bus::wire::{ChainTransportRequest, ChainTransportResult, HostResponse};
        let body = match request {
            ChainTransportRequest::JsonRpc { method, params, .. } => {
                self.rpc_requests
                    .lock()
                    .unwrap()
                    .push((method.clone(), params));
                match method.as_str() {
                    "getLatestBlockhash" => serde_json::json!({
                        "context": {"slot": 1},
                        "value": {
                            "blockhash": "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
                            "lastValidBlockHeight": 9
                        }
                    }),
                    "getBlockHeight" => {
                        serde_json::json!(self.finalized_height.load(Ordering::SeqCst))
                    }
                    _ => serde_json::Value::Null,
                }
            }
            ChainTransportRequest::RestGet { .. } | ChainTransportRequest::RestPost { .. } => {
                serde_json::Value::Null
            }
        };
        Ok(HostResponse::ChainTransport(ChainTransportResult::Ok {
            body,
        }))
    }
}

pub(crate) fn valid_challenge_header() -> String {
    BASE64.encode(
        serde_json::to_vec(&serde_json::json!({
            "x402Version": 2,
            "resource": {"url": "https://wallet.fixture.test/resource"},
            "accepts": [{
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

fn assert_x402_authorization_matches_request(
    authorization: &tinywallet_bus::wire::AuthorizeX402PaymentRequest,
    owner: Option<&tinywallet_bus::wire::QuoteOwner>,
) {
    assert_eq!(
        authorization.owner.as_ref(),
        owner,
        "module approval callback retains the host-stamped conversation owner"
    );
    assert_eq!(authorization.url, "https://wallet.fixture.test/resource");
    assert_eq!(authorization.network, "eip155:1");
    assert_eq!(
        authorization.asset,
        "0xA0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    );
    assert_eq!(
        authorization.recipient,
        "0x3535353535353535353535353535353535353535"
    );
    assert_eq!(authorization.amount_atomic, 100);
}

pub(crate) fn valid_solana_challenge_header() -> String {
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
            }]
        }))
        .unwrap(),
    )
}

#[tokio::test]
async fn x402_pending_capacity_is_reserved_before_authorization_and_released_on_cancel() {
    use tinywallet_bus::wire::{X402CloseRequest, X402ConfigureRequest, X402PreparePaymentRequest};

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
    let payment_requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    host.serve_at(
        crate::service::HOST_OBJECT_PATH.try_into().unwrap(),
        PaymentApprovalHost {
            approved,
            authorizations: authorizations.clone(),
            pause: pause.clone(),
            approval_started: approval_started.clone(),
            release_approval: release_approval.clone(),
            finalized_height: Arc::new(AtomicUsize::new(9)),
            rpc_requests: Arc::new(std::sync::Mutex::new(Vec::new())),
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
    let wallet = Arc::new(crate::service::Wallet {
        callbacks: Some(HostCallbacks::new(&client).unwrap()),
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
                session_id: "pending-capacity-test".to_string(),
                per_request_max_atomic: 1_000,
                daily_max_atomic: 100_000,
                monthly_max_atomic: 100_000,
            },
        })
        .await
        .unwrap();

    let prepare = || X402PreparePaymentRequest {
        service: handle.clone(),
        url: "https://wallet.fixture.test/resource".to_string(),
        payment_required: valid_challenge_header(),
        owner: Some(tinywallet_bus::wire::QuoteOwner {
            thread_id: "thread-attributed".to_string(),
            client_id: "client-attributed".to_string(),
        }),
        additional_secrets: Vec::new(),
        secret: secret(tinywallet_bus::Chain::Evm),
        network: None,
    };
    for _ in 0..(MAX_PENDING - 1) {
        wallet.x402_prepare_payment(prepare()).await.unwrap();
    }
    assert_eq!(authorizations.load(Ordering::SeqCst), MAX_PENDING - 1);
    let first_authorization = payment_requests.lock().unwrap()[0].clone();
    let request_owner = prepare().owner;
    assert_x402_authorization_matches_request(&first_authorization, request_owner.as_ref());

    pause.store(true, Ordering::SeqCst);
    let pending_wallet = wallet.clone();
    let pending_request = prepare();
    let admitted =
        tokio::spawn(async move { pending_wallet.x402_prepare_payment(pending_request).await });
    approval_started.notified().await;

    assert_capacity_rejected_before_approval(&wallet, &prepare, &authorizations).await;

    admitted.abort();
    assert!(admitted.await.unwrap_err().is_cancelled());
    release_approval.notify_one();
    pause.store(false, Ordering::SeqCst);

    assert_admission_is_held_through_durable_commit(
        wallet.clone(),
        handle.clone(),
        authorizations.clone(),
    )
    .await;

    wallet
        .x402_close(X402CloseRequest { service: handle })
        .await
        .unwrap();
    broker_task.abort();
}

async fn assert_capacity_rejected_before_approval(
    wallet: &Arc<crate::service::Wallet>,
    prepare: &impl Fn() -> tinywallet_bus::wire::X402PreparePaymentRequest,
    authorizations: &AtomicUsize,
) {
    let runtime_guard = wallet.x402.read().await;
    let capacity_error = runtime_guard
        .as_ref()
        .unwrap()
        .admit_pending()
        .err()
        .unwrap();
    drop(runtime_guard);
    assert!(capacity_error.contains("capacity reached"));

    let over_capacity = wallet.x402_prepare_payment(prepare()).await;
    assert!(
        over_capacity.is_err(),
        "a full store rejects before it creates another spend authorization"
    );
    assert_eq!(
        authorizations.load(Ordering::SeqCst),
        MAX_PENDING,
        "the rejected request must not reach host approval or signing"
    );
}

async fn assert_admission_is_held_through_durable_commit(
    wallet: Arc<crate::service::Wallet>,
    handle: tinywallet_bus::wire::X402ServiceHandle,
    authorizations: Arc<AtomicUsize>,
) {
    use tinywallet_bus::wire::X402PreparePaymentRequest;

    let prepare = || X402PreparePaymentRequest {
        service: handle.clone(),
        url: "https://wallet.fixture.test/resource".to_string(),
        payment_required: valid_challenge_header(),
        owner: None,
        additional_secrets: Vec::new(),
        secret: secret(tinywallet_bus::Chain::Evm),
        network: None,
    };
    let commit_reached = Arc::new(tokio::sync::Notify::new());
    let release_commit = Arc::new(tokio::sync::Notify::new());
    {
        let mut runtime = wallet.x402.write().await;
        runtime.as_mut().unwrap().commit_handoff = Some((
            Arc::new(AtomicBool::new(true)),
            commit_reached.clone(),
            release_commit.clone(),
        ));
    }
    let pending_wallet = wallet.clone();
    let pending_request = prepare();
    let completing =
        tokio::spawn(async move { pending_wallet.x402_prepare_payment(pending_request).await });
    commit_reached.notified().await;

    let authorizations_before_handoff = authorizations.load(Ordering::SeqCst);
    let during_commit = wallet.x402_prepare_payment(prepare()).await;
    assert!(
        during_commit.is_err(),
        "the completing proof keeps its slot until durable commit"
    );
    assert_eq!(
        authorizations.load(Ordering::SeqCst),
        authorizations_before_handoff,
        "handoff saturation must reject before asking for another approval"
    );

    release_commit.notify_one();
    completing.await.unwrap().unwrap();
    assert_eq!(authorizations.load(Ordering::SeqCst), MAX_PENDING + 1);
}
