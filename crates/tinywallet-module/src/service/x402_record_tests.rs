#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::service::x402::tests::pending_record;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

fn receipt(network: &str, amount: Option<&str>) -> String {
    let mut receipt = serde_json::json!({
        "success": true,
        "transaction": "0xsettled",
        "network": network
    });
    if let Some(amount) = amount {
        receipt["amount"] = amount.into();
    }
    BASE64.encode(serde_json::to_vec(&receipt).unwrap())
}

#[tokio::test]
async fn record_settles_only_on_a_receipt_for_the_payments_network_and_amount() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker_task = tinybus::broker::Broker::new().spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let mut runtime = X402Runtime::new(
        HostCallbacks::new(&connection).unwrap(),
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
    let handle = runtime.handle();
    // The pending payment is 1 atomic unit on eip155:1.
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(pending_record("paid", None)))
        .unwrap()
        .unwrap();
    let status = || ledger::with_ledger(|ledger| ledger.payment("paid").unwrap().status).unwrap();
    let record = |runtime: &X402Runtime, settlement: String| {
        runtime
            .record(X402RecordPaymentRequest {
                service: handle.clone(),
                payment_id: "paid".to_string(),
                response_status: 200,
                settlement_response: Some(settlement),
            })
            .unwrap();
    };

    record(&runtime, receipt("eip155:8453", None));
    assert_eq!(
        status(),
        PaymentStatus::Pending,
        "another network settled it"
    );
    record(&runtime, receipt("eip155:1", Some("2")));
    assert_eq!(
        status(),
        PaymentStatus::Pending,
        "another amount settled it"
    );
    assert_eq!(runtime.summary(&handle).unwrap().reserved_atomic, 1);

    record(&runtime, receipt("eip155:1", Some("1")));
    assert_eq!(status(), PaymentStatus::Settled);
    runtime.close(&handle).unwrap();
    broker_task.abort();
}

#[tokio::test]
async fn record_settles_an_upto_payment_at_the_amount_charged() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker_task = tinybus::broker::Broker::new().spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let mut runtime = X402Runtime::new(
        HostCallbacks::new(&connection).unwrap(),
        X402ConfigResponse {
            workspace_dir: workspace.path().display().to_string(),
            session_id: "coverage-test".to_string(),
            per_request_max_atomic: 10_000,
            daily_max_atomic: 10_000,
            monthly_max_atomic: 10_000,
        },
        memory_ledger_storage(),
    )
    .unwrap();
    let handle = runtime.handle();
    for (id, charged) in [("upto-a", 1200_u64), ("upto-b", 0)] {
        let mut pending = pending_record(id, None);
        pending.amount_atomic = 3600;
        pending.network = "eip155:8453".to_string();
        pending.scheme = Some("upto".to_string());
        ledger::with_ledger_mut(|ledger| ledger.try_record_payment(pending))
            .unwrap()
            .unwrap();

        // Above the signed ceiling: not a settlement of this payment.
        runtime
            .record(X402RecordPaymentRequest {
                service: handle.clone(),
                payment_id: id.to_string(),
                response_status: 200,
                settlement_response: Some(receipt("eip155:8453", Some("3601"))),
            })
            .unwrap();
        let latest = ledger::with_ledger(|ledger| ledger.payment(id).cloned().unwrap()).unwrap();
        assert_eq!(latest.status, PaymentStatus::Pending);

        runtime
            .record(X402RecordPaymentRequest {
                service: handle.clone(),
                payment_id: id.to_string(),
                response_status: 200,
                settlement_response: Some(receipt("eip155:8453", Some(&charged.to_string()))),
            })
            .unwrap();
        let latest = ledger::with_ledger(|ledger| ledger.payment(id).cloned().unwrap()).unwrap();
        assert_eq!(latest.status, PaymentStatus::Settled);
        assert_eq!(latest.amount_atomic, charged);
        assert_eq!(
            latest.amount_display,
            tinywallet_x402::ledger::format_usdc(charged)
        );
        assert_eq!(latest.scheme.as_deref(), Some("upto"));
    }
    let summary = runtime.summary(&handle).unwrap();
    assert_eq!(summary.reserved_atomic, 0, "the unused ceiling is released");
    assert_eq!(summary.daily_total_atomic, 1200);
    runtime.close(&handle).unwrap();
    broker_task.abort();
}

/// A runtime with one pending `upto` payment of 3600 under `id`.
async fn upto_runtime(
    id: &str,
) -> (
    X402Runtime,
    tokio::task::JoinHandle<tinybus::Result<()>>,
    tinybus::Connection,
    tempfile::TempDir,
) {
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker_task = tinybus::broker::Broker::new().spawn(bus.clone());
    let connection = tinybus::Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let workspace = tempfile::tempdir().unwrap();
    let runtime = X402Runtime::new(
        HostCallbacks::new(&connection).unwrap(),
        X402ConfigResponse {
            workspace_dir: workspace.path().display().to_string(),
            session_id: "coverage-test".to_string(),
            per_request_max_atomic: 10_000,
            daily_max_atomic: 10_000,
            monthly_max_atomic: 10_000,
        },
        memory_ledger_storage(),
    )
    .unwrap();
    let mut pending = pending_record(id, None);
    pending.amount_atomic = 3600;
    pending.network = "eip155:8453".to_string();
    pending.scheme = Some("upto".to_string());
    ledger::with_ledger_mut(|ledger| ledger.try_record_payment(pending))
        .unwrap()
        .unwrap();
    (runtime, broker_task, connection, workspace)
}

fn record_charge(runtime: &X402Runtime, id: &str, charged: Option<&str>) -> Result<(), String> {
    runtime.record(X402RecordPaymentRequest {
        service: runtime.handle(),
        payment_id: id.to_string(),
        response_status: 200,
        settlement_response: charged.map(|amount| receipt("eip155:8453", Some(amount))),
    })
}

fn charged(id: &str) -> (PaymentStatus, u64) {
    ledger::with_ledger(|ledger| {
        let latest = ledger.payment(id).unwrap();
        (latest.status, latest.amount_atomic)
    })
    .unwrap()
}

#[tokio::test]
async fn a_settled_payment_accepts_only_a_replay_of_the_same_charge() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let (mut runtime, broker_task, _connection, _workspace) = upto_runtime("once").await;

    record_charge(&runtime, "once", Some("1200")).unwrap();
    assert_eq!(charged("once"), (PaymentStatus::Settled, 1200));

    let error = record_charge(&runtime, "once", Some("1000")).unwrap_err();
    assert!(error.contains("already settled"), "{error}");
    assert_eq!(charged("once"), (PaymentStatus::Settled, 1200));

    record_charge(&runtime, "once", Some("1200")).unwrap();
    record_charge(&runtime, "once", None).unwrap();
    let rows = ledger::with_ledger(|ledger| {
        ledger
            .recent_payments(50)
            .into_iter()
            .filter(|row| row.id == "once")
            .count()
    })
    .unwrap();
    assert_eq!(rows, 2, "one pending row and one settled row, no more");

    let handle = runtime.handle();
    runtime.close(&handle).unwrap();
    broker_task.abort();
}

#[tokio::test]
async fn concurrent_receipts_settle_a_payment_once() {
    let _ledger_guard = LEDGER_TEST_LOCK.lock().await;
    let (mut runtime, broker_task, _connection, _workspace) = upto_runtime("raced").await;

    let outcomes = std::thread::scope(|scope| {
        let first = scope.spawn(|| record_charge(&runtime, "raced", Some("1200")));
        let second = scope.spawn(|| record_charge(&runtime, "raced", Some("900")));
        [first.join().unwrap(), second.join().unwrap()]
    });

    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    let (status, amount) = charged("raced");
    assert_eq!(status, PaymentStatus::Settled);
    let winner = if outcomes[0].is_ok() { 1200 } else { 900 };
    assert_eq!(amount, winner, "the ledger keeps the receipt that won");

    let handle = runtime.handle();
    runtime.close(&handle).unwrap();
    broker_task.abort();
}
