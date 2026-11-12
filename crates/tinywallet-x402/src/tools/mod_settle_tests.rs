//! Tests for matching the settlement receipt to the payment it settles.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;

use super::test::{init_ledger, paid_config, records, run, text, tool};
use crate::ledger::{self, PaymentStatus};
use crate::test_support::{ServerConfig, TestServer, evm_requirement};
use crate::wire::SettlementResponse;

#[tokio::test]
async fn a_receipt_for_another_network_or_amount_does_not_settle_the_payment() {
    let _guard = ledger::TEST_LOCK.lock().await;
    for (network, amount) in [("eip155:84532", None), ("eip155:8453", Some("1"))] {
        let _dir = init_ledger();
        let receipt = B64.encode(
            serde_json::to_vec(&SettlementResponse {
                success: true,
                transaction: "0xother".into(),
                network: network.into(),
                payer: None,
                error_reason: None,
                amount: amount.map(Into::into),
                extensions: serde_json::Map::new(),
            })
            .unwrap(),
        );
        let server = TestServer::start(ServerConfig {
            receipt: Some(receipt),
            ..paid_config(evm_requirement())
        })
        .await;
        let result = run(&tool(), json!({"url": server.url})).await;
        assert!(!result.is_error, "{}", text(&result));
        let records = records();
        assert_eq!(
            records.last().unwrap().status,
            PaymentStatus::Pending,
            "a {network} receipt for {amount:?} settled a 2500 payment on eip155:8453"
        );
        assert_eq!(records.last().unwrap().tx_signature, None);
        ledger::reset_global();
    }
}

fn upto_receipt(amount: &str, transaction: &str) -> String {
    B64.encode(
        serde_json::to_vec(&SettlementResponse {
            success: true,
            transaction: transaction.into(),
            network: "eip155:8453".into(),
            payer: None,
            error_reason: None,
            amount: Some(amount.into()),
            extensions: serde_json::Map::new(),
        })
        .unwrap(),
    )
}

#[tokio::test]
async fn an_upto_payment_is_recorded_at_the_amount_actually_charged() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let twitr: crate::wire::PaymentRequired =
        serde_json::from_str(include_str!("../wire/fixtures/twitr-upto-challenge.json")).unwrap();
    for (charged, transaction, display) in [
        ("1200", "0xsettled", "0.001200 USDC"),
        ("0", "", "0.000000 USDC"),
    ] {
        let _dir = init_ledger();
        let server = TestServer::start(ServerConfig {
            receipt: Some(upto_receipt(charged, transaction)),
            ..paid_config(twitr.accepts[0].clone())
        })
        .await;
        let result = run(&tool(), json!({"url": server.url})).await;
        assert!(!result.is_error, "{}", text(&result));
        assert!(text(&result).contains(display), "{}", text(&result));

        let records = records();
        let pending = records.first().unwrap();
        assert_eq!(pending.status, PaymentStatus::Pending);
        assert_eq!(
            pending.amount_atomic, 3600,
            "the ceiling is held until settled"
        );
        assert_eq!(pending.scheme.as_deref(), Some("upto"));
        let settled = records.last().unwrap();
        assert_eq!(settled.status, PaymentStatus::Settled);
        assert_eq!(settled.amount_atomic, charged.parse::<u64>().unwrap());
        assert_eq!(settled.amount_display, display);
        assert_eq!(settled.scheme.as_deref(), Some("upto"));
        assert_eq!(
            settled.tx_signature.as_deref(),
            Some(transaction).filter(|t| !t.is_empty())
        );
        assert_eq!(
            ledger::with_ledger(ledger::PaymentLedger::outstanding_atomic).unwrap(),
            0,
            "nothing of the ceiling stays held"
        );
        ledger::reset_global();
    }
}

#[tokio::test]
async fn an_upto_receipt_above_the_ceiling_keeps_the_ceiling_pending() {
    let _guard = ledger::TEST_LOCK.lock().await;
    let twitr: crate::wire::PaymentRequired =
        serde_json::from_str(include_str!("../wire/fixtures/twitr-upto-challenge.json")).unwrap();
    let _dir = init_ledger();
    let server = TestServer::start(ServerConfig {
        receipt: Some(upto_receipt("3601", "0xover")),
        ..paid_config(twitr.accepts[0].clone())
    })
    .await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert!(!result.is_error, "{}", text(&result));
    let last = records().pop().unwrap();
    assert_eq!(last.status, PaymentStatus::Pending);
    assert_eq!(last.amount_atomic, 3600);
    ledger::reset_global();
}
