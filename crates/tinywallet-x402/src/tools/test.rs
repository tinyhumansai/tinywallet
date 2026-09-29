//! Tests for the `x402_request` tool: the whole request, pay and record loop
//! against a loopback server, with a fake wallet and chain transport.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, PoisonError};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use tinytools::{PermissionLevel, Tool, ToolExposure, ToolResult};

use super::*;
use crate::ledger::{self, PaymentRecord, PaymentStatus, SpendingBudget};
use crate::test_support::{
    FakePaymentSigner, FakeProxyPolicy, FakeTransport, ServerConfig, TestServer, challenge,
    challenge_header, evm_requirement, solana_requirement,
};
use crate::wire::{PaymentRequirements, SettlementResponse};

fn tool_with(proxy: Arc<FakeProxyPolicy>) -> X402RequestTool {
    X402RequestTool::new(
        Arc::new(FakePaymentSigner::default()),
        Arc::new(FakeTransport::default()),
        proxy,
    )
}

fn tool() -> X402RequestTool {
    tool_with(Arc::new(FakeProxyPolicy::default()))
}

fn receipt(success: bool, transaction: &str) -> String {
    B64.encode(
        serde_json::to_vec(&SettlementResponse {
            success,
            transaction: transaction.into(),
            network: "eip155:8453".into(),
            payer: None,
            error_reason: None,
            amount: None,
            extensions: serde_json::Map::new(),
        })
        .unwrap(),
    )
}

fn paid_config(requirement: PaymentRequirements) -> ServerConfig {
    ServerConfig {
        challenge: Some(challenge(vec![requirement])),
        receipt: Some(receipt(true, "0xabc123")),
        body: "the paid content".into(),
        ..ServerConfig::default()
    }
}

fn init_ledger() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    ledger::init_global(dir.path(), "tool-test", SpendingBudget::default());
    dir
}

fn records() -> Vec<PaymentRecord> {
    // Oldest first.
    let mut records = ledger::with_ledger(|l| l.recent_payments(50)).unwrap();
    records.reverse();
    records
}

fn text(result: &ToolResult) -> String {
    result.text()
}

async fn run(tool: &X402RequestTool, args: serde_json::Value) -> ToolResult {
    tool.execute(args).await.unwrap()
}

// ---------------------------------------------------------------------------
// Declaration
// ---------------------------------------------------------------------------

#[test]
fn the_tool_declares_itself_as_a_deferred_write_tool() {
    let tool = tool();
    assert_eq!(tool.name(), "x402_request");
    assert!(tool.description().contains("x402-payable API"));
    assert_eq!(tool.exposure(), ToolExposure::Deferred);
    assert_eq!(tool.permission_level(), PermissionLevel::Write);
    let schema = tool.parameters_schema();
    assert_eq!(schema["required"], json!(["url"]));
    assert_eq!(
        schema["properties"]["method"]["enum"],
        json!(["GET", "POST", "PUT", "DELETE", "PATCH"])
    );
    assert!(format!("{tool:?}").starts_with("X402RequestTool"));
}

// ---------------------------------------------------------------------------
// Refusals before any network call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_missing_url_is_reported() {
    let result = run(&tool(), json!({})).await;
    assert!(result.is_error);
    assert_eq!(text(&result), "Missing required 'url' parameter");
}

#[tokio::test]
async fn an_unsupported_method_is_reported() {
    let result = run(
        &tool(),
        json!({"url": "http://127.0.0.1:1", "method": "GE T"}),
    )
    .await;
    assert!(result.is_error);
    assert_eq!(text(&result), "Unsupported HTTP method: GE T");
}

#[tokio::test]
async fn an_unreachable_endpoint_is_reported() {
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let result = run(&tool(), json!({"url": format!("http://127.0.0.1:{port}")})).await;
    assert!(result.is_error);
    assert!(
        text(&result).starts_with("Initial request failed: "),
        "{}",
        text(&result)
    );
}

// ---------------------------------------------------------------------------
// Responses that are not paid
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_free_endpoint_is_returned_directly() {
    let server = TestServer::start(ServerConfig::default()).await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert!(!result.is_error);
    assert_eq!(
        text(&result),
        format!("HTTP 200 from {}\n\ncontent", server.url)
    );
    assert_eq!(server.seen().len(), 1);
}

#[tokio::test]
async fn a_402_without_a_challenge_header_is_not_an_x402_endpoint() {
    let server = TestServer::start(ServerConfig {
        omit_challenge_header: true,
        ..paid_config(evm_requirement())
    })
    .await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert!(result.is_error);
    assert_eq!(
        text(&result),
        "Server returned 402 but without a PAYMENT-REQUIRED header — not an x402 endpoint"
    );
}

#[tokio::test]
async fn the_v1_challenge_header_is_accepted() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let _dir = init_ledger();
    let server = TestServer::start(ServerConfig {
        challenge_header: "X-PAYMENT-REQUIRED",
        ..paid_config(evm_requirement())
    })
    .await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert!(!result.is_error, "{}", text(&result));
    ledger::reset_global();
}

#[tokio::test]
async fn an_oversized_body_is_cut_on_a_character_boundary() {
    // 3-byte characters, so 50_000 falls inside one.
    let server = TestServer::start(ServerConfig {
        body: "€".repeat(30_000),
        ..ServerConfig::default()
    })
    .await;
    let result = run(&tool(), json!({"url": server.url})).await;
    let out = text(&result);
    assert!(out.ends_with("…(truncated)"), "{}", &out[out.len() - 40..]);
    assert!(out.len() < 50_100);
}

// ---------------------------------------------------------------------------
// The paid flow
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_evm_402_is_paid_recorded_and_reported() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let _dir = init_ledger();
    let proxy = Arc::new(FakeProxyPolicy::default());
    let server = TestServer::start(paid_config(evm_requirement())).await;

    let result = run(
        &tool_with(proxy.clone()),
        json!({
            "url": server.url,
            "method": "POST",
            "headers": {"x-custom": "kept", "ignored": 7},
            "body": "the body"
        }),
    )
    .await;

    assert!(!result.is_error, "{}", text(&result));
    assert_eq!(
        text(&result),
        format!(
            "HTTP 200 from {}\nx402 payment: 0.002500 USDC on Base\nTransaction: 0xabc123\n\n\
             the paid content",
            server.url
        )
    );
    assert_eq!(*proxy.services.lock().unwrap(), vec!["tool.x402_request"]);

    let seen = server.seen();
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1].method, reqwest::Method::POST);
    assert_eq!(seen[1].body, "the body");
    assert_eq!(seen[1].headers.get("x-custom").unwrap(), "kept");
    assert!(seen[1].headers.get("ignored").is_none());
    assert!(seen[1].payment_signature().is_some());

    let records = records();
    assert_eq!(
        records.iter().map(|r| r.status).collect::<Vec<_>>(),
        vec![PaymentStatus::Pending, PaymentStatus::Settled]
    );
    assert_eq!(records[0].id, records[1].id);
    assert_eq!(records[1].amount_atomic, 2_500);
    assert_eq!(records[1].amount_display, "0.002500 USDC");
    assert_eq!(records[1].tx_signature.as_deref(), Some("0xabc123"));
    assert_eq!(records[1].url, server.url);
    ledger::reset_global();
}

#[tokio::test]
async fn a_solana_402_is_labelled_solana() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let _dir = init_ledger();
    let server = TestServer::start(paid_config(solana_requirement())).await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert!(text(&result).contains("x402 payment: 0.010000 USDC on Solana"));
    ledger::reset_global();
}

#[tokio::test]
async fn a_rejected_payment_is_recorded_as_failed() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let _dir = init_ledger();
    let server = TestServer::start(ServerConfig {
        paid_status: 500,
        receipt: Some(receipt(false, "")),
        body: "nope".into(),
        ..paid_config(evm_requirement())
    })
    .await;
    let result = run(&tool(), json!({"url": server.url})).await;
    // A failed settlement is still a response the agent should read.
    assert!(!result.is_error);
    assert!(text(&result).contains("HTTP 500"));
    assert!(!text(&result).contains("Transaction:"));
    let records = records();
    assert_eq!(records.last().unwrap().status, PaymentStatus::Failed);
    assert_eq!(records.last().unwrap().tx_signature, None);
    ledger::reset_global();
}

#[tokio::test]
async fn a_missing_or_unreadable_receipt_leaves_the_transaction_blank() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    for receipt in [None, Some("***".to_string()), Some(B64.encode("{}"))] {
        let _dir = init_ledger();
        let server = TestServer::start(ServerConfig {
            receipt,
            ..paid_config(evm_requirement())
        })
        .await;
        let result = run(&tool(), json!({"url": server.url})).await;
        assert!(!text(&result).contains("Transaction:"));
        let last = records().pop().unwrap();
        assert_eq!(last.status, PaymentStatus::Settled);
        assert_eq!(last.tx_signature, None);
    }
    ledger::reset_global();
}

#[tokio::test]
async fn a_payment_the_budget_refuses_is_reported_and_not_sent() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let dir = tempfile::tempdir().unwrap();
    ledger::init_global(
        dir.path(),
        "tool-test",
        SpendingBudget {
            per_request_max_atomic: 100,
            ..SpendingBudget::default()
        },
    );
    let server = TestServer::start(paid_config(evm_requirement())).await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert!(result.is_error);
    assert_eq!(
        text(&result),
        "x402 payment failed: x402 amount 2500 exceeds per-request cap 100"
    );
    assert_eq!(server.seen().len(), 1);
    assert!(records().is_empty());
    ledger::reset_global();
}

#[tokio::test]
async fn paying_without_a_ledger_is_reported() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    ledger::reset_global();
    let server = TestServer::start(paid_config(evm_requirement())).await;
    let result = run(&tool(), json!({"url": server.url})).await;
    assert_eq!(
        text(&result),
        "x402 payment failed: x402 wallet: x402 payment ledger not initialized"
    );
}

#[tokio::test]
async fn a_wallet_that_cannot_sign_is_reported() {
    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let _dir = init_ledger();
    let server = TestServer::start(paid_config(evm_requirement())).await;
    let tool = X402RequestTool::new(
        Arc::new(FakePaymentSigner {
            account_error: Some("wallet secret: keyring locked".into()),
            ..FakePaymentSigner::default()
        }),
        Arc::new(FakeTransport::default()),
        Arc::new(FakeProxyPolicy::default()),
    );
    let result = run(&tool, json!({"url": server.url})).await;
    assert_eq!(
        text(&result),
        "x402 payment failed: x402 wallet: wallet secret: keyring locked"
    );
    ledger::reset_global();
}

#[tokio::test]
async fn a_retry_that_never_answers_is_recorded_as_failed() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let _guard = ledger::TEST_LOCK
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let _dir = init_ledger();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let header = challenge_header(&challenge(vec![evm_requirement()]));
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0u8; 4096];
        let _ = socket.read(&mut buffer).await.unwrap();
        let reply = format!(
            "HTTP/1.1 402 Payment Required\r\nPAYMENT-REQUIRED: {header}\r\n\
             Content-Length: 0\r\nConnection: close\r\n\r\n"
        );
        socket.write_all(reply.as_bytes()).await.unwrap();
        drop(socket);
        let (socket, _) = listener.accept().await.unwrap();
        drop(socket);
    });

    let result = run(&tool(), json!({"url": url})).await;
    assert!(result.is_error);
    assert!(
        text(&result).starts_with("x402 retry request failed: "),
        "{}",
        text(&result)
    );
    let statuses: Vec<_> = records().iter().map(|r| r.status).collect();
    assert_eq!(
        statuses,
        vec![PaymentStatus::Pending, PaymentStatus::Failed]
    );
    ledger::reset_global();
}

// ---------------------------------------------------------------------------
// Presentation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn networks_are_labelled_for_people() {
    let server = TestServer::start(ServerConfig::default()).await;
    let cases = [
        ("eip155:8453", "Base"),
        ("eip155:1", "Ethereum"),
        ("eip155:42161", "EVM"),
        ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp", "Solana"),
        ("cosmos:hub", "cosmos:hub"),
    ];
    for (network, label) in cases {
        let response = reqwest::get(&server.url).await.unwrap();
        let result = request::format_response_with_payment(
            response,
            "https://x",
            "0.000001 USDC",
            network,
            Some("sig"),
        )
        .await;
        assert!(
            text(&result).contains(&format!(
                "x402 payment: 0.000001 USDC on {label}\nTransaction: sig"
            )),
            "{network}: {}",
            text(&result)
        );
    }
}

#[test]
fn amounts_are_shown_as_six_decimal_usdc() {
    assert_eq!(request::format_usdc(2_500), "0.002500 USDC");
    assert_eq!(request::format_usdc(1_000_000), "1.000000 USDC");
    assert_eq!(request::format_usdc(0), "0.000000 USDC");
}
