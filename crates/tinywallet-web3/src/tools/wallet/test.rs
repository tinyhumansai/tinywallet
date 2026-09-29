//! Tests for the wallet tools.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use super::{
    WalletChainStatusTool, WalletLookupTxTool, WalletPrepareTransferTool, WalletStatusTool,
    WalletTxReceiptTool, WalletTxStatusTool,
};
use crate::test_support::{FakeWalletAccounts, Rig};

fn text(result: &ToolResult) -> String {
    result.output()
}

fn parsed(result: &ToolResult) -> Value {
    assert!(!result.is_error, "{}", text(result));
    serde_json::from_str(&text(result)).unwrap()
}

#[test]
fn every_wallet_tool_is_deferred_and_named_as_documented() {
    let rig = Rig::new();
    let e = &rig.engine;
    let tools: Vec<(Box<dyn Tool>, &str)> = vec![
        (Box::new(WalletStatusTool::new(e.clone())), "wallet_status"),
        (
            Box::new(WalletChainStatusTool::new(e.clone())),
            "wallet_chain_status",
        ),
        (
            Box::new(WalletPrepareTransferTool::new(e.clone())),
            "wallet_prepare_transfer",
        ),
        (
            Box::new(WalletTxStatusTool::new(e.clone())),
            "wallet_tx_status",
        ),
        (
            Box::new(WalletTxReceiptTool::new(e.clone())),
            "wallet_tx_receipt",
        ),
        (
            Box::new(WalletLookupTxTool::new(e.clone())),
            "wallet_lookup_tx",
        ),
    ];
    for (tool, name) in &tools {
        assert_eq!(tool.name(), *name);
        assert!(matches!(tool.exposure(), ToolExposure::Deferred), "{name}");
        assert!(!tool.description().is_empty());
        let schema = tool.parameters_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(
            schema["additionalProperties"], false,
            "{name} must reject unknown arguments"
        );
    }
}

#[test]
fn the_transfer_and_lookup_schemas_require_what_the_engine_needs() {
    let rig = Rig::new();
    let prepare = WalletPrepareTransferTool::new(rig.engine.clone()).parameters_schema();
    assert_eq!(
        prepare["required"],
        json!(["chain", "toAddress", "amountRaw"])
    );
    assert_eq!(
        prepare["properties"]["chain"]["enum"],
        json!(["evm", "btc", "solana", "tron"])
    );
    let lookup = WalletLookupTxTool::new(rig.engine.clone()).parameters_schema();
    assert_eq!(lookup["required"], json!(["chain", "hash"]));
    assert!(
        lookup["properties"]["chain"]["description"]
            .as_str()
            .unwrap()
            .contains("look up")
    );
}

#[tokio::test]
async fn wallet_status_reports_the_hosts_status_as_json() {
    let rig = Rig::new();
    let out = WalletStatusTool::new(rig.engine.clone())
        .execute(json!({}))
        .await
        .unwrap();
    let status = parsed(&out);
    assert_eq!(status["configured"], true);
    assert_eq!(status["accounts"].as_array().unwrap().len(), 4);

    rig.accounts.set(Err("keyring locked".to_string()));
    let out = WalletStatusTool::new(rig.engine.clone())
        .execute(json!({}))
        .await
        .unwrap();
    assert!(out.is_error);
    assert_eq!(text(&out), "keyring locked");
    rig.accounts.set(Ok(FakeWalletAccounts::unconfigured()));
    let out = WalletStatusTool::new(rig.engine.clone())
        .execute(json!({}))
        .await
        .unwrap();
    assert_eq!(parsed(&out)["configured"], false);
}

#[tokio::test]
async fn chain_status_lists_every_chain_row() {
    let rig = Rig::new();
    let out = WalletChainStatusTool::new(rig.engine.clone())
        .execute(json!({}))
        .await
        .unwrap();
    assert_eq!(parsed(&out).as_array().unwrap().len(), 9);
    rig.accounts.set(Err("nope".to_string()));
    let out = WalletChainStatusTool::new(rig.engine.clone())
        .execute(json!({}))
        .await
        .unwrap();
    assert!(out.is_error);
}

#[tokio::test]
async fn prepare_transfer_returns_the_quote_or_the_reason() {
    let rig = Rig::new();
    let tool = WalletPrepareTransferTool::new(rig.engine.clone());
    let ok = tool
        .execute(json!({"chain": "evm", "toAddress": "0x1111111111111111111111111111111111111111", "amountRaw": "1000"}))
        .await
        .unwrap();
    let quote = parsed(&ok);
    assert!(quote["quoteId"].as_str().unwrap().starts_with("q_"));
    assert_eq!(quote["assetSymbol"], "ETH");

    let bad_args = tool.execute(json!({"chain": "dogecoin"})).await.unwrap();
    assert!(bad_args.is_error);
    assert!(
        text(&bad_args).starts_with("invalid arguments:"),
        "{}",
        text(&bad_args)
    );

    let rejected = tool
        .execute(json!({"chain": "evm", "toAddress": "nope", "amountRaw": "1"}))
        .await
        .unwrap();
    assert!(rejected.is_error);
}

#[tokio::test]
async fn a_short_or_non_ascii_recipient_never_panics_the_logger() {
    let rig = Rig::new();
    let tool = WalletPrepareTransferTool::new(rig.engine.clone());
    for to in ["", "x", "0x12", "ééééééééééééé", "😀😀😀😀😀😀😀😀😀😀😀😀"]
    {
        let out = tool
            .execute(json!({"chain": "evm", "toAddress": to, "amountRaw": "1"}))
            .await
            .unwrap();
        assert!(out.is_error, "{to}");
    }
}

#[tokio::test]
async fn the_lookup_tools_dispatch_and_report_arguments_errors() {
    let rig = Rig::new();
    rig.transport.on_rpc(
        "eth_getTransactionReceipt",
        json!({"status": "0x1", "blockNumber": "0x1"}),
    );
    rig.transport.on_rpc("eth_blockNumber", json!("0x2"));
    rig.transport
        .on_rpc("eth_getTransactionByHash", json!({"hash": "0xabc"}));
    let args = json!({"chain": "evm", "hash": "0xabc", "evmNetwork": "base_mainnet"});

    let status = WalletTxStatusTool::new(rig.engine.clone())
        .execute(args.clone())
        .await
        .unwrap();
    assert_eq!(parsed(&status)["state"], "confirmed");
    let receipt = WalletTxReceiptTool::new(rig.engine.clone())
        .execute(args.clone())
        .await
        .unwrap();
    assert_eq!(parsed(&receipt)["found"], true);
    let lookup = WalletLookupTxTool::new(rig.engine.clone())
        .execute(args)
        .await
        .unwrap();
    assert_eq!(parsed(&lookup)["found"], true);

    for tool in [
        Box::new(WalletTxStatusTool::new(rig.engine.clone())) as Box<dyn Tool>,
        Box::new(WalletTxReceiptTool::new(rig.engine.clone())),
        Box::new(WalletLookupTxTool::new(rig.engine.clone())),
    ] {
        let bad = tool.execute(json!({"chain": "evm"})).await.unwrap();
        assert!(bad.is_error);
        assert!(
            text(&bad).starts_with("invalid arguments:"),
            "{}",
            text(&bad)
        );
        let empty = tool
            .execute(json!({"chain": "evm", "hash": " "}))
            .await
            .unwrap();
        assert_eq!(text(&empty), "tx hash is empty");
    }
}
