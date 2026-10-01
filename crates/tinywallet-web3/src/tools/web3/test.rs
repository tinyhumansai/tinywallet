//! Tests for the swap, bridge and dapp tools.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use super::{
    Web3BridgeExecuteTool, Web3BridgeQuoteTool, Web3DappCallTool, Web3DappExecuteTool,
    Web3SwapExecuteTool, Web3SwapQuoteTool, Web3SwapRoutesTool,
};
use crate::test_support::ServiceRig;

fn parsed(result: &ToolResult) -> Value {
    assert!(!result.is_error, "{}", result.output());
    serde_json::from_str(&result.output()).unwrap()
}

#[test]
fn every_web3_tool_is_deferred_and_named_as_documented() {
    let rig = ServiceRig::new();
    let s = &rig.service;
    let tools: Vec<(Box<dyn Tool>, &str)> = vec![
        (
            Box::new(Web3SwapQuoteTool::new(s.clone())),
            "web3_swap_quote",
        ),
        (
            Box::new(Web3SwapExecuteTool::new(s.clone())),
            "web3_swap_execute",
        ),
        (
            Box::new(Web3SwapRoutesTool::new(s.clone())),
            "web3_swap_routes",
        ),
        (
            Box::new(Web3BridgeQuoteTool::new(s.clone())),
            "web3_bridge_quote",
        ),
        (
            Box::new(Web3BridgeExecuteTool::new(s.clone())),
            "web3_bridge_execute",
        ),
        (Box::new(Web3DappCallTool::new(s.clone())), "web3_dapp_call"),
        (
            Box::new(Web3DappExecuteTool::new(s.clone())),
            "web3_dapp_execute",
        ),
    ];
    for (tool, name) in &tools {
        assert_eq!(tool.name(), *name);
        assert!(matches!(tool.exposure(), ToolExposure::Deferred), "{name}");
        assert_ne!(tool.description().len(), 0);
        assert_eq!(
            tool.parameters_schema()["additionalProperties"],
            false,
            "{name}"
        );
    }
}

#[test]
fn the_execute_tools_share_one_schema_requiring_confirmation() {
    let rig = ServiceRig::new();
    let schemas = [
        Web3SwapExecuteTool::new(rig.service.clone()).parameters_schema(),
        Web3BridgeExecuteTool::new(rig.service.clone()).parameters_schema(),
        Web3DappExecuteTool::new(rig.service.clone()).parameters_schema(),
    ];
    for schema in &schemas {
        assert_eq!(schema["required"], json!(["quoteId", "confirmed"]));
    }
}

#[test]
fn the_quote_schemas_list_their_required_inputs() {
    let rig = ServiceRig::new();
    let swap = Web3SwapQuoteTool::new(rig.service.clone()).parameters_schema();
    assert_eq!(
        swap["required"],
        json!(["chainId", "tokenIn", "tokenInAmount", "tokenOut"])
    );
    let bridge = Web3BridgeQuoteTool::new(rig.service.clone()).parameters_schema();
    assert!(
        bridge["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "dstChainId")
    );
    let dapp = Web3DappCallTool::new(rig.service.clone()).parameters_schema();
    assert_eq!(
        dapp["properties"]["evmNetwork"]["enum"]
            .as_array()
            .unwrap()
            .len(),
        6
    );
    assert_eq!(
        Web3SwapRoutesTool::new(rig.service.clone()).parameters_schema()["properties"],
        json!({})
    );
}

#[tokio::test]
async fn swap_tools_quote_and_execute_end_to_end() {
    let rig = ServiceRig::new();
    rig.rig.script_evm_node("0x1");
    rig.backend.set_swap(Ok(json!({"estimation": {}, "tx": {"to": "0x1111111111111111111111111111111111111111", "data": "0xabcd", "value": "0"}})));
    let quote = Web3SwapQuoteTool::new(rig.service.clone())
        .execute(json!({"chainId": 1, "tokenIn": "0x0", "tokenInAmount": "1", "tokenOut": "0x1"}))
        .await
        .unwrap();
    let quote_id = parsed(&quote)["quoteId"].as_str().unwrap().to_string();

    let executed = Web3SwapExecuteTool::new(rig.service.clone())
        .execute(json!({"quoteId": quote_id, "confirmed": true}))
        .await
        .unwrap();
    assert_eq!(parsed(&executed)["kind"], "swap");
}

#[tokio::test]
async fn bridge_tools_quote_and_reject() {
    let rig = ServiceRig::new();
    rig.backend.set_bridge(Ok(
        json!({"tx": {"to": "0xabc", "data": "0x", "value": "1"}}),
    ));
    let quote = Web3BridgeQuoteTool::new(rig.service.clone())
        .execute(json!({"srcChainId": 1, "srcChainTokenIn": "0x0", "srcChainTokenInAmount": "1", "dstChainId": 56, "dstChainTokenOut": "0x1"}))
        .await
        .unwrap();
    assert_eq!(parsed(&quote)["kind"], "bridge");

    let same = Web3BridgeQuoteTool::new(rig.service.clone())
        .execute(json!({"srcChainId": 1, "srcChainTokenIn": "0x0", "srcChainTokenInAmount": "1", "dstChainId": 1, "dstChainTokenOut": "0x1"}))
        .await
        .unwrap();
    assert!(same.is_error);
    assert!(same.output().contains("different source and destination"));

    let unconfirmed = Web3BridgeExecuteTool::new(rig.service.clone())
        .execute(json!({"quoteId": "w3_x", "confirmed": false}))
        .await
        .unwrap();
    assert_eq!(unconfirmed.output(), "execute requires `confirmed: true`");
}

#[tokio::test]
async fn dapp_tools_prepare_and_execute() {
    let rig = ServiceRig::new();
    rig.rig.script_evm_node("0x1");
    let quote = Web3DappCallTool::new(rig.service.clone())
        .execute(json!({"contractAddress": "0x1111111111111111111111111111111111111111", "calldata": "0xabcd"}))
        .await
        .unwrap();
    let quote_id = parsed(&quote)["quoteId"].as_str().unwrap().to_string();
    let executed = Web3DappExecuteTool::new(rig.service.clone())
        .execute(json!({"quoteId": quote_id, "confirmed": true}))
        .await
        .unwrap();
    assert!(
        parsed(&executed)["transactionHash"]
            .as_str()
            .unwrap()
            .starts_with("0xaaaa")
    );
}

#[tokio::test]
async fn routes_are_listed_or_the_backend_error_is_returned() {
    let rig = ServiceRig::new();
    rig.backend.set_routes(Ok(json!({"chains": [1]})));
    let tool = Web3SwapRoutesTool::new(rig.service.clone());
    assert_eq!(
        parsed(&tool.execute(json!({})).await.unwrap()),
        json!({"chains": [1]})
    );
    rig.backend
        .set_routes(Err("web3 routes failed: signed out".to_string()));
    let out = tool.execute(json!({})).await.unwrap();
    assert!(out.is_error);
    assert_eq!(out.output(), "web3 routes failed: signed out");
}

#[tokio::test]
async fn malformed_arguments_are_reported_not_panicked_on() {
    let rig = ServiceRig::new();
    let tools: Vec<Box<dyn Tool>> = vec![
        Box::new(Web3SwapQuoteTool::new(rig.service.clone())),
        Box::new(Web3SwapExecuteTool::new(rig.service.clone())),
        Box::new(Web3BridgeQuoteTool::new(rig.service.clone())),
        Box::new(Web3BridgeExecuteTool::new(rig.service.clone())),
        Box::new(Web3DappCallTool::new(rig.service.clone())),
        Box::new(Web3DappExecuteTool::new(rig.service.clone())),
    ];
    for tool in tools {
        let out = tool.execute(json!({"unexpected": true})).await.unwrap();
        assert!(out.is_error, "{}", tool.name());
        assert!(
            out.output().starts_with("invalid arguments:"),
            "{}: {}",
            tool.name(),
            out.output()
        );
    }
}
