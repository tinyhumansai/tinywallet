//! `web3_bridge` agent tools: quote a cross-chain bridge and execute it.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::service::{BridgeQuoteParams, ExecuteQuoteParams, Web3Service};
use crate::quote::{execute_tool_schema, to_tool_result};

/// Prepares a cross-chain bridge.
#[derive(Debug)]
pub struct Web3BridgeQuoteTool {
    service: Arc<Web3Service>,
}

/// Confirms and executes a prepared bridge.
#[derive(Debug)]
pub struct Web3BridgeExecuteTool {
    service: Arc<Web3Service>,
}

impl Web3BridgeQuoteTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

impl Web3BridgeExecuteTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Tool for Web3BridgeQuoteTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &'static str {
        "web3_bridge_quote"
    }

    fn description(&self) -> &'static str {
        "Prepare a cross-chain bridge via deBridge DLN. Returns a quote + quoteId to confirm with web3_bridge_execute. Source and destination chains must differ."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "srcChainId": {"type": "integer", "description": "Source deBridge chain id."},
                "srcChainTokenIn": {"type": "string", "description": "Source token address."},
                "srcChainTokenInAmount": {"type": "string", "description": "Source amount in the token's smallest unit."},
                "dstChainId": {"type": "integer", "description": "Destination deBridge chain id (must differ from source)."},
                "dstChainTokenOut": {"type": "string", "description": "Destination token address."},
                "dstChainTokenOutAmount": {"type": "string", "description": "Optional. 'auto' for market rate (default)."},
                "dstChainTokenOutRecipient": {"type": "string", "description": "Optional. Defaults to the wallet's own destination address."},
                "srcChainOrderAuthorityAddress": {"type": "string", "description": "Optional. Defaults to the wallet's source address."},
                "dstChainOrderAuthorityAddress": {"type": "string", "description": "Optional. Defaults to the wallet's destination address."}
            },
            "required": ["srcChainId", "srcChainTokenIn", "srcChainTokenInAmount", "dstChainId", "dstChainTokenOut"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let params: BridgeQuoteParams = match serde_json::from_value(args) {
            Ok(p) => p,
            Err(e) => return Ok(ToolResult::error(format!("invalid arguments: {e}"))),
        };
        Ok(to_tool_result(self.service.quote_bridge(params).await))
    }
}

#[async_trait]
impl Tool for Web3BridgeExecuteTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &'static str {
        "web3_bridge_execute"
    }

    fn description(&self) -> &'static str {
        "Confirm and execute a prepared web3_bridge quote (signs + broadcasts the source-chain tx)."
    }

    fn parameters_schema(&self) -> Value {
        execute_tool_schema()
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let params: ExecuteQuoteParams = match serde_json::from_value(args) {
            Ok(p) => p,
            Err(e) => return Ok(ToolResult::error(format!("invalid arguments: {e}"))),
        };
        Ok(to_tool_result(self.service.execute_quote(params).await))
    }
}
