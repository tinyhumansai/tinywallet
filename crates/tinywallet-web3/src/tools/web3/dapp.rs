//! `web3_dapp` agent tools: prepare a generic EVM contract call and execute it.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::service::{DappCallParams, ExecuteQuoteParams, Web3Service};
use crate::quote::{execute_tool_schema, to_tool_result};

/// Prepares a generic EVM contract call.
#[derive(Debug)]
pub struct Web3DappCallTool {
    service: Arc<Web3Service>,
}

/// Confirms and executes a prepared contract call.
#[derive(Debug)]
pub struct Web3DappExecuteTool {
    service: Arc<Web3Service>,
}

impl Web3DappCallTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

impl Web3DappExecuteTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Tool for Web3DappCallTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "web3_dapp_call"
    }

    fn description(&self) -> &str {
        "Prepare a generic EVM dapp contract call from pre-encoded calldata. Returns a quoteId to confirm with web3_dapp_execute."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "contractAddress": {"type": "string", "description": "Target contract address."},
                "calldata": {"type": "string", "description": "0x-prefixed hex calldata."},
                "valueRaw": {"type": "string", "description": "Optional native value (smallest unit). Defaults to '0'."},
                "evmNetwork": {
                    "type": "string",
                    "enum": ["ethereum_mainnet", "base_mainnet", "arbitrum_one", "optimism_mainnet", "polygon_mainnet", "bsc_mainnet"],
                    "description": "Optional EVM network. Defaults to ethereum_mainnet."
                }
            },
            "required": ["contractAddress", "calldata"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let params: DappCallParams = match serde_json::from_value(args) {
            Ok(p) => p,
            Err(e) => return Ok(ToolResult::error(format!("invalid arguments: {e}"))),
        };
        Ok(to_tool_result(self.service.prepare_dapp_call(params).await))
    }
}

#[async_trait]
impl Tool for Web3DappExecuteTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "web3_dapp_execute"
    }

    fn description(&self) -> &str {
        "Confirm and execute a prepared web3_dapp call (signs + broadcasts)."
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
