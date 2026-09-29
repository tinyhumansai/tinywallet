//! `web3_swap` agent tools: quote a single-chain swap, execute a prepared
//! quote, and list supported routes.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::service::{ExecuteQuoteParams, SwapQuoteParams, Web3Service};
use crate::quote::{execute_tool_schema, to_tool_result};

/// Prepares a single-chain swap.
#[derive(Debug)]
pub struct Web3SwapQuoteTool {
    service: Arc<Web3Service>,
}

/// Confirms and executes a prepared swap.
#[derive(Debug)]
pub struct Web3SwapExecuteTool {
    service: Arc<Web3Service>,
}

/// Lists the chains deBridge can swap and bridge between.
#[derive(Debug)]
pub struct Web3SwapRoutesTool {
    service: Arc<Web3Service>,
}

impl Web3SwapQuoteTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

impl Web3SwapExecuteTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

impl Web3SwapRoutesTool {
    /// A tool over `service`.
    #[must_use]
    pub const fn new(service: Arc<Web3Service>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl Tool for Web3SwapQuoteTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "web3_swap_quote"
    }

    fn description(&self) -> &str {
        "Prepare a single-chain crypto swap via deBridge. Returns a quote + quoteId to confirm with web3_swap_execute. For cross-chain swaps use web3_bridge_quote."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "chainId": {"type": "integer", "description": "deBridge chain id (1 ETH, 56 BNB, 137 Polygon, 8453 Base, 42161 Arbitrum, 10 Optimism, 7565164 Solana)."},
                "tokenIn": {"type": "string", "description": "Input token address (zero address for native)."},
                "tokenInAmount": {"type": "string", "description": "Input amount in the token's smallest unit."},
                "tokenOut": {"type": "string", "description": "Output token address."},
                "tokenOutRecipient": {"type": "string", "description": "Optional. Defaults to the wallet's own address."},
                "senderAddress": {"type": "string", "description": "Optional. Defaults to the wallet's own address."},
                "slippage": {"type": "string", "description": "Optional slippage percent or 'auto' (default 'auto')."}
            },
            "required": ["chainId", "tokenIn", "tokenInAmount", "tokenOut"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let params: SwapQuoteParams = match serde_json::from_value(args) {
            Ok(p) => p,
            Err(e) => return Ok(ToolResult::error(format!("invalid arguments: {e}"))),
        };
        Ok(to_tool_result(self.service.quote_swap(params).await))
    }
}

#[async_trait]
impl Tool for Web3SwapExecuteTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "web3_swap_execute"
    }

    fn description(&self) -> &str {
        "Confirm and execute a prepared web3_swap quote (signs + broadcasts)."
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

#[async_trait]
impl Tool for Web3SwapRoutesTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "web3_swap_routes"
    }

    fn description(&self) -> &str {
        "List the chains deBridge can swap/bridge between."
    }

    fn parameters_schema(&self) -> Value {
        json!({"type": "object", "properties": {}, "additionalProperties": false})
    }

    async fn execute(&self, _args: Value) -> anyhow::Result<ToolResult> {
        Ok(to_tool_result(self.service.routes().await))
    }
}
