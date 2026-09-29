//! `wallet_chain_status`: which chains have an account and a provider.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::wallet::WalletEngine;
use crate::quote::to_tool_result;

/// Lists chain readiness.
#[derive(Debug)]
pub struct WalletChainStatusTool {
    engine: Arc<WalletEngine>,
}

impl WalletChainStatusTool {
    /// A tool over `engine`.
    #[must_use]
    pub const fn new(engine: Arc<WalletEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl Tool for WalletChainStatusTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "wallet_chain_status"
    }

    fn description(&self) -> &str {
        "List blockchain chain readiness — which chains have a configured account and RPC provider."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    async fn execute(&self, _args: Value) -> anyhow::Result<ToolResult> {
        Ok(to_tool_result(self.engine.chain_status().await))
    }
}
