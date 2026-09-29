//! `wallet_status`: whether the wallet is set up and which accounts it has.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::wallet::WalletEngine;
use crate::quote::to_tool_result;

/// Reports the wallet's set-up state and accounts.
#[derive(Debug)]
pub struct WalletStatusTool {
    engine: Arc<WalletEngine>,
}

impl WalletStatusTool {
    /// A tool over `engine`.
    #[must_use]
    pub const fn new(engine: Arc<WalletEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl Tool for WalletStatusTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "wallet_status"
    }

    fn description(&self) -> &str {
        "Check wallet configuration status — whether the wallet is set up, which chains are configured, and available accounts."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {},
            "additionalProperties": false
        })
    }

    async fn execute(&self, _args: Value) -> anyhow::Result<ToolResult> {
        Ok(to_tool_result(self.engine.accounts.status().await))
    }
}
