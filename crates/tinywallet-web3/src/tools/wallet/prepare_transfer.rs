//! `wallet_prepare_transfer`: prepare a transfer quote to confirm later.

use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, warn};
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::execution::PrepareTransferParams;
use crate::crypto::wallet::WalletEngine;
use crate::quote::to_tool_result;

/// Prepares a cryptocurrency transfer.
#[derive(Debug)]
pub struct WalletPrepareTransferTool {
    engine: Arc<WalletEngine>,
}

impl WalletPrepareTransferTool {
    /// A tool over `engine`.
    #[must_use]
    pub const fn new(engine: Arc<WalletEngine>) -> Self {
        Self { engine }
    }
}

/// The first six and last four characters of an address, for correlation
/// without logging it whole.
fn redact_address(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 10 {
        return "…".to_string();
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail}")
}

#[async_trait]
impl Tool for WalletPrepareTransferTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "wallet_prepare_transfer"
    }

    fn description(&self) -> &str {
        "Prepare a cryptocurrency transfer. Returns a quote that must be confirmed before execution."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "chain": {
                    "type": "string",
                    "enum": ["evm", "btc", "solana", "tron"],
                    "description": "Blockchain network to use"
                },
                "toAddress": {
                    "type": "string",
                    "description": "Destination wallet address"
                },
                "amountRaw": {
                    "type": "string",
                    "description": "Transfer amount in the chain's smallest unit (e.g. wei for EVM)"
                },
                "assetSymbol": {
                    "type": "string",
                    "description": "Asset symbol (e.g. ETH, USDC). Defaults to the native asset."
                },
                "evmNetwork": {
                    "type": "string",
                    "enum": ["ethereum_mainnet", "base_mainnet", "arbitrum_one", "optimism_mainnet", "polygon_mainnet", "bsc_mainnet"],
                    "description": "Optional EVM network when chain='evm'. Defaults to ethereum_mainnet."
                }
            },
            "required": ["chain", "toAddress", "amountRaw"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let params: PrepareTransferParams = match serde_json::from_value(args) {
            Ok(p) => p,
            Err(e) => {
                debug!("[wallet_prepare_transfer] invalid arguments: {e}");
                return Ok(ToolResult::error(format!("invalid arguments: {e}")));
            }
        };
        debug!(
            "[wallet_prepare_transfer] chain={:?} to={} amount_len={}",
            params.chain,
            redact_address(&params.to_address),
            params.amount_raw.len()
        );
        let result = self.engine.prepare_transfer(params).await;
        match &result {
            Ok(_) => debug!("[wallet_prepare_transfer] success"),
            Err(e) => warn!("[wallet_prepare_transfer] failed: {e}"),
        }
        Ok(to_tool_result(result))
    }
}
