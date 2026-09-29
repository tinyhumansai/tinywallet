//! Read-only tools for inspecting on-chain transactions by hash:
//! `wallet_tx_status`, `wallet_tx_receipt` and `wallet_lookup_tx`. All three
//! share the `{chain, hash, evmNetwork?}` input.

use std::sync::Arc;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::{Value, json};
use tinytools::{Tool, ToolExposure, ToolResult};

use crate::crypto::defaults::EvmNetwork;
use crate::crypto::wallet::{WalletChain, WalletEngine};
use crate::quote::to_tool_result;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TxQueryArgs {
    chain: WalletChain,
    #[serde(default)]
    evm_network: Option<EvmNetwork>,
    hash: String,
}

fn tx_query_schema(verb: &str) -> Value {
    json!({
        "type": "object",
        "properties": {
            "chain": {
                "type": "string",
                "enum": ["evm", "btc", "solana", "tron"],
                "description": format!("Blockchain network whose transaction to {verb}")
            },
            "hash": {
                "type": "string",
                "description": "Transaction hash / signature / txid to query"
            },
            "evmNetwork": {
                "type": "string",
                "enum": ["ethereum_mainnet", "base_mainnet", "arbitrum_one", "optimism_mainnet", "polygon_mainnet", "bsc_mainnet"],
                "description": "Optional EVM network when chain='evm'. Defaults to ethereum_mainnet."
            }
        },
        "required": ["chain", "hash"],
        "additionalProperties": false
    })
}

fn parse_args(args: Value) -> Result<TxQueryArgs, ToolResult> {
    serde_json::from_value(args).map_err(|e| ToolResult::error(format!("invalid arguments: {e}")))
}

/// Checks the lifecycle state of a transaction.
#[derive(Debug)]
pub struct WalletTxStatusTool {
    engine: Arc<WalletEngine>,
}

impl WalletTxStatusTool {
    /// A tool over `engine`.
    #[must_use]
    pub const fn new(engine: Arc<WalletEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl Tool for WalletTxStatusTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "wallet_tx_status"
    }

    fn description(&self) -> &str {
        "Check the on-chain lifecycle state (pending / confirmed / failed / not_found) of a transaction by hash."
    }

    fn parameters_schema(&self) -> Value {
        tx_query_schema("check")
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let args = match parse_args(args) {
            Ok(a) => a,
            Err(err) => return Ok(err),
        };
        Ok(to_tool_result(
            self.engine
                .tx_status(args.chain, args.evm_network, &args.hash)
                .await,
        ))
    }
}

/// Fetches the receipt of a broadcast transaction.
#[derive(Debug)]
pub struct WalletTxReceiptTool {
    engine: Arc<WalletEngine>,
}

impl WalletTxReceiptTool {
    /// A tool over `engine`.
    #[must_use]
    pub const fn new(engine: Arc<WalletEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl Tool for WalletTxReceiptTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "wallet_tx_receipt"
    }

    fn description(&self) -> &str {
        "Fetch the receipt of a broadcast transaction (success flag, fee, block, gas used) by hash."
    }

    fn parameters_schema(&self) -> Value {
        tx_query_schema("fetch the receipt for")
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let args = match parse_args(args) {
            Ok(a) => a,
            Err(err) => return Ok(err),
        };
        Ok(to_tool_result(
            self.engine
                .tx_receipt(args.chain, args.evm_network, &args.hash)
                .await,
        ))
    }
}

/// Looks up the raw transaction payload by hash.
#[derive(Debug)]
pub struct WalletLookupTxTool {
    engine: Arc<WalletEngine>,
}

impl WalletLookupTxTool {
    /// A tool over `engine`.
    #[must_use]
    pub const fn new(engine: Arc<WalletEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl Tool for WalletLookupTxTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "wallet_lookup_tx"
    }

    fn description(&self) -> &str {
        "Look up the raw transaction payload by hash on the target chain."
    }

    fn parameters_schema(&self) -> Value {
        tx_query_schema("look up")
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let args = match parse_args(args) {
            Ok(a) => a,
            Err(err) => return Ok(err),
        };
        Ok(to_tool_result(
            self.engine
                .lookup_tx(args.chain, args.evm_network, &args.hash)
                .await,
        ))
    }
}
