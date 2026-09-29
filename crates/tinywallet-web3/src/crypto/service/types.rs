//! Types for the swap, bridge and dapp flows: the deBridge chain-id to local
//! signer mapping, request parameters, and the stored quote shape.
//!
//! The backend (deBridge DLN) returns a ready-to-sign **unsigned transaction**.
//! This module only needs to know the *chain family* of a deBridge chain id so
//! signing can be routed to the right wallet primitive (EVM `to`/`data`/`value`
//! or a Solana `VersionedTransaction` hex blob).

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::crypto::defaults::EvmNetwork;
use crate::quote::{QuoteOwner, Quoted};

/// deBridge's internal chain id for Solana mainnet (`/supported-chains-info`).
/// EVM chains use their real chain ids; Solana is a synthetic id. Mirrors the
/// backend's `DEBRIDGE_SOLANA_CHAIN_ID` default.
pub const DEBRIDGE_SOLANA_CHAIN_ID: u64 = 7_565_164;

/// Which local signer can sign for a given deBridge chain id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFamily {
    /// An EVM chain: sign and broadcast `to`/`data`/`value`.
    Evm(EvmNetwork),
    /// Solana: sign and broadcast a serialized `VersionedTransaction`.
    Solana,
}

/// Map a deBridge chain id to the local signer family, or `None` when the
/// wallet has no signer for it (deBridge may route chains we cannot sign for).
#[must_use]
pub const fn chain_family(debridge_chain_id: u64) -> Option<ChainFamily> {
    match debridge_chain_id {
        1 => Some(ChainFamily::Evm(EvmNetwork::EthereumMainnet)),
        10 => Some(ChainFamily::Evm(EvmNetwork::OptimismMainnet)),
        56 => Some(ChainFamily::Evm(EvmNetwork::BscMainnet)),
        137 => Some(ChainFamily::Evm(EvmNetwork::PolygonMainnet)),
        8453 => Some(ChainFamily::Evm(EvmNetwork::BaseMainnet)),
        42161 => Some(ChainFamily::Evm(EvmNetwork::ArbitrumOne)),
        DEBRIDGE_SOLANA_CHAIN_ID => Some(ChainFamily::Solana),
        _ => None,
    }
}

/// Single-chain swap request (forwarded to the backend `/crypto/swap`).
/// `senderAddress` and `tokenOutRecipient` default to the wallet's own derived
/// address for the chain family when omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwapQuoteParams {
    /// deBridge chain id the swap executes on.
    pub chain_id: u64,
    /// Input token address (the zero address for native).
    pub token_in: String,
    /// Input amount in the token's smallest unit.
    pub token_in_amount: String,
    /// Output token address.
    pub token_out: String,
    /// Address receiving the output. Defaults to the wallet's own address.
    #[serde(default)]
    pub token_out_recipient: Option<String>,
    /// Sender. Defaults to the wallet's own address.
    #[serde(default)]
    pub sender_address: Option<String>,
    /// Slippage percent or `auto` (the default).
    #[serde(default)]
    pub slippage: Option<String>,
}

/// Cross-chain bridge request (forwarded to the backend `/crypto/bridge`).
/// Authority and recipient addresses default to the wallet's derived addresses
/// for the relevant chain family when omitted.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BridgeQuoteParams {
    /// Source deBridge chain id.
    pub src_chain_id: u64,
    /// Source token address.
    pub src_chain_token_in: String,
    /// Source amount in the token's smallest unit.
    pub src_chain_token_in_amount: String,
    /// Destination deBridge chain id (must differ from the source).
    pub dst_chain_id: u64,
    /// Destination token address.
    pub dst_chain_token_out: String,
    /// Destination amount; `auto` (the default) for the market rate.
    #[serde(default)]
    pub dst_chain_token_out_amount: Option<String>,
    /// Destination recipient. Defaults to the wallet's destination address.
    #[serde(default)]
    pub dst_chain_token_out_recipient: Option<String>,
    /// Source order authority. Defaults to the wallet's source address.
    #[serde(default)]
    pub src_chain_order_authority_address: Option<String>,
    /// Destination order authority. Defaults to the wallet's destination address.
    #[serde(default)]
    pub dst_chain_order_authority_address: Option<String>,
}

/// Generic EVM dapp contract call (no backend; signed directly via the wallet).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DappCallParams {
    /// The target contract.
    pub contract_address: String,
    /// `0x`-prefixed hex calldata.
    pub calldata: String,
    /// Native value in the smallest unit. Defaults to `0`.
    #[serde(default)]
    pub value_raw: Option<String>,
    /// The EVM network. Defaults to Ethereum mainnet.
    #[serde(default)]
    pub evm_network: Option<EvmNetwork>,
}

/// Confirm and execute a prepared quote.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteQuoteParams {
    /// The quote to execute.
    pub quote_id: String,
    /// Must be `true`: the explicit boundary between quoting and executing.
    pub confirmed: bool,
}

/// What a stored quote signs and broadcasts on execute.
#[derive(Debug, Clone)]
pub enum UnsignedTx {
    /// EVM transaction: `(network, to, data, value)`.
    Evm {
        /// The network to broadcast on.
        network: EvmNetwork,
        /// The target address.
        to: String,
        /// Calldata, `0x`-prefixed hex.
        data: Option<String>,
        /// Native value in wei, as a decimal string.
        value: String,
    },
    /// Solana serialized `VersionedTransaction`, hex-encoded.
    Solana {
        /// The hex-encoded transaction blob.
        tx_blob_hex: String,
    },
}

/// The kind of operation a quote represents (for summaries and logging).
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Web3QuoteKind {
    /// A single-chain swap.
    Swap,
    /// A cross-chain bridge.
    Bridge,
    /// A generic contract call.
    DappCall,
}

/// A prepared quote as the store holds it.
#[derive(Debug, Clone)]
pub struct StoredQuote {
    /// The id a caller presents to execute the quote.
    pub quote_id: String,
    /// What kind of operation it is.
    pub kind: Web3QuoteKind,
    /// The transaction to sign and broadcast.
    pub unsigned: UnsignedTx,
    /// Human/agent-facing summary returned at prepare time.
    pub summary: Value,
    pub(crate) owner: Option<QuoteOwner>,
    pub(crate) expires_at_ms: u64,
}

impl Quoted for StoredQuote {
    fn quote_id(&self) -> &str {
        &self.quote_id
    }

    fn owner(&self) -> Option<&QuoteOwner> {
        self.owner.as_ref()
    }

    fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    fn set_expires_at_ms(&mut self, expires_at_ms: u64) {
        self.expires_at_ms = expires_at_ms;
    }
}

/// Result returned to the agent or RPC caller after broadcasting.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3ExecutionResult {
    /// The quote that was executed.
    pub quote_id: String,
    /// What kind of operation it was.
    pub kind: Web3QuoteKind,
    /// The transaction hash or signature the network reported.
    pub transaction_hash: String,
    /// An explorer link for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    /// Simulated fee in the chain's smallest unit; `None` when not known at
    /// broadcast time (Solana's dynamic fee).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_raw: Option<String>,
}

/// The prepared-quote envelope returned to the caller.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3Quote {
    /// The id to confirm and execute with.
    pub quote_id: String,
    /// What kind of operation it is.
    pub kind: Web3QuoteKind,
    /// When the quote stops being executable, in milliseconds since the epoch.
    pub expires_at_ms: u64,
    /// Backend (deBridge) quote passthrough, or a dapp-call summary.
    pub quote: Value,
}
