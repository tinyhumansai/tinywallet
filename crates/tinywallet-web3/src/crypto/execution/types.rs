//! Wire types for the wallet execution surface: chain/asset/balance snapshots,
//! the prepare-then-execute quote lifecycle, transaction lookups and the RPC
//! parameter shapes.

use serde::{Deserialize, Serialize};

use crate::crypto::defaults::EvmNetwork;
use crate::crypto::wallet::WalletChain;
use crate::quote::{QuoteOwner, Quoted};

/// Whether a chain has an account and a provider ready.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainStatus {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Whether the wallet has an account for the chain.
    pub configured: bool,
    /// Whether the provider is ready.
    pub provider_status: ProviderStatus,
    /// The endpoint the host resolved.
    pub rpc_url: String,
    /// Why the provider is not ready, when the wallet has an account but the
    /// endpoint did not answer a probe. Absent otherwise, so a healthy row
    /// serializes exactly as it always has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Whether a provider answered.
///
/// A chain status row is `Ready` only when its endpoint answered a probe.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    /// Ready.
    Ready,
    /// Missing or unreachable: the wallet has no account for the chain, or its
    /// endpoint did not answer (the reason is in the row's `error`).
    Missing,
}

/// An asset a wallet can hold or send.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedAsset {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Ticker symbol.
    pub symbol: String,
    /// Display name.
    pub name: String,
    /// Whether this is the chain's native asset.
    pub native: bool,
    /// Decimal places of the smallest unit.
    pub decimals: u8,
    /// Token contract or mint address; `None` for a native asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
}

/// A native-asset balance row.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceInfo {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// The wallet address the balance is for.
    pub address: String,
    /// The native asset's symbol.
    pub asset_symbol: String,
    /// Decimal places of the smallest unit.
    pub decimals: u8,
    /// The balance in the smallest unit.
    pub raw: String,
    /// The balance rendered with the decimal point.
    pub formatted: String,
    /// Whether the provider answered; a failed read reports a zero balance
    /// with [`ProviderStatus::Missing`].
    pub provider_status: ProviderStatus,
}

/// What a prepared transfer moves.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreparedKind {
    /// The chain's native asset.
    NativeTransfer,
    /// A token (ERC-20, SPL, TRC-20).
    TokenTransfer,
}

/// Where a prepared transfer is in its lifecycle.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreparedStatus {
    /// Waiting for the caller to confirm.
    AwaitingConfirmation,
    /// Signed and broadcast.
    Broadcasted,
    /// Already used.
    Consumed,
}

/// A prepared transfer awaiting confirmation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTransaction {
    /// The id a caller presents to execute the transfer.
    pub quote_id: String,
    /// Native or token transfer.
    pub kind: PreparedKind,
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// The wallet's own address.
    pub from_address: String,
    /// The recipient.
    pub to_address: String,
    /// The asset's symbol.
    pub asset_symbol: String,
    /// The amount in the smallest unit.
    pub amount_raw: String,
    /// The amount rendered with the decimal point.
    pub amount_formatted: String,
    /// The symbol received, for swaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_symbol: Option<String>,
    /// The minimum amount received, for swaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_receive_raw: Option<String>,
    /// Calldata, for contract calls.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calldata: Option<String>,
    /// The token contract or mint, for token transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_address: Option<String>,
    /// The fee estimate in the chain's smallest unit.
    pub estimated_fee_raw: String,
    /// Lifecycle status.
    pub status: PreparedStatus,
    /// When the quote was created, in milliseconds since the epoch.
    pub created_at_ms: u64,
    /// When the quote stops being executable, in milliseconds since the epoch.
    pub expires_at_ms: u64,
    /// Human-readable notes.
    pub notes: Vec<String>,
    /// Chat-thread owner stamped at prepare time. Present when the quote was
    /// prepared from inside an interactive chat turn; `None` for CLI,
    /// direct-RPC and background callers. Internal gate data: never serialized.
    #[serde(skip_serializing)]
    pub(crate) owner: Option<QuoteOwner>,
}

impl Quoted for PreparedTransaction {
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

    fn is_consumed(&self) -> bool {
        self.status == PreparedStatus::Consumed
    }
}

/// The outcome of executing a prepared transfer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResult {
    /// The quote that was executed.
    pub quote_id: String,
    /// The resulting status.
    pub status: PreparedStatus,
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// The transaction hash, signature or txid the network reported.
    pub transaction_hash: String,
    /// An explorer link for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    /// The transfer as it was executed.
    pub transaction: PreparedTransaction,
}

/// Result of a low-level "sign this unsigned transaction and broadcast it"
/// primitive. Unlike [`ExecutionResult`] it carries no [`PreparedTransaction`]:
/// it is the minimal output the swap/bridge/dapp service needs after handing
/// the wallet an externally-built transaction.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawBroadcastResult {
    /// The transaction hash or signature the network reported.
    pub transaction_hash: String,
    /// An explorer link for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    /// Simulated fee in the chain's smallest unit. `None` when the fee is not
    /// known at broadcast time (Solana's dynamic base-plus-priority fee, which
    /// must be read back from the confirmed transaction).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_raw: Option<String>,
}

/// Normalized lifecycle state of a broadcast transaction.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxState {
    /// Seen by the node but not yet included in a block.
    Pending,
    /// Included in a block and succeeded.
    Confirmed,
    /// Included in a block but reverted or failed.
    Failed,
    /// The node has no record of this hash.
    NotFound,
}

/// A transaction's lifecycle state.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxStatusInfo {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// The hash that was queried.
    pub hash: String,
    /// Lifecycle state.
    pub state: TxState,
    /// Confirmations, when the chain reports them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
    /// The block (or slot) that included the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
}

/// A transaction's receipt.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxReceiptInfo {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// The hash that was queried.
    pub hash: String,
    /// Whether the node knows the transaction.
    pub found: bool,
    /// Whether it succeeded, once known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    /// The block (or slot) that included the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Gas (or energy) used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
    /// The fee paid, in the chain's smallest unit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_raw: Option<String>,
    /// Raw provider receipt payload, passed through unchanged.
    pub raw: serde_json::Value,
}

/// A raw transaction lookup.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TxLookupInfo {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM lookups.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// The hash that was queried.
    pub hash: String,
    /// Whether the node knows the transaction.
    pub found: bool,
    /// Raw provider transaction payload, passed through unchanged.
    pub raw: serde_json::Value,
}

/// Parameters for preparing a transfer.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareTransferParams {
    /// The chain family.
    pub chain: WalletChain,
    /// The recipient.
    pub to_address: String,
    /// The amount in the smallest unit.
    pub amount_raw: String,
    /// The asset's symbol; the native asset when absent.
    #[serde(default)]
    pub asset_symbol: Option<String>,
    /// The EVM network; Ethereum mainnet when absent.
    #[serde(default)]
    pub evm_network: Option<EvmNetwork>,
}

/// Parameters for executing a prepared transfer.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecutePreparedParams {
    /// The quote to execute.
    pub quote_id: String,
    /// Must be `true`: the explicit boundary between preparing and acting.
    pub confirmed: bool,
}
