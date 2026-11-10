//! Implementation-local quote state and raw broadcast results.

use tinywallet_bus::wire::QuoteOwner;

use crate::quote::Quoted;

pub use tinywallet_bus::wire::{
    BalanceInfo, ChainStatus, ExecutePreparedParams, ExecutionResult, PrepareTransferParams,
    PreparedKind, PreparedStatus, PreparedTransaction, ProviderStatus, SupportedAsset,
    TokenBalanceInfo, TxLookupInfo, TxReceiptInfo, TxState, TxStatusInfo,
};

/// The owner-bound record held in the implementation's quote store.
#[derive(Debug, Clone)]
pub(crate) struct PreparedTransferQuote {
    /// Public transfer facts returned by the contract API.
    pub transaction: PreparedTransaction,
    /// Owner captured when the transfer was prepared.
    pub owner: Option<QuoteOwner>,
}

impl Quoted for PreparedTransferQuote {
    fn quote_id(&self) -> &str {
        &self.transaction.quote_id
    }

    fn owner(&self) -> Option<&QuoteOwner> {
        self.owner.as_ref()
    }

    fn expires_at_ms(&self) -> u64 {
        self.transaction.expires_at_ms
    }

    fn set_expires_at_ms(&mut self, expires_at_ms: u64) {
        self.transaction.expires_at_ms = expires_at_ms;
    }

    fn is_consumed(&self) -> bool {
        self.transaction.status == PreparedStatus::Consumed
    }
}

/// Result of a low-level sign-and-broadcast primitive.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RawBroadcastResult {
    /// Transaction hash or signature from the network.
    pub transaction_hash: String,
    /// Explorer URL for the transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    /// Simulated fee in smallest units when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_raw: Option<String>,
}
