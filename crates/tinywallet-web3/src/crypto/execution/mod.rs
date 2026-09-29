//! The wallet execution surface: read operations (balances, supported assets,
//! network defaults, chain status, transaction lookups) and write operations
//! (prepare-then-execute) for native sends and token transfers.
//!
//! Execution is intentionally narrower than the metadata surface:
//!
//! - Every write is prepared first, then explicitly confirmed.
//! - Secret material never enters this crate; signing goes through
//!   [`WalletSigner`](crate::crypto::seams::WalletSigner).
//! - EVM (Ethereum and the L2s), Bitcoin (P2WPKH), Solana (native and SPL) and
//!   Tron (native and TRC-20) all sign and broadcast.
//!
//! The operations are methods on
//! [`WalletEngine`](crate::crypto::wallet::WalletEngine), split by concern:
//!
//! - [`types`] — wire types: snapshots, the quote lifecycle, lookups, params.
//! - [`validate`] — address/amount/calldata validation, formatting, hex.
//! - `accounts` — resolving a derived account for a chain.
//! - `queries` — the read-only surface.
//! - `transfer` — preparing a transfer quote.
//! - `tx_lookup` — transaction status, receipt and raw lookup.
//! - `broadcast` — `execute_prepared` and the raw sign-and-broadcast
//!   primitives.

mod accounts;
mod broadcast;
mod queries;
mod transfer;
mod tx_lookup;
mod types;
mod validate;

pub use types::{
    BalanceInfo, ChainStatus, ExecutePreparedParams, ExecutionResult, PrepareTransferParams,
    PreparedKind, PreparedStatus, PreparedTransaction, ProviderStatus, RawBroadcastResult,
    SupportedAsset, TxLookupInfo, TxReceiptInfo, TxState, TxStatusInfo,
};
pub use validate::{hex_to_bytes, hex_to_u128, u128_to_hex};

pub(crate) use validate::validate_calldata;

/// Log prefix shared by the execution modules.
const LOG_PREFIX: &str = "[wallet]";

#[cfg(test)]
mod test;
