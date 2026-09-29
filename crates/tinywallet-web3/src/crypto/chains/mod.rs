//! Per-chain wallet executors. Each submodule owns its transaction
//! choreography (which RPC calls, in what order, what gets signed and what
//! gets broadcast) but never a key: signing goes through
//! [`WalletSigner`](crate::crypto::seams::WalletSigner) and the network through
//! [`Transport`](tinywallet_crypto::rpc::Transport).
//!
//! Every chain exposes a small surface, as free functions over a
//! [`WalletEngine`](crate::crypto::wallet::WalletEngine):
//!
//! - `execute_*_quote(engine, quote)` — sign and broadcast a prepared transfer.
//! - `native_balance(engine, address)` — the native-asset balance.
//! - `tx_status` / `tx_receipt` / `lookup_tx` — read-only inspection by hash.
//!
//! EVM and Solana additionally expose `sign_and_broadcast_*` primitives that
//! sign and broadcast an externally-built transaction for the swap/bridge/dapp
//! service.

pub(crate) mod btc;
pub(crate) mod evm;
mod rpc;
pub(crate) mod solana;
pub(crate) mod tron;
