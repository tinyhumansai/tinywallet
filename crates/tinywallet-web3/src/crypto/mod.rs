//! The crypto rail: the wallet engine, its chains and the swap/bridge/dapp
//! service, over the seams in [`seams`].
//!
//! Everything chain-specific lives here, apart from the rail-neutral
//! [`crate::quote`] and [`crate::seams`], so a future card rail can sit beside
//! it.
//!
//! - [`wallet`] — [`WalletEngine`](wallet::WalletEngine) and its vocabulary.
//! - [`execution`] — balances, transfers and lookups on the engine.
//! - [`chains`] — the per-chain choreography (private).
//! - [`defaults`] — static reference data.
//! - [`abi`] — ERC-20 calldata.
//! - [`service`] — swap, bridge and dapp calls.
//! - [`seams`] — what a host implements.

pub mod abi;
mod chains;
pub mod defaults;
pub mod execution;
pub mod seams;
pub mod service;
pub mod wallet;
