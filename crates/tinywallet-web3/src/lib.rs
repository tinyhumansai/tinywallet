//! Wallet, swap, bridge and dapp flows for `TinyWallet`, behind host seams.
//!
//! This crate is the logic that used to live in the `OpenHuman` host: balances,
//! transfers, transaction lookups, swaps, bridges and generic contract calls,
//! each as a prepare-then-confirm flow. It holds no key, no HTTP client and no
//! configuration. A host implements the seams and hands over an engine.
//!
//! # Layout
//!
//! | Module | What it is |
//! | --- | --- |
//! | [`quote`] | rail-neutral: the capped, TTL'd, owner-gated quote store |
//! | [`seams`] | rail-neutral: [`QuoteScope`](seams::QuoteScope) |
//! | [`crypto`] | the crypto rail: wallet engine, chains, swap/bridge/dapp service |
//! | `tools` | agent tools over the engine and the service (feature `tools`) |
//!
//! Keeping the rail-neutral half apart from the crypto half is deliberate: a
//! later card rail can reuse [`quote`] and [`seams`] without touching the chain
//! code. A CI guard keeps chain vocabulary out of those two modules.
//!
//! # Keys never enter this crate
//!
//! Derivation and signing go through
//! [`WalletSigner`](crypto::seams::WalletSigner), typically backed by the
//! loaded wallet module. The crate sees an address and finished signatures.
//!
//! # Using it
//!
//! ```
//! use std::sync::Arc;
//! use tinywallet_web3::crypto::wallet::{WalletEngine, WalletSeams};
//! # fn seams() -> WalletSeams { unimplemented!() }
//! # fn demo() {
//! let engine = Arc::new(WalletEngine::new(seams()));
//! # let _ = engine;
//! # }
//! ```
//!
//! # Feature flags
//!
//! | Feature | Default | Gates |
//! | --- | --- | --- |
//! | `tools` | off | the agent tools ([`tools`]) and `quote::to_tool_result` |

pub mod crypto;
pub mod quote;
pub mod seams;
#[cfg(feature = "tools")]
pub mod tools;
#[cfg(test)]
mod test_support;
