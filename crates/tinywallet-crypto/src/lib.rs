//! The crypto rail of `TinyWallet`: the pure, chain-specific rules a host runs
//! itself, with no key material, no signer and no network I/O.
//!
//! This crate holds what used to sit in `tinywallet-bus` beside the wire
//! contract, and was split out so the bus can stay contract-only:
//!
//! - [`address`] — validating an address *before* a spec is sent. A bad address
//!   caught here is a rejected input; caught in the module it is a failed call.
//! - [`asset`] — network and token reference data.
//! - [`rpc::Transport`] — the network seam. It models I/O and performs none,
//!   because endpoint selection and retry policy are the host's.
//! - [`tx`] — the structural protobuf reader and the Tron verification half:
//!   Tron has the node build the transaction, so a client that signs blind
//!   authorises whatever a compromised endpoint returned.
//!
//! The name leaves room for other payment rails beside it. Anything that is
//! neutral about the rail (quotes, ledgers, protocol envelopes) is deliberately
//! kept out of this crate.
//!
//! It links no `bitcoin`, `k256` or `coins-*` crate; CI asserts that.
//!
//! # Feature flags
//!
//! | Feature | Gates |
//! | --- | --- |
//! | `btc` | Bitcoin addresses |
//! | `evm` | EVM addresses |
//! | `solana` | Solana addresses |
//! | `tron` | Tron addresses, and the Tron parts of [`tx`] |
//! | `keccak` | EIP-55 checksums for EVM addresses |
//! | `net` | the [`rpc::Transport`] seam |
//! | `asset` | network and token reference data |
//! | `tx-codec` | the [`tx`] module: protobuf reader and Tron verification |
//! | `serde` | serde derives on [`Chain`] and [`TronTransfer`] |

pub mod address;
#[cfg(feature = "asset")]
pub mod asset;
pub mod chain;
mod error;
#[cfg(feature = "net")]
pub mod rpc;
pub mod transfer;
#[cfg(feature = "tx-codec")]
pub mod tx;

pub use chain::Chain;
pub use error::{Error, Result};
pub use transfer::TronTransfer;
