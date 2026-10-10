//! The wire contract that crosses the `TinyBus` boundary for `TinyWallet`: the
//! member names that carry it, the request and response types, and the
//! compatibility rule for that vocabulary.
//!
//! A host loads the `tinywallet-module` dynamic library but cannot import Rust
//! items from that binary. This crate is the ordinary library that supplies its
//! call vocabulary — interface name, object path, member names, request and
//! response types, and the compatibility rule for that vocabulary.
//!
//! It is deliberately transport-free: no `TinyBus`, no runtime, no HTTP client,
//! and above all no chain library. Key custody, derivation, transaction
//! building and signing, and broadcast are the module's, and taking this crate
//! links none of them — no `bitcoin`, no `secp256k1` C build, no `ethers-core`,
//! no BIP-39 implementation.
//!
//! Shared chain identifiers, errors and transfer data live here. Crypto and
//! x402 algorithms remain in their implementation crates and are not re-exported.
//! Implementations re-export this vocabulary for source compatibility.
//!
//! The `serde` feature derives wire serialization; `wire` enables call DTOs.
//! Legacy feature names remain accepted but never enable implementation code.

pub mod names;
pub mod version;
#[cfg(feature = "wire")]
pub mod wire;

pub mod chain;
mod error;
pub mod transfer;
pub use chain::Chain;
pub use error::{Error, Result};
pub use transfer::TronTransfer;

pub use names::{BUS_NAME, CONFIDENTIAL_METHODS, METHODS, OBJECT_PATH};
pub use version::{CONTRACT_VERSION, is_compatible};

#[cfg(test)]
#[path = "lib_tests.rs"]
mod test;
