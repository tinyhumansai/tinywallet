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
//! # Where the chain rules went
//!
//! This crate used to hold the pure rules a host runs itself. They now live in
//! two focused crates, and the paths below are **compat re-exports that are
//! removed in the next minor release**; depend on the new crates directly:
//!
//! | Old path | Now in |
//! | --- | --- |
//! | `address`, `asset`, `chain`, `rpc`, `tx`, [`Chain`], [`Error`], [`Result`] | `tinywallet-crypto` |
//! | `eip712`, `abi` | `tinywallet-x402` (features `eip712`, `abi`) |
//! | `wire::TronTransfer` | `tinywallet-crypto` (`TronTransfer`) |
//!
//! The re-exports never enable more than the bus feature that names them, and
//! `tinywallet-x402` is taken with default features off, so this crate cannot
//! pull in the x402 wire types or anything heavier.
//!
//! # Feature flags
//!
//! Each flag forwards to the crate that owns the module now.
//!
//! | Feature | Gates |
//! | --- | --- |
//! | `btc` | Bitcoin addresses |
//! | `evm` | EVM addresses |
//! | `solana` | Solana addresses |
//! | `tron` | Tron addresses, and `tx` with `tx-codec` |
//! | `keccak` | EIP-55 checksums for EVM addresses |
//! | `net` | the `rpc::Transport` seam |
//! | `asset` | network and token reference data |
//! | `wire` | the host/module wire contract |
//! | `eip712` | EIP-712 typed-data hashing |
//! | `abi` | ERC-20 `transfer` calldata |
//! | `tx-codec` | the Tron protobuf reader and verification half |

pub mod names;
pub mod version;
#[cfg(feature = "wire")]
pub mod wire;

// Compat re-exports, removed in the next minor release. Each is gated exactly as
// the module it replaces was, so a `default-features = false` consumer sees the
// same surface as before.
/// Compat re-export of `tinywallet_crypto::address`, removed in the next minor release.
pub use tinywallet_crypto::address;
/// Compat re-export of `tinywallet_crypto::asset`, removed in the next minor release.
#[cfg(feature = "asset")]
pub use tinywallet_crypto::asset;
/// Compat re-export of `tinywallet_crypto::chain`, removed in the next minor release.
pub use tinywallet_crypto::chain;
/// Compat re-export of `tinywallet_crypto::rpc`, removed in the next minor release.
#[cfg(feature = "net")]
pub use tinywallet_crypto::rpc;
/// Compat re-export of `tinywallet_crypto::tx`, removed in the next minor release.
#[cfg(feature = "tx-codec")]
pub use tinywallet_crypto::tx;
/// Compat re-export of `tinywallet_x402::abi`, removed in the next minor release.
#[cfg(feature = "abi")]
pub use tinywallet_x402::abi;
/// Compat re-export of `tinywallet_x402::eip712`, removed in the next minor release.
#[cfg(feature = "eip712")]
pub use tinywallet_x402::eip712;

pub use names::{BUS_NAME, CONFIDENTIAL_METHODS, METHODS, OBJECT_PATH};
/// Compat re-exports of `tinywallet_crypto::{Chain, Error, Result}`, removed in
/// the next minor release.
pub use tinywallet_crypto::{Chain, Error, Result};
pub use version::{CONTRACT_VERSION, is_compatible};

#[cfg(test)]
#[path = "lib_tests.rs"]
mod test;
