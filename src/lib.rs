//! Agent-friendly multi-chain wallet primitives in Rust.
//!
//! `tinywallet` owns the parts of wallet handling that are pure: address
//! formats, their validation, and the conversions between their encodings.
//! Bitcoin, EVM chains, Solana, and Tron each get a module, and
//! [`address::validate`] dispatches across them for chain-generic callers.
//!
//! # What this crate deliberately does not do
//!
//! No network access, no RPC endpoints, no key storage, no transaction
//! broadcasting. Every function here is a deterministic pure function of its
//! arguments.
//!
//! That is the seam, not a gap. Endpoint selection, retry policy, and key
//! custody are things a host must own — they depend on its config, its threat
//! model, and its runtime — and a crate that guessed at any of them would be
//! wrong for every host that guessed differently. What is left is the part
//! that is genuinely the same everywhere, which is exactly what belongs in a
//! shared crate.
//!
//! # Example
//!
//! ```
//! # #[cfg(all(feature = "btc", feature = "tron"))] {
//! use tinywallet::{address, chain::Chain};
//!
//! // Chain-generic dispatch.
//! let addr = address::validate(Chain::Btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;
//!
//! // Or reach for a chain's own module when you need more than validation.
//! let hex = address::tron::to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")?;
//! assert!(hex.starts_with("41"));
//! # }
//! # Ok::<(), tinywallet::Error>(())
//! ```
//!
//! # Feature flags
//!
//! Every chain is a separate default-on gate, so a host that only needs one
//! chain does not pay for the others' parsers.
//!
//! | Feature | Default | Gates |
//! | --- | --- | --- |
//! | `btc` | on | Bitcoin addresses (pulls `bitcoin`) |
//! | `evm` | on | EVM addresses (no dependencies) |
//! | `solana` | on | Solana addresses (pulls `bs58`) |
//! | `tron` | on | Tron addresses (pulls `bs58`, `hex`) |
//! | `keccak` | on | EIP-55 checksums for EVM (pulls `sha3`) |
//! | `net` | on | the `rpc::Transport` network seam (pulls `async-trait`) |
//! | `key` | on | BIP-39/BIP-32/SLIP-0010 key derivation (`tinywallet::key`) |
//! | `asset` | on | network and token reference data (`tinywallet::asset`) |
//! | `client` | on | chain queries over the seam (`tinywallet::client`) |
//! | `tx` | on | transaction building and signing (`tinywallet::tx`) |
//! | `x402` | on | x402 machine-payment wire types (`tinywallet::x402`) |

mod error;

#[cfg(feature = "abi")]
pub mod abi;
pub mod address;
#[cfg(feature = "asset")]
pub mod asset;
pub mod chain;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "eip712")]
pub mod eip712;
#[cfg(feature = "key")]
pub mod key;
#[cfg(feature = "net")]
pub mod rpc;
#[cfg(feature = "tx-codec")]
pub mod tx;
#[cfg(feature = "wire")]
pub mod wire;
#[cfg(feature = "x402")]
pub mod x402;

pub use chain::Chain;
pub use error::{Error, Result};
