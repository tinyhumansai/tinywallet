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
//!
//! # Where half of this crate lives
//!
//! The wire contract, the address rules, the ABI and EIP-712 encoders, the
//! reference data, the [`rpc::Transport`] seam and the transaction *verification*
//! codec are [`tinywallet_crypto`]'s (the wire contract is [`tinywallet_bus`]'s, and
//! the ABI, EIP-712 and x402 types are [`tinywallet_x402`]'s), and are re-exported below so every
//! `tinywallet::…` path still resolves. What stays here is what needs a key or a
//! chain library: derivation ([`key`]), building and signing ([`tx`]), the chain
//! queries ([`client`]) and the x402 payment types ([`x402`]).
//!
//! The split exists so a host that has moved signing into the `tinywallet`
//! `TinyBus` module can depend on `tinywallet-bus` (or `tinywallet-crypto`) alone and link no `bitcoin`
//! crate, no native `secp256k1` build, and no BIP-39 implementation — while
//! still validating an address before it sends a spec and verifying what a Tron
//! node handed back before it signs.

#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "key")]
pub mod key;
#[cfg(feature = "tx-codec")]
pub mod tx;
#[cfg(feature = "x402")]
pub mod x402;

// Re-exported rather than re-declared: the sibling crates own these modules, and
// pointing this crate's paths at them keeps one definition of every type that
// crosses the bus. A second copy here would make the host's `wire::Signature` a
// different type from the module's, which is exactly the failure the split was
// made to prevent.
#[cfg(feature = "wire")]
pub use tinywallet_bus::wire;
#[cfg(feature = "asset")]
pub use tinywallet_crypto::asset;
#[cfg(feature = "net")]
pub use tinywallet_crypto::rpc;
pub use tinywallet_crypto::{Chain, Error, Result, address, chain};
#[cfg(feature = "abi")]
pub use tinywallet_x402::abi;
#[cfg(feature = "eip712")]
pub use tinywallet_x402::eip712;
