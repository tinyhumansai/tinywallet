//! The x402 machine-payment protocol for `TinyWallet`.
//!
//! This crate owns the parts of x402 that are the same for every host:
//!
//! - [`wire`] — the v2 header payloads and the rules for reading them.
//! - [`eip712`] — EIP-712 typed-data hashing and the EIP-3009 authorization
//!   x402 signs. Nothing here signs; it returns the bytes to sign.
//! - [`abi`] — ERC-20 `transfer` calldata.
//! - [`ledger`] — the append-only spending ledger and its budgets.
//! - [`thread`] — the [`ThreadScope`](thread::ThreadScope) seam that tells
//!   the ledger which thread a payment belongs to.
//! - [`protocol`] — reading a 402 challenge, the client that pays and retries,
//!   and the [`ProxyPolicy`](protocol::ProxyPolicy) seam.
//! - [`crypto`] — building the on-chain payment (EVM EIP-3009, Solana SPL)
//!   behind the [`PaymentSigner`](crypto::PaymentSigner) seam.
//! - [`tools`] — the `x402_request` agent tool.
//!
//! It depends on `tinywallet-crypto` and never on `tinywallet-bus`, so the bus
//! can re-export from here without a cycle.
//!
//! # Rail-neutral versus crypto-specific
//!
//! [`ledger`] and [`protocol`] say nothing about *how* a payment is made: a
//! [`PaymentBuilder`](protocol::PaymentBuilder) turns a challenge into a proof,
//! and the crypto rail is one implementation of it. [`crypto`] is the only
//! module that knows about chains, keys and signatures. A later card rail can
//! reuse the neutral half by implementing the same builder.
//!
//! # Keys never enter this crate
//!
//! Signing goes through [`PaymentSigner`](crypto::PaymentSigner). The host holds
//! the mnemonic (or the module that does); this crate only ever sees an account
//! address and finished signatures.
//!
//! # Feature flags
//!
//! | Feature | Default | Gates |
//! | --- | --- | --- |
//! | `wire` | on | the x402 header payload types ([`wire`]) |
//! | `eip712` | off | EIP-712 hashing ([`eip712`]) |
//! | `abi` | off | ERC-20 `transfer` calldata ([`abi`]) |
//! | `ledger` | off | the spending ledger ([`ledger`]) and the thread seam ([`thread`]) |
//! | `pay` | off | the 402 client and the payment builders ([`protocol`], [`crypto`]) |
//! | `tools` | off | the `x402_request` tool ([`tools`]) |

#[cfg(feature = "abi")]
pub mod abi;
#[cfg(feature = "pay")]
pub mod crypto;
#[cfg(feature = "eip712")]
pub mod eip712;
#[cfg(feature = "tools")]
pub mod error;
#[cfg(feature = "ledger")]
pub mod ledger;
#[cfg(feature = "pay")]
pub mod protocol;
#[cfg(feature = "ledger")]
pub mod thread;
#[cfg(feature = "tools")]
pub mod tools;
#[cfg(feature = "wire")]
pub mod wire;

#[cfg(feature = "tools")]
pub use error::{Error, Result};

#[cfg(all(test, feature = "pay"))]
mod test_support;
