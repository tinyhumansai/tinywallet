//! Transaction building and signing.
//!
//! Pure: a transaction is built and signed from its fields and a key, with no
//! network involved. Fetching a nonce or a gas price and broadcasting the
//! result are [`crate::client`]'s job, over the host's
//! [`Transport`](crate::rpc::Transport).
//!
//! Splitting it this way is what makes signing testable. A signed transaction
//! is a deterministic function of its inputs, so it can be pinned against a
//! published vector byte-for-byte — which matters more here than anywhere else
//! in the crate, because a signing bug does not fail loudly. It produces a
//! well-formed, perfectly signed transaction that moves the wrong funds, or one
//! that is valid on a chain the user did not intend.
//!
//! # Where the other half lives
//!
//! [`Error`], [`proto`] and the verification entry points in [`tron`] are
//! [`tinywallet_crypto::tx`]'s and are re-exported here, so every
//! `tinywallet::tx::…` path still resolves. They are over there because a host
//! that has moved signing into a loadable module still has to check what a node
//! handed back before it signs, and doing that must not cost it `bitcoin` and a
//! native C build.

#[cfg(all(feature = "tx", feature = "btc"))]
pub mod btc;
#[cfg(feature = "tx")]
pub mod evm;
#[cfg(feature = "tx")]
mod rlp;
#[cfg(all(feature = "tx", feature = "solana"))]
pub mod solana;
#[cfg(feature = "tron")]
pub mod tron;

#[cfg(feature = "tron")]
pub use tinywallet_crypto::tx::proto;
pub use tinywallet_crypto::tx::{Error, Result};

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
