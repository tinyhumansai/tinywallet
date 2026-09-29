//! The wallet engine and its vocabulary.
//!
//! [`WalletEngine`] is the instance-owned state of the wallet flows: the
//! transport, the seams a host implements, and the prepared-transfer quote
//! store. Its operations are spread over [`crate::crypto::execution`]; the
//! per-chain work is in [`crate::crypto::chains`].

mod engine;
mod types;

pub(crate) use engine::transport_message;
pub use engine::{WalletEngine, WalletSeams};
pub use types::{WalletAccount, WalletChain, WalletSetupSource, WalletStatus};

#[cfg(test)]
mod test;
