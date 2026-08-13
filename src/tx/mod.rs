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
//! well-formed transaction that moves the wrong funds, or one that is valid on
//! a chain the user did not intend.

#[cfg(all(feature = "tx", feature = "btc"))]
pub mod btc;
#[cfg(feature = "tx")]
pub mod evm;
#[cfg(feature = "tron")]
pub mod proto;
#[cfg(feature = "tx")]
mod rlp;
#[cfg(all(feature = "tx", feature = "solana"))]
pub mod solana;
#[cfg(feature = "tron")]
pub mod tron;

#[cfg(test)]
mod test;

/// Errors raised while building or signing a transaction.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// An address in the transaction was rejected.
    #[error(transparent)]
    Address(crate::Error),

    /// A field was structurally invalid.
    #[error("invalid transaction field '{field}': {reason}")]
    InvalidField {
        /// Which field.
        field: &'static str,
        /// Why it was rejected.
        reason: String,
    },

    /// The available UTXOs cannot cover the amount plus the fee.
    ///
    /// Its own variant because it is the one failure a caller can act on -
    /// by lowering the amount, lowering the fee, or waiting for a deposit -
    /// rather than merely report.
    #[error("insufficient funds: have {available}, need {required}")]
    InsufficientFunds {
        /// Total value of the available UTXOs, in satoshis.
        available: u64,
        /// Amount plus fee, in satoshis.
        required: u64,
    },

    /// A node returned something that does not match what was requested.
    ///
    /// Raised where a chain has the node build the transaction (Tron), so the
    /// client must check the result before signing it. Signing blind would let
    /// a compromised endpoint have its own transfer authorised.
    #[error("untrusted node response: {reason}")]
    UntrustedResponse {
        /// What did not match.
        reason: String,
    },

    /// Signing failed.
    ///
    /// Carries no key material — see [`crate::key`] for why an error string is
    /// the easiest way for a secret to escape.
    #[error("signing failed: {reason}")]
    Signing {
        /// What went wrong, never including key material.
        reason: String,
    },
}

/// Result alias for transaction building and signing.
pub type Result<T> = std::result::Result<T, Error>;
