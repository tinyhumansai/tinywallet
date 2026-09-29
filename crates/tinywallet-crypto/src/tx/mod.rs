//! Reading and checking transaction bytes.
//!
//! This is the half of transaction handling that needs no key and no chain
//! library: the structural protobuf reader in [`proto`] and the verification
//! entry points in [`tron`]. Building and signing live in the root
//! `tinywallet` crate behind its `tx` gate, which is what pulls `bitcoin` and
//! its native `secp256k1` build.
//!
//! [`Error`] is defined here rather than there because both halves raise it and
//! a host that only verifies still has to match on it. Some variants —
//! [`Error::InsufficientFunds`], [`Error::Signing`] — are only ever produced by
//! the building half; they stay in one enum so a caller does not have to
//! translate between two vocabularies for the same operation.

#[cfg(feature = "tron")]
pub mod proto;
#[cfg(feature = "tron")]
pub mod tron;

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
    /// Carries no key material — see `tinywallet::key` for why an error string is
    /// the easiest way for a secret to escape.
    #[error("signing failed: {reason}")]
    Signing {
        /// What went wrong, never including key material.
        reason: String,
    },
}

/// Result alias for transaction building and signing.
pub type Result<T> = std::result::Result<T, Error>;
