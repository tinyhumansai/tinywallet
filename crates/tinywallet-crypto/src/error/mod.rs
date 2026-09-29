//! Crate-wide error and result types.
//!
//! Every fallible public function in this crate returns [`Result`], and every
//! failure mode is a distinct [`Error`] variant. Add a variant rather than
//! encoding new context into an existing message: callers match on variants,
//! and message text is not a stable API.
//!
//! Errors carry the offending input verbatim. That is a deliberate choice for
//! this crate: an address is public data, and a caller diagnosing a rejected
//! address needs to see exactly what was rejected — a truncated or elided
//! address turns a one-line fix into a debugging session. **Nothing in this
//! crate ever puts a secret in an error**; key-material failures report the
//! failing step, never the material.

use crate::chain::Chain;

/// Errors returned by this crate.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An address was empty or contained only whitespace.
    #[error("{chain} address is empty")]
    EmptyAddress {
        /// The chain the address was being validated for.
        chain: Chain,
    },

    /// An address was not well-formed for its chain.
    ///
    /// Covers every syntactic rejection: a bad base58 checksum, a wrong
    /// length, a non-hex character, an invalid bech32 payload.
    #[error("invalid {chain} address '{address}': {reason}")]
    InvalidAddress {
        /// The chain the address was being validated for.
        chain: Chain,
        /// The rejected address, verbatim.
        address: String,
        /// Why it was rejected.
        reason: String,
    },

    /// An address was well-formed but belongs to the wrong network — a
    /// testnet or regtest address where a mainnet one is required.
    ///
    /// Separate from [`Error::InvalidAddress`] because it is the one failure a
    /// caller is likely to *handle* rather than merely report: it means the
    /// user is pointed at the wrong network, not that they typo'd.
    #[error("{chain} address '{address}' is not on {expected}: {reason}")]
    WrongNetwork {
        /// The chain the address was being validated for.
        chain: Chain,
        /// The rejected address, verbatim.
        address: String,
        /// The network that was required.
        expected: String,
        /// Detail from the underlying parser.
        reason: String,
    },

    /// An address is well-formed but its type is not supported for the
    /// requested role.
    ///
    /// Raised by `address::btc::validate_sender`: signing is only
    /// implemented for P2WPKH, so a P2TR or P2SH address is a perfectly valid
    /// *recipient* and an unusable *sender*.
    #[error("{chain} address '{address}' is not supported as a sender: {reason}")]
    UnsupportedAddressType {
        /// The chain the address was being validated for.
        chain: Chain,
        /// The rejected address, verbatim.
        address: String,
        /// Which address types are supported instead.
        reason: String,
    },

    /// The chain's feature gate was disabled when this crate was built.
    ///
    /// Only [`crate::address::validate`] can return this, and only for a chain
    /// whose gate is off. It is a *build* fact, not a property of the input:
    /// the validation code was not compiled, so there is no answer to give.
    /// Reporting it as an error rather than silently accepting or rejecting
    /// the address is the point — either of those would be a wrong answer
    /// dressed up as a real one.
    #[error(
        "tinywallet was built without support for {chain}; \
         enable the '{chain}' feature to validate its addresses"
    )]
    ChainNotCompiled {
        /// The chain whose feature gate is disabled.
        chain: Chain,
    },
}

/// The crate's standard result type.
///
/// Use this alias in public signatures instead of spelling out
/// `std::result::Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test;
