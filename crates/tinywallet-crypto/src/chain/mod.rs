//! The set of chains this crate understands.
//!
//! [`Chain`] exists so errors can name the chain they came from without every
//! variant carrying a stringly-typed label, and so a host can drive
//! chain-generic code — a dispatch table, a UI picker — off one enum rather
//! than its own parallel copy.
//!
//! It is deliberately **not** feature-gated. A host compiled with only the
//! `solana` gate should still be able to name and match on `Chain::Btc`
//! (in a config file it round-trips, say) without that failing to compile;
//! only the *validation functions* disappear with their gates.

use std::fmt;
use std::str::FromStr;

/// A blockchain this crate has address support for.
///
/// Serde support is conditional so the enum stays dependency-free in builds
/// that do not need it. The representation is the lowercase variant name
/// (`"btc"`, `"evm"`, …), matching [`FromStr`] and [`fmt::Display`] below, so a
/// value written by one and read by the other agrees — this type crosses a
/// host/backend boundary in [`crate::wire`], where a mismatch between the text
/// and JSON forms would be a runtime deserialization failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Chain {
    /// Bitcoin (mainnet).
    Btc,
    /// An EVM chain — Ethereum and every address-compatible network.
    ///
    /// One variant covers all of them because the address format is identical
    /// across EVM chains; nothing about validating an address distinguishes
    /// Ethereum from Polygon or Base.
    Evm,
    /// Solana (mainnet-beta).
    Solana,
    /// Tron (mainnet).
    Tron,
}

impl Chain {
    /// Every chain this crate knows, in declaration order.
    ///
    /// Useful for a host enumerating supported chains. This is the full set
    /// regardless of which feature gates are enabled — see the module docs.
    pub const ALL: &'static [Self] = &[Self::Btc, Self::Evm, Self::Solana, Self::Tron];

    /// The chain's lowercase machine-readable name (`"btc"`, `"evm"`,
    /// `"solana"`, `"tron"`).
    ///
    /// This is the form [`Chain::from_str`] parses, so `chain.as_str()` always
    /// round-trips.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Btc => "btc",
            Self::Evm => "evm",
            Self::Solana => "solana",
            Self::Tron => "tron",
        }
    }
}

impl fmt::Display for Chain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Returned by [`Chain::from_str`] when the input names no known chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown chain '{0}'")]
pub struct UnknownChain(pub String);

impl FromStr for Chain {
    type Err = UnknownChain;

    /// Parse a chain from its machine-readable name, case-insensitively.
    ///
    /// `"ethereum"` and `"eth"` are accepted as aliases for [`Chain::Evm`],
    /// and `"bitcoin"` for [`Chain::Btc`], because those are the spellings
    /// that show up in user-facing config.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownChain`] if `s` names no known chain.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "btc" | "bitcoin" => Ok(Self::Btc),
            "evm" | "eth" | "ethereum" => Ok(Self::Evm),
            "solana" | "sol" => Ok(Self::Solana),
            "tron" | "trx" => Ok(Self::Tron),
            other => Err(UnknownChain(other.to_string())),
        }
    }
}

#[cfg(test)]
mod test;
