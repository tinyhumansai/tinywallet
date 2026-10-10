//! Deterministic key derivation from a BIP-39 mnemonic.
//!
//! [`derive()`] turns a mnemonic and a derivation path into the signing key and
//! address for one chain. It is a pure function: same inputs, same key, every
//! time, with no I/O and no global state.
//!
//! ## This crate derives keys; it does not keep them
//!
//! Nothing here reads or writes a keychain, a file, or an environment
//! variable, and no key is cached between calls. Custody is deliberately the
//! host's problem: where the mnemonic is sealed, what unlocks it, whether the
//! user is prompted, and how long a decrypted phrase may live in memory are
//! all policy decisions that depend on the host's threat model, and a library
//! that quietly picked an answer would be picking it for every host.
//!
//! The consequence for a caller is that the mnemonic arrives as a `&str` the
//! host already decrypted, and this crate's job is to touch it briefly and
//! forget it.
//!
//! ## Two derivation algorithms, not one
//!
//! | Chain | Curve | Scheme |
//! | --- | --- | --- |
//! | Bitcoin | secp256k1 | BIP-32 |
//! | EVM | secp256k1 | BIP-32 |
//! | Tron | secp256k1 | BIP-32 |
//! | Solana | ed25519 | SLIP-0010, hardened-only |
//!
//! The split is forced by the curve. BIP-32's non-hardened derivation needs
//! public-key addition, which ed25519 does not offer, so SLIP-0010 defines
//! hardened-only derivation for it. That is why [`Error::UnhardenedSolanaPath`]
//! exists: a path like `m/44'/501'/0'/0` is not merely unsupported here, it is
//! underivable, and accepting it by silently hardening the last segment would
//! hand back a *different account* than the path names.

use zeroize::Zeroizing;

use crate::chain::Chain;

mod bip32;
mod slip10;

#[cfg(feature = "btc")]
mod btc;
#[cfg(feature = "evm")]
mod evm;
#[cfg(feature = "solana")]
mod solana;
#[cfg(feature = "tron")]
mod tron;

/// Errors raised while deriving a key.
///
/// Every variant names the failing *step*. None carries key material, a seed,
/// or any part of a mnemonic — an error string is the single easiest way for a
/// secret to escape into a log, so nothing secret is ever put in one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The mnemonic is not a valid BIP-39 phrase — wrong word count, a word
    /// outside the wordlist, or a failed checksum.
    ///
    /// Deliberately carries no detail beyond this. The underlying error can
    /// quote the offending word, which is one twelfth of a seed phrase.
    #[error("invalid BIP-39 mnemonic")]
    InvalidMnemonic,

    /// A public SEC1 encoding does not represent a secp256k1 point.
    #[error("invalid SEC1 public key")]
    InvalidPublicKey,

    /// The derivation path is not well-formed.
    #[error("invalid derivation path '{path}': {reason}")]
    InvalidPath {
        /// The rejected path. A path is not secret — it is public metadata
        /// about which account was meant.
        path: String,
        /// Why it was rejected.
        reason: String,
    },

    /// A Solana path contains a non-hardened segment.
    ///
    /// Separate from [`Error::InvalidPath`] because it is not a typo: the path
    /// is syntactically fine and simply cannot be derived on ed25519. See the
    /// module docs — silently hardening it would return a different account
    /// than the caller asked for.
    #[error(
        "Solana path '{path}' has a non-hardened segment; ed25519 (SLIP-0010) \
         supports hardened derivation only, so every segment needs a trailing '"
    )]
    UnhardenedSolanaPath {
        /// The rejected path.
        path: String,
    },

    /// Key derivation failed arithmetically.
    ///
    /// Essentially unreachable in practice: BIP-32 specifies retrying with the
    /// next index when a derived scalar falls outside the curve order, and the
    /// odds of hitting that are negligible. It is a variant rather than a panic
    /// because a wallet must not abort the process over it.
    #[error("key derivation failed at {step}")]
    Derivation {
        /// Which step failed.
        step: &'static str,
    },

    /// The chain's feature gate was disabled when this crate was built.
    ///
    /// A build fact, not a property of the inputs — the same reasoning as
    /// [`crate::Error::ChainNotCompiled`].
    #[error(
        "tinywallet was built without support for {chain}; \
         enable the '{chain}' feature to derive its keys"
    )]
    ChainNotCompiled {
        /// The chain whose gate is disabled.
        chain: Chain,
    },
}

/// Result alias for key derivation.
pub type Result<T> = std::result::Result<T, Error>;

/// A derived signing key and the address it controls.
///
/// The secret is held in [`Zeroizing`], so dropping this wipes it rather than
/// leaving it in freed memory for whatever allocates there next.
///
/// `Debug` is implemented by hand and prints only the chain and address.
/// Deriving it would put raw key material into every `{:?}`, every
/// `unwrap()` panic message, and every log line that formats a struct
/// containing one — which is exactly how a private key ends up in a bug
/// report.
pub struct DerivedKey {
    chain: Chain,
    address: String,
    secret: Zeroizing<Vec<u8>>,
}

impl DerivedKey {
    /// Build a derived key. Internal: the per-chain modules construct these.
    fn new(chain: Chain, address: String, secret: Vec<u8>) -> Self {
        Self {
            chain,
            address,
            secret: Zeroizing::new(secret),
        }
    }

    /// The chain this key is for.
    #[must_use]
    pub const fn chain(&self) -> Chain {
        self.chain
    }

    /// The address this key controls, in the chain's canonical text form.
    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    /// The raw secret key bytes.
    ///
    /// 32 bytes on every supported chain. Treat the returned slice as live key
    /// material: do not copy it into a `String`, a log, or an error. It is
    /// borrowed rather than returned by value so it cannot outlive the
    /// zeroizing owner.
    #[must_use]
    pub fn secret_bytes(&self) -> &[u8] {
        &self.secret
    }
}

impl std::fmt::Debug for DerivedKey {
    /// Prints the chain and address only. See the type docs: a derived `Debug`
    /// here would leak key material into panic messages and logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DerivedKey")
            .field("chain", &self.chain)
            .field("address", &self.address)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Derive the signing key and address for `chain` from `mnemonic` at `path`.
///
/// `mnemonic` is a BIP-39 phrase the host has already decrypted; it is used
/// for the duration of the call and not retained. `path` is a BIP-32 style
/// derivation path (`m/44'/60'/0'/0/0`).
///
/// # Errors
///
/// - [`Error::InvalidMnemonic`] if the phrase is not valid BIP-39.
/// - [`Error::InvalidPath`] if the path is malformed.
/// - [`Error::UnhardenedSolanaPath`] for a Solana path with a non-hardened
///   segment — see the module docs for why that is its own variant.
/// - [`Error::ChainNotCompiled`] if `chain`'s feature gate is off.
///
/// # Examples
///
/// ```
/// # #[cfg(feature = "evm")] {
/// use tinywallet::{key, Chain};
///
/// // The BIP-39 test vector mnemonic. Never use it for real funds.
/// let phrase = "abandon abandon abandon abandon abandon abandon \
///               abandon abandon abandon abandon abandon about";
/// let derived = key::derive(Chain::Evm, phrase, "m/44'/60'/0'/0/0")?;
///
/// assert_eq!(derived.address(), "0x9858EfFD232B4033E47d90003D41EC34EcaEda94");
/// // Debug never prints the secret.
/// assert!(format!("{derived:?}").contains("<redacted>"));
/// # }
/// # Ok::<(), tinywallet::key::Error>(())
/// ```
pub fn derive(chain: Chain, mnemonic: &str, path: &str) -> Result<DerivedKey> {
    match chain {
        #[cfg(feature = "btc")]
        Chain::Btc => btc::derive(mnemonic, path),
        #[cfg(feature = "evm")]
        Chain::Evm => evm::derive(mnemonic, path),
        #[cfg(feature = "solana")]
        Chain::Solana => solana::derive(mnemonic, path),
        #[cfg(feature = "tron")]
        Chain::Tron => tron::derive(mnemonic, path),
        #[allow(unreachable_patterns)]
        other => Err(Error::ChainNotCompiled { chain: other }),
    }
}

/// Turn a BIP-39 phrase into its 64-byte seed.
///
/// Shared by every chain: the seed is scheme-independent, and only what
/// happens after it differs. The result zeroizes on drop.
fn seed_from_mnemonic(mnemonic: &str) -> Result<Zeroizing<Vec<u8>>> {
    use coins_bip39::{English, Mnemonic};

    // The error is discarded on purpose: `coins_bip39` reports which word
    // failed the wordlist check, and a word is one twelfth of a seed phrase.
    let parsed: Mnemonic<English> = mnemonic
        .trim()
        .parse()
        .map_err(|_| Error::InvalidMnemonic)?;
    let seed = parsed.to_seed(None).map_err(|_| Error::InvalidMnemonic)?;
    Ok(Zeroizing::new(seed.to_vec()))
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;

#[cfg(feature = "evm")]
pub use evm::address_from_public_key as evm_address_from_public_key;
