//! Bitcoin address validation.
//!
//! Two functions, because Bitcoin has two different answers depending on which
//! side of a transaction the address sits on:
//!
//! - [`validate`] — any well-formed mainnet address. Correct for a
//!   **recipient**: we do not care which address type they prefer, because
//!   paying to a P2WPKH, P2TR, P2SH or P2PKH output is the same operation.
//! - [`validate_sender`] — additionally requires **P2WPKH** (`bc1q…` native
//!   segwit). Correct for a **sender**, because that is the only script type
//!   this crate's family of signing paths knows how to spend.
//!
//! Calling [`validate`] where [`validate_sender`] belongs is the dangerous
//! direction: it accepts an address that will fail much later, at signing
//! time, after a transaction has been assembled. The two are separate
//! functions rather than a boolean flag so that mistake reads wrong at the
//! call site.
//!
//! # Why this does not use the `bitcoin` crate
//!
//! It used to. The crate is excellent and this module is a strictly smaller
//! thing than what it offers — but it carries `secp256k1`, and therefore a
//! native C build, into every consumer that only ever wanted to check whether a
//! string is a well-formed address. That cost is invisible in a full wallet and
//! dominant in a host that has moved signing elsewhere.
//!
//! Address *parsing* is a safe thing to own directly, unlike the BIP-32 walk in
//! `tinywallet::key`, which deliberately still delegates. The distinction is
//! failure mode, not difficulty: a parser that is wrong rejects a good address
//! or accepts a malformed one, and both are caught immediately by the vectors
//! below. A derivation that is wrong returns a *valid key for the wrong
//! account* — silently, and unrecoverably. So this module is hand-rolled
//! against the published BIP-173 and BIP-350 vectors, and key derivation is
//! not.
//!
//! The five mainnet forms, in full:
//!
//! | Type | Encoding | Prefix / witness version | Program length |
//! | --- | --- | --- | --- |
//! | P2PKH | base58check | version byte `0x00` | 20 |
//! | P2SH | base58check | version byte `0x05` | 20 |
//! | P2WPKH | bech32 | `bc`, v0 | 20 |
//! | P2WSH | bech32 | `bc`, v0 | 32 |
//! | P2TR | bech32m | `bc`, v1 | 32 |
//!
//! Witness versions 2..=16 are accepted as recipients with a 2..=40 byte
//! program, per BIP-350. Refusing them would make this crate reject addresses
//! that are valid today and spendable by their owners, purely because a future
//! output type had not been invented when it was written.

use crate::chain::Chain;
use crate::{Error, Result};

/// Human-readable part of a Bitcoin **mainnet** bech32 address.
const MAINNET_HRP: &str = "bc";

/// Base58check version byte for P2PKH.
const P2PKH_VERSION: u8 = 0x00;

/// Base58check version byte for P2SH.
const P2SH_VERSION: u8 = 0x05;

/// Base58check version bytes belonging to Bitcoin test networks.
const TEST_VERSIONS: [u8; 2] = [0x6f, 0xc4];

/// What a well-formed mainnet address turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Pay to public key hash — legacy, base58.
    P2pkh,
    /// Pay to script hash — base58.
    P2sh,
    /// Pay to witness public key hash — the only spendable-from type here.
    P2wpkh,
    /// Pay to witness script hash.
    P2wsh,
    /// A segwit output that is none of the above: taproot, or a future version.
    OtherWitness,
}

/// Validate a Bitcoin **mainnet** address of any type, returning it trimmed.
///
/// Use this for transaction recipients.
///
/// # Errors
///
/// - [`Error::EmptyAddress`] if `address` is empty or all whitespace.
/// - [`Error::InvalidAddress`] if it does not parse as a Bitcoin address.
/// - [`Error::WrongNetwork`] if it parses but belongs to testnet, signet, or
///   regtest.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::btc;
///
/// // Native segwit, wrapped segwit, legacy, and taproot are all accepted.
/// assert!(btc::validate("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_ok());
/// assert!(btc::validate("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_ok());
///
/// // A testnet address is well-formed but on the wrong network.
/// assert!(btc::validate("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").is_err());
/// ```
pub fn validate(address: &str) -> Result<String> {
    let trimmed = trimmed_non_empty(address)?;
    parse(trimmed)?;
    Ok(trimmed.to_string())
}

/// Validate a Bitcoin address usable as a **sender**, returning it trimmed.
///
/// Everything [`validate`] requires, plus the address must be P2WPKH — native
/// segwit, the `bc1q…` form. Signing is only implemented for that script type,
/// so any other type would fail later with a much less obvious error.
///
/// # Errors
///
/// - Everything [`validate`] returns.
/// - [`Error::UnsupportedAddressType`] if the address is well-formed mainnet
///   but not P2WPKH.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::address::btc;
///
/// // Native segwit: usable as a sender.
/// assert!(btc::validate_sender("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").is_ok());
///
/// // A legacy address is a fine recipient but cannot be signed for here.
/// assert!(btc::validate("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_ok());
/// assert!(btc::validate_sender("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2").is_err());
/// ```
pub fn validate_sender(address: &str) -> Result<String> {
    let trimmed = trimmed_non_empty(address)?;
    // Deliberately ordered: a malformed or wrong-network address is reported as
    // such, never as an unsupported *type*, which would point at the wrong fix.
    if parse(trimmed)? != Kind::P2wpkh {
        return Err(Error::UnsupportedAddressType {
            chain: Chain::Btc,
            address: trimmed.to_string(),
            reason: "only P2WPKH (bc1q… native segwit) can be signed for".to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Encode a 20-byte public key hash as a mainnet P2WPKH (`bc1q…`) address.
///
/// The counterpart to parsing: `tinywallet_bus::key` derives a public key and needs
/// its address, and doing that here keeps the bech32 encoding in the module
/// that also decodes it. Public rather than crate-private because that caller
/// is in the root crate now, on the far side of the contract split.
///
/// # Errors
///
/// [`Error::InvalidAddress`] only if bech32 encoding fails, which for a
/// fixed-length v0 program and a constant HRP it cannot.
pub fn encode_p2wpkh(pubkey_hash: &[u8; 20]) -> Result<String> {
    // `hrp::BC` rather than parsing `MAINNET_HRP`: the parse could not fail for
    // a two-letter constant, and an error arm that cannot fire is one nothing
    // can test.
    bech32::segwit::encode_v0(bech32::hrp::BC, pubkey_hash).map_err(|e| Error::InvalidAddress {
        chain: Chain::Btc,
        address: String::new(),
        reason: e.to_string(),
    })
}

/// Trim `address` and reject it if nothing is left.
fn trimmed_non_empty(address: &str) -> Result<&str> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(Error::EmptyAddress { chain: Chain::Btc });
    }
    Ok(trimmed)
}

/// Identify a mainnet address, or say why it is not one.
///
/// Dispatch is on *shape*, not on a list of known prefixes. A bech32 string is
/// an all-letter human-readable part, a `1` separator, then a data part drawn
/// from an alphabet that excludes `1` — so the last `1` is the separator, and
/// what precedes it is the HRP.
///
/// Routing every bech32-shaped string to [`parse_bech32`], rather than only
/// those starting `bc1`, is what lets a testnet or foreign-chain address be
/// reported as the wrong network instead of as malformed base58. Matching on a
/// hardcoded prefix list left that check unreachable and gave a Litecoin
/// address a base58 error message.
fn parse(address: &str) -> Result<Kind> {
    let lower = address.to_ascii_lowercase();
    if let Some(separator) = lower.rfind('1') {
        let hrp = &lower[..separator];
        if !hrp.is_empty() && hrp.chars().all(|c| c.is_ascii_lowercase()) {
            return parse_bech32(address);
        }
    }
    parse_base58(address)
}

/// Decode a bech32 or bech32m segwit address.
///
/// One call does the whole job: `bech32::segwit::decode` rejects a witness
/// version above 16, selects the checksum algorithm the version requires
/// (bech32 for v0, bech32m for v1+, per BIP-350), rejects mixed case, and
/// enforces the program-length rules — 20 or 32 bytes at v0, 2..=40 above it.
/// Re-checking any of that here would be a second, drifting implementation of
/// rules the crate already owns.
fn parse_bech32(address: &str) -> Result<Kind> {
    let (hrp, version, program) =
        bech32::segwit::decode(address).map_err(|e| Error::InvalidAddress {
            chain: Chain::Btc,
            address: address.to_string(),
            reason: e.to_string(),
        })?;

    if hrp.as_str() != MAINNET_HRP {
        return Err(wrong_network(address, "a non-mainnet human-readable part"));
    }

    // Only v0 needs discriminating, because only P2WPKH is spendable here.
    // Taproot and every future version are payable recipients and nothing more,
    // so they share one arm rather than each earning a variant that no caller
    // would branch on.
    if version.to_u8() != 0 {
        return Ok(Kind::OtherWitness);
    }
    match program.len() {
        20 => Ok(Kind::P2wpkh),
        // Guaranteed 32 by the length validation above; spelled out rather than
        // wildcarded so a future relaxation upstream cannot silently land here
        // as "P2WSH".
        32 => Ok(Kind::P2wsh),
        other => Err(Error::InvalidAddress {
            chain: Chain::Btc,
            address: address.to_string(),
            reason: format!("witness v0 program must be 20 or 32 bytes, got {other}"),
        }),
    }
}

/// Decode a base58check P2PKH or P2SH address.
fn parse_base58(address: &str) -> Result<Kind> {
    let decoded = bs58::decode(address)
        .with_check(None)
        .into_vec()
        .map_err(|e| Error::InvalidAddress {
            chain: Chain::Btc,
            address: address.to_string(),
            reason: e.to_string(),
        })?;

    // base58check strips the 4-byte checksum, leaving version || payload.
    let (version, payload) = decoded.split_first().ok_or_else(|| Error::InvalidAddress {
        chain: Chain::Btc,
        address: address.to_string(),
        reason: "empty base58check payload".to_string(),
    })?;

    if TEST_VERSIONS.contains(version) {
        return Err(wrong_network(address, "a test network version byte"));
    }
    if payload.len() != 20 {
        return Err(Error::InvalidAddress {
            chain: Chain::Btc,
            address: address.to_string(),
            reason: format!("hash must be 20 bytes, got {}", payload.len()),
        });
    }
    match *version {
        P2PKH_VERSION => Ok(Kind::P2pkh),
        P2SH_VERSION => Ok(Kind::P2sh),
        other => Err(Error::InvalidAddress {
            chain: Chain::Btc,
            address: address.to_string(),
            reason: format!("unknown base58check version byte {other:#04x}"),
        }),
    }
}

/// A well-formed address that belongs to another network.
fn wrong_network(address: &str, reason: &str) -> Error {
    Error::WrongNetwork {
        chain: Chain::Btc,
        address: address.to_string(),
        expected: "mainnet".to_string(),
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod test;
