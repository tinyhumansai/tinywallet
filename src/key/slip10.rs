//! SLIP-0010 hardened-only derivation on ed25519, used by Solana.
//!
//! ed25519 cannot do BIP-32's non-hardened derivation: that step needs
//! public-key addition, which the curve's key format does not support. SLIP-0010
//! defines the hardened-only variant instead, and this is it — about twenty
//! lines of HMAC-SHA512, with no scalar arithmetic and so no failure mode
//! beyond a malformed path.
//!
//! Solana wallets standardise on `m/44'/501'/N'/0'`, which is fully hardened,
//! so the restriction costs nothing in practice.

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zeroize::Zeroizing;

use super::{Error, Result};

type HmacSha512 = Hmac<Sha512>;

/// The domain-separation key SLIP-0010 specifies for ed25519.
const CURVE_SEED: &[u8] = b"ed25519 seed";

/// Derive the 32-byte ed25519 secret for `path` from `seed`.
///
/// `path` must be fully hardened. Each index is OR-ed with `0x8000_0000`
/// regardless, but [`parse_path`] rejects an unhardened segment first — see
/// [`Error::UnhardenedSolanaPath`] for why that is not silently tolerated.
pub(super) fn derive(seed: &[u8], path: &str) -> Result<Zeroizing<[u8; 32]>> {
    let indices = parse_path(path)?;

    let mut mac = HmacSha512::new_from_slice(CURVE_SEED).map_err(|_| Error::Derivation {
        step: "SLIP-0010 master HMAC",
    })?;
    mac.update(seed);
    let digest = mac.finalize().into_bytes();

    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain_code = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest[..32]);
    chain_code.copy_from_slice(&digest[32..]);

    for index in indices {
        let hardened = index | 0x8000_0000;
        let mut mac =
            HmacSha512::new_from_slice(chain_code.as_slice()).map_err(|_| Error::Derivation {
                step: "SLIP-0010 child HMAC",
            })?;
        // The leading zero byte is what marks this as the hardened form.
        mac.update(&[0u8]);
        mac.update(key.as_slice());
        mac.update(&hardened.to_be_bytes());
        let digest = mac.finalize().into_bytes();
        key.copy_from_slice(&digest[..32]);
        chain_code.copy_from_slice(&digest[32..]);
    }

    Ok(key)
}

/// Parse a fully hardened path into its indices.
///
/// # Errors
///
/// [`Error::InvalidPath`] if the path does not start at `m`, has no segments,
/// or holds a non-numeric index. [`Error::UnhardenedSolanaPath`] if any segment
/// lacks its trailing apostrophe.
fn parse_path(path: &str) -> Result<Vec<u32>> {
    let trimmed = path.trim();
    let mut segments = trimmed.split('/');

    if segments.next() != Some("m") {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "must start with 'm'".to_string(),
        });
    }

    let mut out = Vec::new();
    for segment in segments {
        let Some(index) = segment.strip_suffix('\'') else {
            return Err(Error::UnhardenedSolanaPath {
                path: path.to_string(),
            });
        };
        let index = index.parse::<u32>().map_err(|e| Error::InvalidPath {
            path: path.to_string(),
            reason: format!("segment '{segment}': {e}"),
        })?;
        // The raw index must leave the hardening bit clear, because the caller
        // sets it (`index | 0x8000_0000`). A segment that already carries it
        // would OR to itself, so `m/44'/501'/2147483648'` and
        // `m/44'/501'/0'` would silently derive the same key from visibly
        // different paths — a wrong answer, not a rejected one.
        if index >= 0x8000_0000 {
            return Err(Error::InvalidPath {
                path: path.to_string(),
                reason: format!("segment '{segment}' exceeds the maximum raw index"),
            });
        }
        out.push(index);
    }

    if out.is_empty() {
        return Err(Error::InvalidPath {
            path: path.to_string(),
            reason: "has no segments".to_string(),
        });
    }
    Ok(out)
}
