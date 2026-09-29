//! The crypto rail: build and sign the on-chain payment a 402 asks for.
//!
//! Everything chain-specific about x402 lives here, and nothing above it does.
//!
//! - [`signer`] — the [`PaymentSigner`] seam: the host's wallet, seen as "give
//!   me your address" and "sign these bytes".
//! - [`evm_payment`] — EIP-3009 `transferWithAuthorization` over an EIP-712
//!   digest.
//! - [`solana_payment`] — a partially-signed SPL `TransferChecked` legacy
//!   transaction.
//! - [`payments`] — [`CryptoPayments`], the [`PaymentBuilder`] that picks
//!   between the two.
//!
//! ## Where keys are
//!
//! Not here. [`PaymentSigner::sign`] takes a message and returns a signature;
//! the mnemonic, the derived key and whatever module holds them stay behind the
//! trait. This crate cannot leak a key it never sees.
//!
//! [`PaymentBuilder`]: crate::protocol::PaymentBuilder

mod evm_payment;
mod payments;
mod signer;
mod solana_payment;

pub use payments::CryptoPayments;
pub use signer::{PaymentAccount, PaymentSigner, SignScheme};

use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const LOG_PREFIX: &str = "[x402]";

/// A fresh 32-byte value for an EIP-3009 nonce or a Solana memo.
///
/// Uniqueness is what matters here, not secrecy: the nonce stops a signed
/// authorization being replayed, and the memo makes two otherwise identical
/// transfers distinct transactions. So it hashes the clock, the process id and a
/// process-wide counter, and the counter is what keeps two calls in the same
/// clock tick apart.
pub(crate) fn fresh_nonce() -> [u8; 32] {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    hasher.finalize().into()
}

#[cfg(test)]
mod test;
