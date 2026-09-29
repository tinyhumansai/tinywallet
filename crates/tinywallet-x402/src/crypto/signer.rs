//! The wallet seam: an address, and signatures, and nothing else.

use async_trait::async_trait;

use crate::wire::PaymentChain;

/// The signature scheme a payment needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignScheme {
    /// Ed25519 over the message bytes (a Solana transaction message).
    Ed25519,
    /// secp256k1 over a 32-byte prehashed digest (an EIP-712 signing digest),
    /// with a recovery id.
    Secp256k1Digest,
}

/// The account a payment is signed as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentAccount {
    /// The account's address in the chain's own encoding: base58 for Solana, a
    /// `0x` EIP-55 checksummed address for EVM.
    pub address: String,
    /// The raw 32-byte public key, when the wallet has it.
    ///
    /// Solana only. When `None`, the key is decoded from `address`, which for
    /// Solana is the base58 of the same 32 bytes.
    pub pubkey: Option<[u8; 32]>,
}

/// The host's wallet, as x402 uses it.
///
/// Implementations resolve the wallet's secret however the host stores it and
/// sign without ever handing it back. Errors are plain strings carrying the
/// text a user should see; the crate prefixes them with `x402 wallet: `.
#[async_trait]
pub trait PaymentSigner: Send + Sync {
    /// The account payments on `chain` are signed as.
    ///
    /// # Errors
    ///
    /// A description of why the wallet could not be reached or has no account
    /// for `chain`.
    async fn account(&self, chain: PaymentChain) -> Result<PaymentAccount, String>;

    /// Sign `message` as the account [`account`](Self::account) reports for
    /// `chain`.
    ///
    /// The return value is:
    ///
    /// - [`SignScheme::Ed25519`]: the 64-byte signature.
    /// - [`SignScheme::Secp256k1Digest`]: 65 bytes, `r ‖ s ‖ recovery_id` where
    ///   the recovery id is the raw `0` or `1`, not the EIP-712 `27`/`28`
    ///   offset — the crate applies that itself.
    ///
    /// # Errors
    ///
    /// A description of why signing failed.
    async fn sign(
        &self,
        chain: PaymentChain,
        message: &[u8],
        scheme: SignScheme,
    ) -> Result<Vec<u8>, String>;
}
