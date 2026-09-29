//! The seam between the protocol and a payment rail.

use async_trait::async_trait;

use super::error::X402Error;
use crate::wire::{PaymentChain, PaymentPayload, PaymentRequired, PaymentRequirements};

/// Turns a 402 requirement into the proof that answers it.
///
/// The crypto rail implements this with [`crate::crypto::CryptoPayments`]. The
/// trait names no key, signature or transaction, so a rail that authorises
/// rather than signs bytes can implement it too.
#[async_trait]
pub trait PaymentBuilder: Send + Sync {
    /// Build the payload for `requirement`, one of `challenge.accepts`, on the
    /// chain family `chain`.
    ///
    /// # Errors
    ///
    /// [`X402Error::Protocol`] for a requirement that cannot be paid as given,
    /// [`X402Error::Wallet`] when the wallet cannot produce the payment.
    async fn build(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error>;
}
