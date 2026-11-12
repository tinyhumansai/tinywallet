//! The seam between the protocol and a payment rail.

use async_trait::async_trait;
use chrono::{DateTime, Utc};

use super::error::X402Error;
use crate::wire::{
    PaymentChain, PaymentPayload, PaymentProof, PaymentRequired, PaymentRequirements,
};

/// Rail-specific metadata that stays in the host ledger and is never added to
/// the facilitator-facing payment payload.
#[derive(Debug, Clone)]
pub struct PaymentBuild {
    /// The unchanged facilitator wire payload.
    pub payload: PaymentPayload,
    /// An exact wall-clock authorization deadline, when the rail exposes one.
    pub authorization_valid_until: Option<DateTime<Utc>>,
    /// Solana blockhash expiry bound from the same blockhash used in payload.
    pub solana_last_valid_block_height: Option<u64>,
}

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

    /// Build a payload plus rail metadata. The conservative default preserves
    /// compatibility for existing builders and extracts only the exact EVM
    /// deadline available in the wire proof.
    async fn build_with_metadata(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentBuild, X402Error> {
        let payload = self.build(challenge, requirement, chain).await?;
        let authorization_valid_until = payload
                .payload
                .authorization_deadline_secs()
                .and_then(|seconds| DateTime::from_timestamp(seconds, 0));
        Ok(PaymentBuild {
            payload,
            authorization_valid_until,
            solana_last_valid_block_height: None,
        })
    }

    /// Return a well-typed finalized Solana block height when this builder has
    /// the trusted transport needed to refresh pending authorizations.
    /// Implementations without such a transport conservatively return `None`.
    async fn finalized_solana_block_height(&self) -> Result<Option<u64>, X402Error> {
        Ok(None)
    }
}
