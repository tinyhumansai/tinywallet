//! [`CryptoPayments`]: the crypto rail's [`PaymentBuilder`].

use std::sync::Arc;

use async_trait::async_trait;
use tinywallet_crypto::Chain;
use tinywallet_crypto::rpc::{self, NetworkId, Transport};

use super::evm_payment::build_evm_payment;
use super::signer::PaymentSigner;
use super::solana_payment::{b58_to_32, build_solana_payment};
use crate::protocol::{PaymentBuild, PaymentBuilder, X402Error};
use crate::wire::{
    PaymentChain, PaymentPayload, PaymentProof, PaymentRequired, PaymentRequirements,
};

/// Builds EVM and Solana payments with an injected wallet and chain transport.
#[derive(Clone)]
pub struct CryptoPayments {
    signer: Arc<dyn PaymentSigner>,
    transport: Arc<dyn Transport>,
}

impl std::fmt::Debug for CryptoPayments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoPayments").finish_non_exhaustive()
    }
}

impl CryptoPayments {
    /// Pay with `signer`, reading the Solana blockhash through `transport`.
    #[must_use]
    pub fn new(signer: Arc<dyn PaymentSigner>, transport: Arc<dyn Transport>) -> Self {
        Self { signer, transport }
    }

    async fn build_with_rail_metadata(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentBuild, X402Error> {
        let (payload, solana_last_valid_block_height) = match chain {
            PaymentChain::Solana => {
                let account = self
                    .signer
                    .account(PaymentChain::Solana)
                    .await
                    .map_err(X402Error::Wallet)?;
                let pubkey = match account.pubkey {
                    Some(key) => key,
                    None => b58_to_32(&account.address)?,
                };
                let (payload, last_valid_height) = build_solana_payment(
                    self.signer.as_ref(),
                    self.transport.as_ref(),
                    pubkey,
                    challenge,
                    requirement,
                )
                .await?;
                (payload, Some(last_valid_height))
            }
            PaymentChain::Evm => (
                build_evm_payment(self.signer.as_ref(), challenge, requirement).await?,
                None,
            ),
        };
        let authorization_valid_until = payload
            .payload
            .authorization_deadline_secs()
            .and_then(|seconds| chrono::DateTime::from_timestamp(seconds, 0));
        Ok(PaymentBuild {
            payload,
            authorization_valid_until,
            solana_last_valid_block_height,
        })
    }
}

#[async_trait]
impl PaymentBuilder for CryptoPayments {
    async fn build(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        Ok(self
            .build_with_rail_metadata(challenge, requirement, chain)
            .await?
            .payload)
    }

    async fn build_with_metadata(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentBuild, X402Error> {
        self.build_with_rail_metadata(challenge, requirement, chain)
            .await
    }

    async fn finalized_solana_block_height(&self) -> Result<Option<u64>, X402Error> {
        const METHOD: &str = "getBlockHeight";
        let network = NetworkId::chain(Chain::Solana);
        let result = self
            .transport
            .json_rpc(
                network,
                METHOD,
                serde_json::json!([{"commitment": "finalized"}]),
            )
            .await
            .map_err(|error| X402Error::Wallet(format!("fetch finalized block height: {error}")))?;
        let height: u64 = rpc::decode(network, METHOD, result)
            .map_err(|error| X402Error::Wallet(format!("fetch finalized block height: {error}")))?;
        Ok(Some(height))
    }
}
