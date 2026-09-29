//! [`CryptoPayments`]: the crypto rail's [`PaymentBuilder`].

use std::sync::Arc;

use async_trait::async_trait;
use tinywallet_crypto::rpc::Transport;

use super::evm_payment::build_evm_payment;
use super::signer::PaymentSigner;
use super::solana_payment::{b58_to_32, build_solana_payment};
use crate::protocol::{PaymentBuilder, X402Error};
use crate::wire::{PaymentChain, PaymentPayload, PaymentRequired, PaymentRequirements};

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
}

#[async_trait]
impl PaymentBuilder for CryptoPayments {
    async fn build(
        &self,
        challenge: &PaymentRequired,
        requirement: &PaymentRequirements,
        chain: PaymentChain,
    ) -> Result<PaymentPayload, X402Error> {
        match chain {
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
                build_solana_payment(
                    self.signer.as_ref(),
                    self.transport.as_ref(),
                    pubkey,
                    challenge,
                    requirement,
                )
                .await
            }
            PaymentChain::Evm => {
                build_evm_payment(self.signer.as_ref(), challenge, requirement).await
            }
        }
    }
}
