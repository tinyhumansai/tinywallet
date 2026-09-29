//! Signing and broadcasting: the raw primitives the swap/bridge/dapp service
//! uses for externally-built transactions, and `execute_prepared`, which
//! atomically consumes a quote and dispatches it to the right chain.

use log::warn;

use crate::crypto::chains::{btc, evm, solana, tron};
use crate::crypto::defaults::{EvmNetwork, explorer_tx_url};
use crate::crypto::wallet::{WalletChain, WalletEngine};

use super::LOG_PREFIX;
use super::types::{ExecutePreparedParams, ExecutionResult, RawBroadcastResult};

impl WalletEngine {
    /// Sign and broadcast an externally-built unsigned EVM transaction
    /// (deBridge swap/bridge or generic dapp calldata).
    ///
    /// # Errors
    ///
    /// A message when the wallet has no EVM account, the calldata or target is
    /// malformed, or signing or broadcast fails.
    pub(crate) async fn sign_and_broadcast_evm(
        &self,
        network: EvmNetwork,
        to: &str,
        data_hex: Option<String>,
        value_raw: &str,
    ) -> Result<RawBroadcastResult, String> {
        evm::sign_and_broadcast_evm(self, network, to, data_hex, value_raw).await
    }

    /// Sign and broadcast an externally-built hex `VersionedTransaction`
    /// (deBridge Solana swap/bridge).
    ///
    /// # Errors
    ///
    /// A message when the blob is malformed, the wallet is not a required
    /// signer, or signing or broadcast fails.
    pub(crate) async fn sign_and_broadcast_solana(
        &self,
        tx_blob_hex: &str,
    ) -> Result<RawBroadcastResult, String> {
        solana::sign_and_broadcast_versioned(self, tx_blob_hex).await
    }

    /// Confirm and execute a prepared transfer: sign it and broadcast it.
    ///
    /// The quote is removed from the store *before* broadcasting, so two
    /// concurrent confirmations cannot both pass and double-submit. If signing
    /// or broadcast fails the quote is restored with a fresh lifetime, keeping
    /// it retryable.
    ///
    /// # Errors
    ///
    /// A message when `confirmed` is not `true`, the quote is missing (or owned
    /// by another chat thread), expired or already executed, or the chain
    /// operation fails.
    pub async fn execute_prepared(
        &self,
        params: ExecutePreparedParams,
    ) -> Result<ExecutionResult, String> {
        if !params.confirmed {
            return Err("execute_prepared requires `confirmed: true`".to_string());
        }
        // Bind execute to the chat thread that prepared the quote. A
        // mismatched owner gets the same "not found" error as a missing quote,
        // so a leaked quote id cannot be hijacked from another session.
        let caller = self.scope.current_owner();
        let quote = self.quotes.take_for(&params.quote_id, caller.as_ref())?;
        let chain = quote.chain;
        let restorable = quote.clone();
        let result = match chain {
            WalletChain::Evm => evm::execute_evm_quote(self, quote).await,
            WalletChain::Btc => btc::execute_btc_quote(self, quote).await,
            WalletChain::Solana => solana::execute_solana_quote(self, quote).await,
            WalletChain::Tron => tron::execute_tron_quote(self, quote).await,
        };
        let mut final_result = match result {
            Ok(value) => value,
            Err(error) => {
                // Restore the quote so the caller can fix the cause and retry;
                // `restore` refreshes the lifetime so a slow chain call does
                // not hand back an already-expired quote.
                self.quotes.restore(restorable);
                warn!(
                    "{LOG_PREFIX} execute chain={} quote_id={} failed (quote restored, ttl refreshed): {error}",
                    chain.as_str(),
                    params.quote_id
                );
                return Err(error);
            }
        };
        if final_result.explorer_url.is_none() {
            final_result.explorer_url = explorer_tx_url(chain, &final_result.transaction_hash);
        }
        Ok(final_result)
    }
}
