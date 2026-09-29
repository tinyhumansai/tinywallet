//! The shared confirm-then-execute path: take the stored quote (owner-gated),
//! route its unsigned transaction to the matching wallet signer, and put the
//! quote back on failure so it stays retryable.

use log::warn;

use super::types::{ExecuteQuoteParams, UnsignedTx, Web3ExecutionResult};
use super::{LOG_PREFIX, Web3Service};

impl Web3Service {
    /// Confirm and execute a prepared quote: sign and broadcast the stored
    /// unsigned transaction via the wallet, restoring the quote (with a
    /// refreshed lifetime) on failure.
    ///
    /// # Errors
    ///
    /// A message when `confirmed` is not `true`, the quote is missing (or owned
    /// by another chat thread) or expired, or signing or broadcast fails.
    pub async fn execute_quote(
        &self,
        params: ExecuteQuoteParams,
    ) -> Result<Web3ExecutionResult, String> {
        if !params.confirmed {
            return Err("execute requires `confirmed: true`".to_string());
        }
        let caller = self.engine.scope.current_owner();
        let quote = self.quotes.take_for(&params.quote_id, caller.as_ref())?;
        let kind = quote.kind;
        let restorable = quote.clone();

        let result = match &quote.unsigned {
            UnsignedTx::Evm {
                network,
                to,
                data,
                value,
            } => {
                self.engine
                    .sign_and_broadcast_evm(*network, to, data.clone(), value)
                    .await
            }
            UnsignedTx::Solana { tx_blob_hex } => {
                self.engine.sign_and_broadcast_solana(tx_blob_hex).await
            }
        };

        match result {
            Ok(broadcast) => Ok(Web3ExecutionResult {
                quote_id: params.quote_id,
                kind,
                transaction_hash: broadcast.transaction_hash,
                explorer_url: broadcast.explorer_url,
                fee_raw: broadcast.fee_raw,
            }),
            Err(error) => {
                // Restore with a refreshed lifetime so the caller can retry.
                self.quotes.restore(restorable);
                warn!(
                    "{LOG_PREFIX} execute quote_id={} kind={kind:?} failed (restored): {error}",
                    params.quote_id
                );
                Err(error)
            }
        }
    }
}
