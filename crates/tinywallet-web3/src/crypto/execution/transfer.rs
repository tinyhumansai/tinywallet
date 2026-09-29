//! Preparing a native/token transfer quote: resolve the network, the asset and
//! the source account, then stamp a [`PreparedTransaction`] the caller must
//! separately confirm through [`WalletEngine::execute_prepared`].

use log::debug;

use crate::crypto::defaults::{EvmNetwork, asset_catalog, evm_asset_catalog, find_asset_for_network};
use crate::crypto::wallet::{WalletChain, WalletEngine};
use crate::quote::now_ms;

use super::LOG_PREFIX;
use super::types::{PrepareTransferParams, PreparedKind, PreparedStatus, PreparedTransaction};
use super::validate::{estimated_fee_raw, format_amount, validate_address, validate_amount};

impl WalletEngine {
    /// Validate a transfer and store a quote for it.
    ///
    /// The quote is bound to the chat thread the scope reports, so only that
    /// thread can execute it.
    ///
    /// # Errors
    ///
    /// A message when the address or amount is invalid, the asset is unknown
    /// for the chain, a token transfer is asked of Bitcoin, or the wallet has
    /// no account for the chain.
    pub async fn prepare_transfer(
        &self,
        params: PrepareTransferParams,
    ) -> Result<PreparedTransaction, String> {
        let to = validate_address(params.chain, &params.to_address)?;
        let amount = validate_amount(&params.amount_raw)?;
        if amount == 0 {
            return Err("transfer amount must be greater than zero".to_string());
        }
        let network = (params.chain == WalletChain::Evm)
            .then(|| params.evm_network.unwrap_or(EvmNetwork::EthereumMainnet));
        let account = self.require_account(params.chain).await?;
        let cluster = self.endpoints.solana_cluster();
        let asset = match params.asset_symbol.as_deref().map(str::trim) {
            None | Some("") => {
                // Native asset for the chain (or the chosen EVM network).
                let catalog = match network {
                    Some(net) => evm_asset_catalog(net),
                    None => asset_catalog(params.chain, cluster),
                };
                catalog
                    .into_iter()
                    .find(|value| value.native)
                    .ok_or_else(|| {
                        format!(
                            "native asset metadata missing for '{}'",
                            params.chain.as_str()
                        )
                    })?
            }
            Some(symbol) => find_asset_for_network(params.chain, network, symbol, cluster)
                .ok_or_else(|| {
                    format!(
                        "unsupported asset_symbol '{symbol}' for chain '{}'",
                        params.chain.as_str()
                    )
                })?,
        };
        let kind = if asset.native {
            PreparedKind::NativeTransfer
        } else {
            PreparedKind::TokenTransfer
        };
        // BTC has no native token concept; reject a token transfer on it.
        if params.chain == WalletChain::Btc && !asset.native {
            return Err("token transfers are not supported on Bitcoin".to_string());
        }
        let now = now_ms();
        let label = match network {
            Some(net) => format!("{} ({})", params.chain.as_str(), net.network_label()),
            None => params.chain.as_str().to_string(),
        };
        let quote = PreparedTransaction {
            quote_id: self.quotes.next_id(),
            kind,
            chain: params.chain,
            evm_network: network,
            from_address: account.address.clone(),
            to_address: to,
            asset_symbol: asset.symbol.clone(),
            amount_raw: amount.to_string(),
            amount_formatted: format_amount(amount, asset.decimals),
            receive_symbol: None,
            min_receive_raw: None,
            calldata: None,
            token_address: asset.contract_address.clone(),
            estimated_fee_raw: estimated_fee_raw(params.chain, kind),
            status: PreparedStatus::AwaitingConfirmation,
            created_at_ms: now,
            expires_at_ms: now + self.quotes.ttl_ms(),
            notes: vec![format!(
                "Prepared {} transfer on {} using default network settings.",
                asset.symbol, label
            )],
            owner: self.scope.current_owner(),
        };
        debug!(
            "{LOG_PREFIX} prepare_transfer chain={} kind={:?} quote_id={} amount={} asset={}",
            params.chain.as_str(),
            kind,
            quote.quote_id,
            quote.amount_raw,
            quote.asset_symbol
        );
        Ok(self.quotes.insert(quote))
    }
}
