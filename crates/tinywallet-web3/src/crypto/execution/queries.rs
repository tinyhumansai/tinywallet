//! Read-only wallet surface: network defaults, the supported-asset catalog,
//! per-chain provider status and live balances.

use log::{debug, warn};

use crate::crypto::chains::{btc, evm, solana, tron};
use crate::crypto::defaults::{
    EvmNetwork, WalletAssetDefinition, WalletNetworkDefaults, asset_catalog, evm_asset_catalog,
    network_defaults,
};
use crate::crypto::wallet::{WalletAccount, WalletChain, WalletEngine};
use crate::quote::WALLET_NOT_CONFIGURED_MESSAGE;

use super::LOG_PREFIX;
use super::types::{BalanceInfo, ChainStatus, ProviderStatus, SupportedAsset};
use super::validate::format_amount;

/// EVM networks surfaced as their own native-balance rows. The single derived
/// EVM account address is shared across all of them, so `balances` reads the
/// native asset (ETH / ETH / BNB) on each network independently.
pub(crate) const EVM_BALANCE_NETWORKS: [EvmNetwork; 3] = [
    EvmNetwork::EthereumMainnet,
    EvmNetwork::BaseMainnet,
    EvmNetwork::BscMainnet,
];

fn asset_to_supported(asset: WalletAssetDefinition) -> SupportedAsset {
    SupportedAsset {
        chain: asset.chain,
        evm_network: asset.evm_network,
        symbol: asset.symbol,
        name: asset.name,
        native: asset.native,
        decimals: asset.decimals,
        contract_address: asset.contract_address,
    }
}

impl WalletEngine {
    /// The default row for every supported network, with the endpoints the
    /// host resolved.
    #[must_use]
    pub fn network_defaults(&self) -> Vec<WalletNetworkDefaults> {
        let rows = network_defaults(self.endpoints.as_ref());
        debug!("{LOG_PREFIX} network_defaults count={}", rows.len());
        rows
    }

    /// Every asset the wallet catalogues.
    #[must_use]
    pub fn supported_assets(&self) -> Vec<SupportedAsset> {
        let cluster = self.endpoints.solana_cluster();
        let mut assets: Vec<SupportedAsset> = Vec::new();
        for network in EvmNetwork::ALL {
            assets.extend(
                evm_asset_catalog(network)
                    .into_iter()
                    .map(asset_to_supported),
            );
        }
        for chain in [WalletChain::Btc, WalletChain::Solana, WalletChain::Tron] {
            assets.extend(
                asset_catalog(chain, cluster)
                    .into_iter()
                    .map(asset_to_supported),
            );
        }
        debug!("{LOG_PREFIX} supported_assets count={}", assets.len());
        assets
    }

    /// Which chains have an account and a provider that answers.
    ///
    /// A chain with an account has its endpoint probed (see
    /// `WalletEngine::probe_provider`): [`ProviderStatus::Ready`] when it
    /// answers, [`ProviderStatus::Missing`] with the failure in
    /// [`ChainStatus::error`] when it does not. A chain with no account is
    /// `Missing` and is not contacted.
    ///
    /// # Errors
    ///
    /// The host's error if the wallet status cannot be read. An endpoint that
    /// fails its probe is reported in its row, not as an error.
    pub async fn chain_status(&self) -> Result<Vec<ChainStatus>, String> {
        let status = self.accounts.status().await?;
        let has = |chain: WalletChain| status.accounts.iter().any(|a| a.chain == chain);
        let mut rows = Vec::new();
        for network in EvmNetwork::ALL {
            rows.push(
                self.chain_status_row(WalletChain::Evm, Some(network), has(WalletChain::Evm))
                    .await,
            );
        }
        for chain in [WalletChain::Btc, WalletChain::Solana, WalletChain::Tron] {
            rows.push(self.chain_status_row(chain, None, has(chain)).await);
        }
        debug!("{LOG_PREFIX} chain_status reported chains={}", rows.len());
        Ok(rows)
    }

    /// One chain's status row, probing its endpoint when it has an account.
    async fn chain_status_row(
        &self,
        chain: WalletChain,
        network: Option<EvmNetwork>,
        has_account: bool,
    ) -> ChainStatus {
        let (provider_status, error) = if has_account {
            match self.probe_provider(chain, network).await {
                Ok(()) => (ProviderStatus::Ready, None),
                Err(error) => {
                    warn!(
                        "{LOG_PREFIX} chain_status chain={} network={} probe failed: {error}",
                        chain.as_str(),
                        network.map_or("-", EvmNetwork::as_str)
                    );
                    (ProviderStatus::Missing, Some(error))
                }
            }
        } else {
            (ProviderStatus::Missing, None)
        };
        ChainStatus {
            chain,
            evm_network: network,
            configured: has_account,
            provider_status,
            rpc_url: self.endpoints.url(chain, network),
            error,
        }
    }

    /// The native-asset definition for a non-EVM chain.
    fn native_asset_for(&self, chain: WalletChain) -> Result<WalletAssetDefinition, String> {
        asset_catalog(chain, self.endpoints.solana_cluster())
            .into_iter()
            .find(|value| value.native)
            .ok_or_else(|| format!("native asset metadata missing for '{}'", chain.as_str()))
    }

    /// Live native balances: one row per displayed EVM network plus one each
    /// for Bitcoin, Solana and Tron. A provider that cannot be reached yields a
    /// zero row marked [`ProviderStatus::Missing`] rather than failing the read.
    ///
    /// # Errors
    ///
    /// [`WALLET_NOT_CONFIGURED_MESSAGE`] when the wallet is not set up, or the
    /// host's error if the status cannot be read.
    pub async fn balances(&self) -> Result<Vec<BalanceInfo>, String> {
        let status = self.accounts.status().await?;
        if !status.configured {
            return Err(WALLET_NOT_CONFIGURED_MESSAGE.to_string());
        }
        let mut out = Vec::with_capacity(status.accounts.len() + EVM_BALANCE_NETWORKS.len());
        for account in &status.accounts {
            match account.chain {
                // The EVM account fans out into one native-balance row per
                // displayed network, all sharing the same address.
                WalletChain::Evm => {
                    for network in EVM_BALANCE_NETWORKS {
                        let asset = evm_asset_catalog(network)
                            .into_iter()
                            .find(|value| value.native)
                            .ok_or_else(|| {
                                format!(
                                    "native asset metadata missing for evm network '{}'",
                                    network.as_str()
                                )
                            })?;
                        out.push(self.balance_row(account, Some(network), asset).await);
                    }
                }
                chain => {
                    let asset = self.native_asset_for(chain)?;
                    out.push(self.balance_row(account, None, asset).await);
                }
            }
        }
        debug!("{LOG_PREFIX} balances returned rows={}", out.len());
        Ok(out)
    }

    /// Read one native balance, falling back to a zero row on failure.
    async fn balance_row(
        &self,
        account: &WalletAccount,
        network: Option<EvmNetwork>,
        asset: WalletAssetDefinition,
    ) -> BalanceInfo {
        let chain = account.chain;
        let read = match chain {
            WalletChain::Evm => {
                evm::evm_balance(
                    self,
                    network.unwrap_or(EvmNetwork::EthereumMainnet),
                    &account.address,
                )
                .await
            }
            WalletChain::Btc => btc::native_balance(self, &account.address).await,
            WalletChain::Solana => solana::native_balance(self, &account.address).await,
            WalletChain::Tron => tron::native_balance(self, &account.address).await,
        };
        let (raw, provider_status) = match read {
            Ok(balance) => (balance.to_string(), ProviderStatus::Ready),
            Err(error) => {
                warn!(
                    "{LOG_PREFIX} balances chain={} network={} address={} falling back to zero: {error}",
                    chain.as_str(),
                    network.map_or("-", EvmNetwork::as_str),
                    account.address
                );
                ("0".to_string(), ProviderStatus::Missing)
            }
        };
        let raw_u128 = raw.parse::<u128>().unwrap_or(0);
        BalanceInfo {
            chain,
            evm_network: network,
            address: account.address.clone(),
            asset_symbol: asset.symbol,
            decimals: asset.decimals,
            formatted: format_amount(raw_u128, asset.decimals),
            raw,
            provider_status,
        }
    }
}
