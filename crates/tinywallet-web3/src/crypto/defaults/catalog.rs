//! Static catalogs: assets per chain, explorer URLs and network defaults.
//!
//! Everything here is a pure function of its inputs. The two things that vary
//! by deployment (the endpoint a host resolved, and the Solana cluster) come in
//! as arguments or through [`RpcEndpoints`].

use crate::crypto::seams::RpcEndpoints;
use crate::crypto::wallet::WalletChain;

use super::types::{EvmNetwork, SolanaCluster, WalletAssetDefinition, WalletNetworkDefaults};

const BLOCKSTREAM_TX_BASE: &str = "https://blockstream.info/tx/";
const SOLSCAN_TX_BASE: &str = "https://solscan.io/tx/";
const TRONSCAN_TX_BASE: &str = "https://tronscan.org/#/transaction/";

const DEFAULT_BTC_REST_URL: &str = "https://blockstream.info/api";
const DEFAULT_TRON_REST_URL: &str = "https://api.trongrid.io";

/// The built-in endpoint for `chain`. For EVM this is Ethereum mainnet's.
#[must_use]
pub const fn default_rpc_url(chain: WalletChain, cluster: SolanaCluster) -> &'static str {
    match chain {
        WalletChain::Evm => EvmNetwork::EthereumMainnet.default_rpc_url(),
        WalletChain::Btc => DEFAULT_BTC_REST_URL,
        WalletChain::Solana => cluster.rpc_url(),
        WalletChain::Tron => DEFAULT_TRON_REST_URL,
    }
}

/// The explorer link for a transaction on `chain` (Ethereum mainnet for EVM).
///
/// `cluster` only matters for Solana, whose link then carries the cluster
/// (`?cluster=devnet`) so it opens on the network the transaction went to.
#[must_use]
pub fn explorer_tx_url(
    chain: WalletChain,
    cluster: SolanaCluster,
    tx_hash: &str,
) -> Option<String> {
    let (base, suffix) = match chain {
        WalletChain::Evm => (EvmNetwork::EthereumMainnet.explorer_tx_base(), ""),
        WalletChain::Btc => (BLOCKSTREAM_TX_BASE, ""),
        WalletChain::Solana => (SOLSCAN_TX_BASE, cluster.explorer_tx_suffix()),
        WalletChain::Tron => (TRONSCAN_TX_BASE, ""),
    };
    Some(format!("{base}{tx_hash}{suffix}"))
}

/// The explorer link for a transaction on a specific EVM network.
#[must_use]
pub fn explorer_tx_url_for_evm_network(network: EvmNetwork, tx_hash: &str) -> Option<String> {
    Some(format!("{}{}", network.explorer_tx_base(), tx_hash))
}

fn asset(
    chain: WalletChain,
    evm_network: Option<EvmNetwork>,
    symbol: &str,
    name: &str,
    decimals: u8,
    contract_address: Option<&str>,
) -> WalletAssetDefinition {
    WalletAssetDefinition {
        chain,
        evm_network,
        symbol: symbol.to_string(),
        name: name.to_string(),
        native: contract_address.is_none(),
        decimals,
        contract_address: contract_address.map(str::to_string),
    }
}

/// The assets catalogued for a non-EVM chain, or Ethereum mainnet's for EVM.
///
/// `cluster` picks the Solana USDC mint.
#[must_use]
pub fn asset_catalog(chain: WalletChain, cluster: SolanaCluster) -> Vec<WalletAssetDefinition> {
    match chain {
        WalletChain::Evm => evm_asset_catalog(EvmNetwork::EthereumMainnet),
        WalletChain::Btc => vec![asset(chain, None, "BTC", "Bitcoin", 8, None)],
        WalletChain::Solana => vec![
            asset(chain, None, "SOL", "Solana", 9, None),
            asset(
                chain,
                None,
                "USDC",
                "USD Coin (Solana)",
                6,
                Some(cluster.usdc_mint()),
            ),
        ],
        WalletChain::Tron => vec![
            asset(chain, None, "TRX", "Tron", 6, None),
            asset(
                chain,
                None,
                "USDT",
                "Tether USD (TRC20)",
                6,
                Some("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
            ),
        ],
    }
}

/// The assets catalogued for one EVM network.
#[must_use]
pub fn evm_asset_catalog(network: EvmNetwork) -> Vec<WalletAssetDefinition> {
    let evm = |symbol: &str, name: &str, decimals: u8, contract: Option<&str>| {
        asset(
            WalletChain::Evm,
            Some(network),
            symbol,
            name,
            decimals,
            contract,
        )
    };
    let (native_symbol, native_name) = match network {
        EvmNetwork::PolygonMainnet => ("POL", "Polygon"),
        EvmNetwork::BscMainnet => ("BNB", "BNB"),
        _ => ("ETH", "Ether"),
    };
    let mut assets = vec![evm(native_symbol, native_name, 18, None)];
    // Per-L2 USDC native addresses. BSC is handled below (18-decimal tokens).
    let usdc = match network {
        EvmNetwork::EthereumMainnet => Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        EvmNetwork::BaseMainnet => Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
        EvmNetwork::ArbitrumOne => Some("0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
        EvmNetwork::OptimismMainnet => Some("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
        EvmNetwork::PolygonMainnet => Some("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
        EvmNetwork::BscMainnet => None,
    };
    if let Some(usdc) = usdc {
        assets.push(evm("USDC", "USD Coin", 6, Some(usdc)));
    }
    // BNB Chain BEP20 stablecoins use 18 decimals (unlike the 6-decimal USDC on
    // other EVM chains), so they are catalogued separately.
    if network == EvmNetwork::BscMainnet {
        assets.extend([
            evm(
                "USDT",
                "Tether USD (BEP20)",
                18,
                Some("0x55d398326f99059fF775485246999027B3197955"),
            ),
            evm(
                "USDC",
                "USD Coin (BEP20)",
                18,
                Some("0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d"),
            ),
        ]);
    }
    if network == EvmNetwork::EthereumMainnet {
        assets.extend([
            evm(
                "USDT",
                "Tether USD",
                6,
                Some("0xdAC17F958D2ee523a2206206994597C13D831ec7"),
            ),
            evm(
                "DAI",
                "Dai",
                18,
                Some("0x6B175474E89094C44Da98b954EedeAC495271d0F"),
            ),
            evm(
                "WETH",
                "Wrapped Ether",
                18,
                Some("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"),
            ),
        ]);
    }
    assets
}

/// The default row for every supported network, with the endpoints the host
/// resolved through `endpoints`.
#[must_use]
pub fn network_defaults(endpoints: &dyn RpcEndpoints) -> Vec<WalletNetworkDefaults> {
    let cluster = endpoints.solana_cluster();
    let mut out = Vec::new();
    for network in EvmNetwork::ALL {
        out.push(WalletNetworkDefaults {
            chain: WalletChain::Evm,
            evm_network: Some(network),
            network: network.network_label().to_string(),
            chain_id: Some(network.chain_id()),
            rpc_url: endpoints.url(WalletChain::Evm, Some(network)),
            rpc_source: endpoints.source(WalletChain::Evm, Some(network)),
            explorer_tx_url_base: network.explorer_tx_base().to_string(),
            explorer_tx_url_suffix: None,
            supports_broadcast: true,
            supports_token_transfers: true,
            supports_contract_calls: true,
            assets: evm_asset_catalog(network),
        });
    }
    for (chain, label, explorer, suffix) in [
        (WalletChain::Btc, "bitcoin-mainnet", BLOCKSTREAM_TX_BASE, ""),
        (
            WalletChain::Solana,
            cluster.network_label(),
            SOLSCAN_TX_BASE,
            cluster.explorer_tx_suffix(),
        ),
        (WalletChain::Tron, "tron-mainnet", TRONSCAN_TX_BASE, ""),
    ] {
        out.push(WalletNetworkDefaults {
            chain,
            evm_network: None,
            network: label.to_string(),
            chain_id: None,
            rpc_url: endpoints.url(chain, None),
            rpc_source: endpoints.source(chain, None),
            explorer_tx_url_base: explorer.to_string(),
            explorer_tx_url_suffix: (!suffix.is_empty()).then(|| suffix.to_string()),
            supports_broadcast: true,
            supports_token_transfers: chain != WalletChain::Btc,
            supports_contract_calls: false,
            assets: asset_catalog(chain, cluster),
        });
    }
    out
}

/// Find an asset by symbol (case-insensitive) on `chain`.
#[must_use]
pub fn find_asset(
    chain: WalletChain,
    symbol: &str,
    cluster: SolanaCluster,
) -> Option<WalletAssetDefinition> {
    find_asset_for_network(chain, None, symbol, cluster)
}

/// Find an asset by symbol (case-insensitive) on `chain`; for EVM, on
/// `network` (Ethereum mainnet when `None`).
#[must_use]
pub fn find_asset_for_network(
    chain: WalletChain,
    network: Option<EvmNetwork>,
    symbol: &str,
    cluster: SolanaCluster,
) -> Option<WalletAssetDefinition> {
    let needle = symbol.trim();
    let catalog = match (chain, network) {
        (WalletChain::Evm, Some(net)) => evm_asset_catalog(net),
        (WalletChain::Evm, None) => evm_asset_catalog(EvmNetwork::EthereumMainnet),
        (other, _) => asset_catalog(other, cluster),
    };
    catalog
        .into_iter()
        .find(|asset| asset.symbol.eq_ignore_ascii_case(needle))
}
