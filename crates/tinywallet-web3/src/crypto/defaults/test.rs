//! Tests for the static reference data.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    EvmNetwork, RpcSource, SolanaCluster, asset_catalog, default_rpc_url, evm_asset_catalog,
    explorer_tx_url, explorer_tx_url_for_evm_network, find_asset, find_asset_for_network,
    network_defaults,
};
use crate::crypto::wallet::WalletChain;
use crate::test_support::FakeRpcEndpoints;

const MAINNET: SolanaCluster = SolanaCluster::Mainnet;

#[test]
fn asset_catalog_includes_default_erc20s() {
    let evm = asset_catalog(WalletChain::Evm, MAINNET);
    assert!(evm.iter().any(|asset| asset.symbol == "USDC"));
    assert!(
        evm.iter()
            .any(|asset| asset.symbol == "ETH" && asset.native)
    );
}

#[test]
fn every_native_asset_is_the_only_one_without_a_contract() {
    for chain in WalletChain::ALL {
        let catalog = asset_catalog(chain, MAINNET);
        let natives = catalog.iter().filter(|a| a.native).count();
        assert_eq!(natives, 1, "{chain:?} has exactly one native asset");
        assert!(
            catalog
                .iter()
                .all(|a| a.native == a.contract_address.is_none())
        );
    }
}

#[test]
fn base_network_resolves_chain_id_8453_and_its_usdc() {
    assert_eq!(EvmNetwork::BaseMainnet.chain_id(), 8453);
    let catalog = evm_asset_catalog(EvmNetwork::BaseMainnet);
    let usdc = catalog.iter().find(|asset| asset.symbol == "USDC").unwrap();
    assert_eq!(
        usdc.contract_address.as_deref(),
        Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    );
}

#[test]
fn native_symbols_differ_by_network() {
    let native = |n| {
        evm_asset_catalog(n)
            .into_iter()
            .find(|a| a.native)
            .unwrap()
            .symbol
    };
    assert_eq!(native(EvmNetwork::PolygonMainnet), "POL");
    assert_eq!(native(EvmNetwork::BscMainnet), "BNB");
    assert_eq!(native(EvmNetwork::ArbitrumOne), "ETH");
}

#[test]
fn bsc_stablecoins_use_eighteen_decimals_and_have_no_six_decimal_usdc() {
    let bsc = evm_asset_catalog(EvmNetwork::BscMainnet);
    assert!(bsc.iter().filter(|a| !a.native).all(|a| a.decimals == 18));
    assert!(bsc.iter().any(|a| a.symbol == "USDT"));
}

#[test]
fn ethereum_carries_the_extra_tokens() {
    let symbols: Vec<String> = evm_asset_catalog(EvmNetwork::EthereumMainnet)
        .into_iter()
        .map(|a| a.symbol)
        .collect();
    for wanted in ["ETH", "USDC", "USDT", "DAI", "WETH"] {
        assert!(symbols.iter().any(|s| s == wanted), "missing {wanted}");
    }
}

#[test]
fn every_network_has_distinct_ids_labels_and_explorers() {
    let mut ids: Vec<u64> = EvmNetwork::ALL.iter().map(|n| n.chain_id()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), EvmNetwork::ALL.len());
    for network in EvmNetwork::ALL {
        assert!(network.default_rpc_url().starts_with("https://"));
        assert!(
            network.explorer_tx_base().ends_with("/tx/")
                || network.explorer_tx_base().contains("tx")
        );
        assert_eq!(network.network_label().replace('-', "_"), network.as_str());
        let round: EvmNetwork =
            serde_json::from_value(serde_json::json!(network.as_str())).unwrap();
        assert_eq!(round, network);
    }
}

#[test]
fn network_defaults_lists_all_evm_networks_and_three_other_chains() {
    let endpoints = FakeRpcEndpoints::new();
    endpoints.override_endpoint(WalletChain::Btc, None);
    let defaults = network_defaults(&endpoints);
    let evm = defaults
        .iter()
        .filter(|d| d.chain == WalletChain::Evm)
        .count();
    assert_eq!(evm, EvmNetwork::ALL.len());
    for chain in [WalletChain::Btc, WalletChain::Solana, WalletChain::Tron] {
        assert!(
            defaults.iter().any(|d| d.chain == chain),
            "missing {chain:?}"
        );
    }
    let btc = defaults
        .iter()
        .find(|d| d.chain == WalletChain::Btc)
        .unwrap();
    assert_eq!(btc.rpc_source, RpcSource::EnvOverride);
    assert_eq!(btc.rpc_url, "https://rpc.test/btc");
    assert!(!btc.supports_token_transfers);
    assert!(!btc.supports_contract_calls);
    let tron = defaults
        .iter()
        .find(|d| d.chain == WalletChain::Tron)
        .unwrap();
    assert_eq!(tron.rpc_source, RpcSource::Default);
    assert!(tron.supports_token_transfers);
    let base = defaults
        .iter()
        .find(|d| d.evm_network == Some(EvmNetwork::BaseMainnet))
        .unwrap();
    assert_eq!(base.chain_id, Some(8453));
    assert!(base.supports_contract_calls);
}

#[test]
fn find_asset_for_network_finds_base_usdc() {
    let usdc = find_asset_for_network(
        WalletChain::Evm,
        Some(EvmNetwork::BaseMainnet),
        "usdc",
        MAINNET,
    )
    .unwrap();
    assert_eq!(usdc.decimals, 6);
    assert_eq!(usdc.evm_network, Some(EvmNetwork::BaseMainnet));
    let eth = find_asset(WalletChain::Evm, " eth ", MAINNET).unwrap();
    assert!(eth.native, "lookup trims and ignores case");
    assert!(find_asset(WalletChain::Btc, "ETH", MAINNET).is_none());
}

#[test]
fn the_solana_cluster_drives_both_the_endpoint_and_the_mint() {
    assert_eq!(MAINNET.rpc_url(), "https://api.mainnet-beta.solana.com");
    assert_eq!(
        default_rpc_url(WalletChain::Solana, MAINNET),
        MAINNET.rpc_url()
    );
    let devnet = SolanaCluster::Devnet;
    assert_eq!(
        default_rpc_url(WalletChain::Solana, devnet),
        "https://api.devnet.solana.com"
    );
    let main_usdc = find_asset(WalletChain::Solana, "USDC", MAINNET).unwrap();
    let dev_usdc = find_asset(WalletChain::Solana, "USDC", devnet).unwrap();
    assert_eq!(
        main_usdc.contract_address.as_deref(),
        Some(MAINNET.usdc_mint())
    );
    assert_eq!(
        dev_usdc.contract_address.as_deref(),
        Some(devnet.usdc_mint())
    );
    assert_ne!(main_usdc.contract_address, dev_usdc.contract_address);
}

#[test]
fn default_endpoints_exist_for_every_chain() {
    assert_eq!(
        default_rpc_url(WalletChain::Evm, MAINNET),
        EvmNetwork::EthereumMainnet.default_rpc_url()
    );
    assert!(default_rpc_url(WalletChain::Btc, MAINNET).contains("blockstream"));
    assert!(default_rpc_url(WalletChain::Tron, MAINNET).contains("trongrid"));
}

#[test]
fn explorer_links_append_the_hash() {
    assert_eq!(
        explorer_tx_url(WalletChain::Evm, MAINNET, "0xabc").as_deref(),
        Some("https://etherscan.io/tx/0xabc")
    );
    assert_eq!(
        explorer_tx_url(WalletChain::Solana, MAINNET, "sig").as_deref(),
        Some("https://solscan.io/tx/sig")
    );
    assert_eq!(
        explorer_tx_url(WalletChain::Tron, MAINNET, "id").as_deref(),
        Some("https://tronscan.org/#/transaction/id")
    );
    assert_eq!(
        explorer_tx_url(WalletChain::Btc, MAINNET, "id").as_deref(),
        Some("https://blockstream.info/tx/id")
    );
    assert_eq!(
        explorer_tx_url_for_evm_network(EvmNetwork::BaseMainnet, "0x1").as_deref(),
        Some("https://basescan.org/tx/0x1")
    );
}

#[test]
fn a_devnet_solana_link_names_the_cluster() {
    let devnet = SolanaCluster::Devnet;
    assert_eq!(
        explorer_tx_url(WalletChain::Solana, devnet, "sig").as_deref(),
        Some("https://solscan.io/tx/sig?cluster=devnet")
    );
    // The cluster is a Solana matter: every other chain's link is unchanged.
    for chain in [WalletChain::Evm, WalletChain::Btc, WalletChain::Tron] {
        assert_eq!(
            explorer_tx_url(chain, devnet, "h"),
            explorer_tx_url(chain, MAINNET, "h"),
            "{chain:?}"
        );
    }
}

fn solana_row(cluster: SolanaCluster) -> super::WalletNetworkDefaults {
    let endpoints = FakeRpcEndpoints::new();
    endpoints.set_cluster(cluster);
    network_defaults(&endpoints)
        .into_iter()
        .find(|d| d.chain == WalletChain::Solana)
        .unwrap()
}

#[test]
fn mainnet_network_defaults_describe_mainnet_beta() {
    let row = solana_row(MAINNET);
    assert_eq!(row.network, "solana-mainnet-beta");
    assert_eq!(row.chain_id, None);
    assert_eq!(row.explorer_tx_url_base, "https://solscan.io/tx/");
    assert_eq!(row.explorer_tx_url_suffix, None);
    let usdc = row.assets.iter().find(|a| a.symbol == "USDC").unwrap();
    assert_eq!(usdc.contract_address.as_deref(), Some(MAINNET.usdc_mint()));
    let json = serde_json::to_value(&row).unwrap();
    assert!(
        json.get("explorerTxUrlSuffix").is_none(),
        "the mainnet row serializes as it always has: {json}"
    );
}

#[test]
fn devnet_network_defaults_describe_devnet() {
    let devnet = SolanaCluster::Devnet;
    let row = solana_row(devnet);
    assert_eq!(row.network, "solana-devnet");
    assert_eq!(row.explorer_tx_url_base, "https://solscan.io/tx/");
    assert_eq!(
        row.explorer_tx_url_suffix.as_deref(),
        Some("?cluster=devnet")
    );
    let usdc = row.assets.iter().find(|a| a.symbol == "USDC").unwrap();
    assert_eq!(usdc.contract_address.as_deref(), Some(devnet.usdc_mint()));
    assert_ne!(usdc.contract_address.as_deref(), Some(MAINNET.usdc_mint()));
    // Base plus hash plus suffix is the same link `explorer_tx_url` builds.
    assert_eq!(
        format!(
            "{}sig{}",
            row.explorer_tx_url_base,
            row.explorer_tx_url_suffix.as_deref().unwrap()
        ),
        explorer_tx_url(WalletChain::Solana, devnet, "sig").unwrap()
    );
    let json = serde_json::to_value(&row).unwrap();
    assert_eq!(json["explorerTxUrlSuffix"], "?cluster=devnet");
}

#[test]
fn the_cluster_only_changes_the_solana_row() {
    let endpoints = FakeRpcEndpoints::new();
    let main = network_defaults(&endpoints);
    endpoints.set_cluster(SolanaCluster::Devnet);
    let dev = network_defaults(&endpoints);
    for (a, b) in main.iter().zip(&dev) {
        if a.chain == WalletChain::Solana {
            assert_ne!(a.network, b.network);
        } else {
            assert_eq!(a.network, b.network);
            assert_eq!(a.explorer_tx_url_suffix, None);
            assert_eq!(b.explorer_tx_url_suffix, None);
        }
    }
}
