//! Unit tests for the network and asset catalog.
//!
//! These lean hard on decimals and contract addresses, because those are the
//! fields that silently misprice or misdirect a transfer rather than failing
//! loudly.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{EvmNetwork, Network, SolanaCluster, catalog, find, networks};
use crate::chain::Chain;

#[test]
fn every_evm_network_has_a_distinct_chain_id() {
    // A duplicate here would let a transaction signed for one network be
    // replayed on another.
    let mut ids: Vec<u64> = EvmNetwork::ALL.iter().map(|n| n.chain_id()).collect();
    let total = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), total, "duplicate EVM chain id");
}

#[test]
fn chain_ids_match_the_published_values() {
    // Hardcoded rather than derived: these are external constants, and a test
    // that recomputed them from the same table would prove nothing.
    for (network, expected) in [
        (EvmNetwork::Ethereum, 1),
        (EvmNetwork::Optimism, 10),
        (EvmNetwork::Bsc, 56),
        (EvmNetwork::Polygon, 137),
        (EvmNetwork::Base, 8453),
        (EvmNetwork::Arbitrum, 42161),
    ] {
        assert_eq!(network.chain_id(), expected, "{network}");
    }
}

#[test]
fn chain_id_lookup_round_trips() {
    for network in EvmNetwork::ALL {
        assert_eq!(
            EvmNetwork::from_chain_id(network.chain_id()),
            Some(*network)
        );
    }
    assert_eq!(EvmNetwork::from_chain_id(999_999), None);
}

#[test]
fn usdc_is_six_decimals_everywhere_except_bnb_chain() {
    // The trap this catalog exists to encode: same symbol, same chain family,
    // different scale. Getting it wrong misprices a transfer by 10^12.
    for network in [
        EvmNetwork::Ethereum,
        EvmNetwork::Base,
        EvmNetwork::Arbitrum,
        EvmNetwork::Optimism,
        EvmNetwork::Polygon,
    ] {
        let usdc = find(Network::Evm(network), "USDC")
            .unwrap_or_else(|| panic!("{network} should list USDC"));
        assert_eq!(usdc.decimals, 6, "{network} USDC decimals");
    }

    let bsc = find(Network::Evm(EvmNetwork::Bsc), "USDC").unwrap();
    assert_eq!(bsc.decimals, 18, "BEP-20 USDC is 18 decimals");
}

#[test]
fn bnb_chain_lists_no_six_decimal_usdc() {
    // Regression guard for the shape of `evm_catalog`: BSC is excluded from
    // the 6-decimal branch and added in the 18-decimal one. If it ever
    // appeared in both, `find` would return whichever came first.
    let usdc: Vec<_> = catalog(Network::Evm(EvmNetwork::Bsc))
        .into_iter()
        .filter(|a| a.symbol == "USDC")
        .collect();
    assert_eq!(usdc.len(), 1, "exactly one USDC entry: {usdc:?}");
    assert_eq!(usdc[0].decimals, 18);
}

#[test]
fn solana_usdc_mint_differs_per_cluster() {
    // A devnet transfer built with the mainnet mint targets a token account
    // that does not exist there.
    let mainnet = find(Network::Solana(SolanaCluster::Mainnet), "USDC").unwrap();
    let devnet = find(Network::Solana(SolanaCluster::Devnet), "USDC").unwrap();
    assert_ne!(mainnet.contract_address, devnet.contract_address);
    assert_eq!(mainnet.decimals, devnet.decimals, "only the mint differs");
}

#[test]
fn solana_mints_are_valid_solana_addresses() {
    for cluster in [SolanaCluster::Mainnet, SolanaCluster::Devnet] {
        let mint = cluster.usdc_mint();
        assert!(
            crate::address::solana::validate(mint).is_ok(),
            "{cluster:?} mint is not a valid Solana address: {mint}"
        );
    }
}

#[test]
fn every_token_contract_is_valid_for_its_own_chain() {
    // Cross-checks the catalog against this crate's own validators, which
    // would catch a contract address pasted from the wrong chain.
    for network in networks(SolanaCluster::Mainnet) {
        for asset in catalog(network) {
            let Some(contract) = asset.contract_address.as_deref() else {
                continue;
            };
            assert!(
                crate::address::validate(network.chain(), contract).is_ok(),
                "{network} {} has an invalid contract for {}: {contract}",
                asset.symbol,
                network.chain()
            );
        }
    }
}

#[test]
fn native_assets_carry_no_contract_and_tokens_always_do() {
    for network in networks(SolanaCluster::Mainnet) {
        for asset in catalog(network) {
            if asset.native {
                assert!(
                    asset.contract_address.is_none(),
                    "{network} native {} should have no contract",
                    asset.symbol
                );
            } else {
                assert!(
                    asset.contract_address.is_some(),
                    "{network} token {} needs a contract",
                    asset.symbol
                );
            }
        }
    }
}

#[test]
fn every_network_lists_exactly_one_native_asset_first() {
    for network in networks(SolanaCluster::Mainnet) {
        let assets = catalog(network);
        assert!(!assets.is_empty(), "{network} has no assets");
        assert!(assets[0].native, "{network} native asset must be first");
        assert_eq!(
            assets.iter().filter(|a| a.native).count(),
            1,
            "{network} must have exactly one native asset"
        );
    }
}

#[test]
fn native_gas_assets_match_their_network() {
    for (network, symbol, decimals) in [
        (EvmNetwork::Ethereum, "ETH", 18),
        (EvmNetwork::Base, "ETH", 18),
        (EvmNetwork::Polygon, "POL", 18),
        (EvmNetwork::Bsc, "BNB", 18),
    ] {
        let assets = catalog(Network::Evm(network));
        assert_eq!(assets[0].symbol, symbol, "{network} native symbol");
        assert_eq!(assets[0].decimals, decimals);
    }
    assert_eq!(catalog(Network::Btc)[0].decimals, 8, "BTC is 8 decimals");
    assert_eq!(catalog(Network::Tron)[0].decimals, 6, "TRX is 6 decimals");
    assert_eq!(
        catalog(Network::Solana(SolanaCluster::Mainnet))[0].decimals,
        9,
        "SOL is 9 decimals"
    );
}

#[test]
fn find_is_case_insensitive_and_trims() {
    let network = Network::Evm(EvmNetwork::Ethereum);
    for query in ["usdc", "USDC", "  UsDc  "] {
        assert!(find(network, query).is_some(), "{query:?} should resolve");
    }
    assert!(find(network, "NOTATOKEN").is_none());
}

#[test]
fn a_token_absent_from_a_network_is_not_found_there() {
    // DAI is catalogued on Ethereum only. Returning it for Base would hand
    // back a mainnet contract address for a different network.
    assert!(find(Network::Evm(EvmNetwork::Ethereum), "DAI").is_some());
    assert!(find(Network::Evm(EvmNetwork::Base), "DAI").is_none());
}

#[test]
fn network_reports_its_chain_and_chain_id() {
    assert_eq!(Network::Btc.chain(), Chain::Btc);
    assert_eq!(Network::Tron.chain(), Chain::Tron);
    assert_eq!(
        Network::Solana(SolanaCluster::Devnet).chain(),
        Chain::Solana
    );
    assert_eq!(Network::Evm(EvmNetwork::Base).chain(), Chain::Evm);

    assert_eq!(Network::Evm(EvmNetwork::Base).chain_id(), Some(8453));
    assert_eq!(Network::Btc.chain_id(), None, "only EVM has a chain id");
}

#[test]
fn explorer_urls_end_with_the_transaction_hash() {
    let hash = "0xdeadbeef";
    for network in networks(SolanaCluster::Mainnet) {
        let url = network.explorer_tx_url(hash).unwrap();
        assert!(url.starts_with("https://"), "{network}: {url}");
        assert!(url.ends_with(hash), "{network}: {url}");
    }
}

#[test]
fn networks_are_distinct_and_cover_every_chain() {
    let all = networks(SolanaCluster::Mainnet);
    let mut seen = all.clone();
    seen.sort_by_key(std::string::ToString::to_string);
    seen.dedup();
    assert_eq!(seen.len(), all.len(), "duplicate network");

    for chain in Chain::ALL {
        assert!(
            all.iter().any(|n| n.chain() == *chain),
            "no network for {chain}"
        );
    }
}

#[test]
fn the_solana_cluster_is_a_parameter_not_a_global() {
    // Both clusters are reachable from one process without touching any
    // ambient state — the property that lets a host pick the cluster.
    let mainnet = networks(SolanaCluster::Mainnet);
    let devnet = networks(SolanaCluster::Devnet);
    assert!(mainnet.contains(&Network::Solana(SolanaCluster::Mainnet)));
    assert!(devnet.contains(&Network::Solana(SolanaCluster::Devnet)));
    assert_eq!(SolanaCluster::default(), SolanaCluster::Mainnet);
}
