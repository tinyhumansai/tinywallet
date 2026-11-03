//! Unit tests for the [`Chain`](super::Chain) enum.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::str::FromStr;

use super::{Chain, UnknownChain};

#[cfg(feature = "wire")]
use crate::wire::{EvmNetwork, RpcEndpointKey};

#[test]
fn as_str_round_trips_through_from_str() {
    for chain in Chain::ALL {
        assert_eq!(Chain::from_str(chain.as_str()).unwrap(), *chain);
    }
}

#[test]
fn display_matches_as_str() {
    for chain in Chain::ALL {
        assert_eq!(chain.to_string(), chain.as_str());
    }
}

#[test]
fn all_contains_no_duplicates() {
    let mut seen = Chain::ALL.to_vec();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), Chain::ALL.len());
}

#[test]
fn parsing_is_case_and_whitespace_insensitive() {
    assert_eq!(Chain::from_str("  BTC \n").unwrap(), Chain::Btc);
    assert_eq!(Chain::from_str("SoLaNa").unwrap(), Chain::Solana);
}

#[test]
fn common_aliases_parse() {
    // These are the spellings that turn up in user-facing config.
    for (input, expected) in [
        ("bitcoin", Chain::Btc),
        ("eth", Chain::Evm),
        ("ethereum", Chain::Evm),
        ("sol", Chain::Solana),
        ("trx", Chain::Tron),
    ] {
        assert_eq!(Chain::from_str(input).unwrap(), expected, "alias {input}");
    }
}

#[test]
fn an_unknown_name_is_reported_with_the_input() {
    assert_eq!(
        Chain::from_str("dogecoin").unwrap_err(),
        UnknownChain("dogecoin".to_string())
    );
}

#[cfg(feature = "wire")]
#[test]
fn endpoint_keys_cover_known_chains_and_reject_unknown_evm_ids() {
    for network in EvmNetwork::ALL {
        assert_eq!(
            super::endpoint_key(Chain::Evm, Some(network.chain_id())),
            Some(RpcEndpointKey::Evm { network })
        );
    }
    assert_eq!(super::endpoint_key(Chain::Evm, None), None);
    assert_eq!(super::endpoint_key(Chain::Evm, Some(u64::MAX)), None);
    assert_eq!(
        super::endpoint_key(Chain::Btc, Some(u64::MAX)),
        Some(RpcEndpointKey::Btc)
    );
    assert_eq!(
        super::endpoint_key(Chain::Solana, None),
        Some(RpcEndpointKey::Solana)
    );
    assert_eq!(
        super::endpoint_key(Chain::Tron, None),
        Some(RpcEndpointKey::Tron)
    );
}
