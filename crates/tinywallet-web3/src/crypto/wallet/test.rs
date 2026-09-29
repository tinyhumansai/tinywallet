//! Tests for the wallet vocabulary and the engine's plumbing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;
use tinywallet_crypto::Chain;
use tinywallet_crypto::rpc::{NetworkId, TransportError};

use super::{WalletChain, WalletEngine, WalletSeams, transport_message};
use crate::crypto::defaults::EvmNetwork;
use crate::test_support::{Rig, configured_status};

#[test]
fn chains_serialize_as_snake_case_and_map_onto_the_crypto_chain() {
    assert_eq!(serde_json::to_value(WalletChain::Solana).unwrap(), json!("solana"));
    let parsed: WalletChain = serde_json::from_value(json!("tron")).unwrap();
    assert_eq!(parsed, WalletChain::Tron);
    for chain in WalletChain::ALL {
        assert_eq!(chain.as_str(), chain.to_chain().as_str());
    }
    assert_eq!(WalletChain::Evm.to_chain(), Chain::Evm);
    assert_eq!(WalletChain::Btc.to_chain(), Chain::Btc);
}

#[test]
fn status_serializes_camel_case_and_skips_absent_fields() {
    let mut status = configured_status();
    status.source = None;
    status.updated_at_ms = None;
    let value = serde_json::to_value(&status).unwrap();
    assert_eq!(value["onboardingCompleted"], true);
    assert_eq!(value["accounts"][0]["derivationPath"], "m/44'/60'/0'/0/0");
    assert!(value.get("source").is_none());
    assert!(value.get("updatedAtMs").is_none());
}

#[test]
fn network_ids_pick_the_evm_chain_id_or_the_bare_chain() {
    assert_eq!(
        WalletEngine::network_id(WalletChain::Evm, Some(EvmNetwork::BaseMainnet)),
        NetworkId::evm(8453)
    );
    assert_eq!(
        WalletEngine::network_id(WalletChain::Evm, None),
        NetworkId::evm(1),
        "EVM with no network means Ethereum mainnet"
    );
    assert_eq!(
        WalletEngine::network_id(WalletChain::Btc, Some(EvmNetwork::BaseMainnet)),
        NetworkId::chain(Chain::Btc),
        "a network is only meaningful for EVM"
    );
}

#[test]
fn transport_messages_pass_through_without_the_network_prefix() {
    let network = NetworkId::chain(Chain::Btc);
    let unreachable = TransportError::Unreachable {
        network,
        message: "wallet REST GET transport failed: refused".to_string(),
    };
    let rpc = TransportError::Rpc {
        network,
        message: "wallet REST GET HTTP failure: status=404 body=nope".to_string(),
    };
    assert_eq!(transport_message(unreachable), "wallet REST GET transport failed: refused");
    assert_eq!(transport_message(rpc), "wallet REST GET HTTP failure: status=404 body=nope");
}

#[test]
fn an_engine_starts_with_no_quotes_and_debugs_without_leaking() {
    let rig = Rig::new();
    assert!(rig.engine.prepared_quotes().is_empty());
    let debug = format!("{:?}", rig.engine);
    assert!(debug.contains("WalletEngine"), "{debug}");
    let seams = WalletSeams {
        transport: rig.transport.clone(),
        endpoints: rig.endpoints.clone(),
        signer: rig.signer.clone(),
        accounts: rig.accounts.clone(),
        scope: rig.scope.clone(),
    };
    assert!(format!("{seams:?}").contains("WalletSeams"));
}
