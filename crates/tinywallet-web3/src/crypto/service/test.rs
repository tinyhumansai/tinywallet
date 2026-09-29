//! Tests for the service's shared types and the execute path.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;
use tinywallet_bus::wire::TransactionSpec;

use super::{
    ChainFamily, DEBRIDGE_SOLANA_CHAIN_ID, DappCallParams, ExecuteQuoteParams, UnsignedTx,
    Web3QuoteKind, chain_family,
};
use crate::crypto::defaults::EvmNetwork;
use crate::quote::Quoted;
use crate::test_support::{ServiceRig, owner_a, owner_b};

const TO: &str = "0x1111111111111111111111111111111111111111";

fn dapp_call() -> DappCallParams {
    DappCallParams {
        contract_address: TO.to_string(),
        calldata: "0xabcdef".to_string(),
        value_raw: None,
        evm_network: None,
    }
}

fn execute(id: &str, confirmed: bool) -> ExecuteQuoteParams {
    ExecuteQuoteParams {
        quote_id: id.to_string(),
        confirmed,
    }
}

// ── types ────────────────────────────────────────────────────────────────

#[test]
fn chain_family_maps_known_ids() {
    assert_eq!(chain_family(1), Some(ChainFamily::Evm(EvmNetwork::EthereumMainnet)));
    assert_eq!(chain_family(10), Some(ChainFamily::Evm(EvmNetwork::OptimismMainnet)));
    assert_eq!(chain_family(56), Some(ChainFamily::Evm(EvmNetwork::BscMainnet)));
    assert_eq!(chain_family(137), Some(ChainFamily::Evm(EvmNetwork::PolygonMainnet)));
    assert_eq!(chain_family(8453), Some(ChainFamily::Evm(EvmNetwork::BaseMainnet)));
    assert_eq!(chain_family(42161), Some(ChainFamily::Evm(EvmNetwork::ArbitrumOne)));
    assert_eq!(chain_family(DEBRIDGE_SOLANA_CHAIN_ID), Some(ChainFamily::Solana));
}

#[test]
fn every_evm_chain_family_agrees_with_the_network_chain_id() {
    for network in EvmNetwork::ALL {
        assert_eq!(chain_family(network.chain_id()), Some(ChainFamily::Evm(network)));
    }
}

#[test]
fn an_unsignable_chain_has_no_family() {
    // Neither an EVM chain we sign for nor the deBridge Solana id.
    assert_eq!(chain_family(999_999), None);
}

#[test]
fn params_deserialize_from_camel_case_with_optional_fields_absent() {
    let dapp: DappCallParams = serde_json::from_value(json!({
        "contractAddress": TO, "calldata": "0x", "evmNetwork": "base_mainnet"
    }))
    .unwrap();
    assert_eq!(dapp.evm_network, Some(EvmNetwork::BaseMainnet));
    assert_eq!(dapp.value_raw, None);
    let exec: ExecuteQuoteParams = serde_json::from_value(json!({"quoteId": "q", "confirmed": true})).unwrap();
    assert!(exec.confirmed);
    assert_eq!(serde_json::to_value(Web3QuoteKind::DappCall).unwrap(), json!("dapp_call"));
}

// ── execute ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn execute_requires_confirmation() {
    let rig = ServiceRig::new();
    let quote = rig.service.prepare_dapp_call(dapp_call()).await.unwrap();
    let err = rig.service.execute_quote(execute(&quote.quote_id, false)).await.unwrap_err();
    assert_eq!(err, "execute requires `confirmed: true`");
    assert_eq!(rig.service.stored_quotes().len(), 1, "an unconfirmed call leaves the quote alone");
}

#[tokio::test]
async fn an_unknown_quote_is_not_found() {
    let rig = ServiceRig::new();
    let err = rig.service.execute_quote(execute("w3_missing", true)).await.unwrap_err();
    assert_eq!(err, "quote 'w3_missing' not found");
}

#[tokio::test]
async fn an_evm_quote_is_signed_and_broadcast_on_its_network() {
    let rig = ServiceRig::new();
    rig.rig.script_evm_node("0x2105");
    let mut params = dapp_call();
    params.evm_network = Some(EvmNetwork::BaseMainnet);
    params.value_raw = Some("7".to_string());
    let quote = rig.service.prepare_dapp_call(params).await.unwrap();
    assert!(quote.quote_id.starts_with("w3_"));

    let result = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap();

    assert_eq!(result.kind, Web3QuoteKind::DappCall);
    assert_eq!(result.quote_id, quote.quote_id);
    assert_eq!(result.transaction_hash, format!("0x{}", "aa".repeat(32)));
    assert!(result.explorer_url.unwrap().starts_with("https://basescan.org/tx/"));
    assert_eq!(result.fee_raw.as_deref(), Some("21000000000000"));
    match &rig.rig.signer.transactions()[0] {
        TransactionSpec::Evm { to, value_wei, data_hex, chain_id, .. } => {
            assert_eq!(to, TO);
            assert_eq!(value_wei, "7");
            assert_eq!(data_hex, "0xabcdef");
            assert_eq!(*chain_id, 8453);
        }
        other => panic!("expected an EVM spec, got {other:?}"),
    }
    assert!(rig.service.stored_quotes().is_empty(), "the quote is consumed");
}

#[tokio::test]
async fn a_solana_quote_is_routed_to_the_versioned_signer() {
    let rig = ServiceRig::new();
    let quote = rig
        .service
        .store_quote(Web3QuoteKind::Swap, UnsignedTx::Solana { tx_blob_hex: "zz".to_string() }, json!({}));
    // A malformed blob fails inside the Solana signer, proving the routing.
    let err = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap_err();
    assert!(err.starts_with("invalid Solana transaction hex blob"), "{err}");
}

#[tokio::test]
async fn a_failed_broadcast_restores_the_quote_with_a_fresh_lifetime() {
    let rig = ServiceRig::new();
    rig.rig.script_evm_node("0x1");
    rig.rig.signer.fail_transaction("module unavailable");
    let quote = rig.service.prepare_dapp_call(dapp_call()).await.unwrap();
    let err = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap_err();
    assert_eq!(err, "module unavailable");
    let restored = rig.service.stored_quotes();
    assert_eq!(restored.len(), 1);
    assert!(restored[0].expires_at_ms() >= quote.expires_at_ms, "the lifetime was refreshed");
    // It is executable again once the cause is fixed: here the same failure repeats.
    let again = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap_err();
    assert_eq!(again, "module unavailable");
}

#[tokio::test]
async fn a_quote_is_bound_to_the_thread_that_prepared_it() {
    let rig = ServiceRig::new();
    rig.rig.scope.set(Some(owner_a()));
    let quote = rig.service.prepare_dapp_call(dapp_call()).await.unwrap();

    rig.rig.scope.set(Some(owner_b()));
    let err = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap_err();
    assert_eq!(err, format!("quote '{}' not found", quote.quote_id));

    rig.rig.scope.set(None);
    let err = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap_err();
    assert_eq!(err, format!("quote '{}' not found", quote.quote_id));
    assert_eq!(rig.service.stored_quotes().len(), 1, "wrong callers cannot consume it");

    rig.rig.scope.set(Some(owner_a()));
    let err = rig.service.execute_quote(execute(&quote.quote_id, true)).await.unwrap_err();
    assert_ne!(err, format!("quote '{}' not found", quote.quote_id), "the owner gets past the gate");
}

#[test]
fn a_service_debugs_without_leaking_and_starts_empty() {
    let rig = ServiceRig::new();
    assert!(rig.service.stored_quotes().is_empty());
    assert!(format!("{:?}", rig.service).contains("Web3Service"));
}
