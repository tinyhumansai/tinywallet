//! Tests for quote preparation, driven against a scripted backend.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};

use super::{unsigned_from_response, value_to_string};
use crate::crypto::defaults::EvmNetwork;
use crate::crypto::service::{
    BridgeQuoteParams, ChainFamily, DappCallParams, SwapQuoteParams, UnsignedTx, Web3QuoteKind,
};
use crate::crypto::wallet::WalletChain;
use crate::quote::WALLET_NOT_CONFIGURED_MESSAGE;
use crate::test_support::{FakeWalletAccounts, ServiceRig, configured_status, sample_address};

const SOLANA: u64 = 7_565_164;

fn swap(chain_id: u64) -> SwapQuoteParams {
    SwapQuoteParams {
        chain_id,
        token_in: "0x0".to_string(),
        token_in_amount: "1".to_string(),
        token_out: "0x1".to_string(),
        token_out_recipient: None,
        sender_address: None,
        slippage: None,
    }
}

fn bridge(src: u64, dst: u64) -> BridgeQuoteParams {
    BridgeQuoteParams {
        src_chain_id: src,
        src_chain_token_in: "0x0".to_string(),
        src_chain_token_in_amount: "1".to_string(),
        dst_chain_id: dst,
        dst_chain_token_out: "0x1".to_string(),
        dst_chain_token_out_amount: None,
        dst_chain_token_out_recipient: None,
        src_chain_order_authority_address: None,
        dst_chain_order_authority_address: None,
    }
}

fn evm_tx_response() -> Value {
    json!({"estimation": {"out": 1}, "tx": {"to": "0xabc", "data": "0xdeadbeef", "value": "10"}})
}

// ── response parsing ─────────────────────────────────────────────────────

#[test]
fn a_value_may_be_a_string_a_number_or_absent() {
    assert_eq!(value_to_string(&json!({"value": "123"})), "123");
    assert_eq!(value_to_string(&json!({"value": 456})), "456");
    assert_eq!(value_to_string(&json!({})), "0");
    assert_eq!(value_to_string(&json!({"value": true})), "0");
}

#[test]
fn an_evm_response_yields_to_data_and_value() {
    let resp = json!({"tx": {"to": "0xabc", "data": "0xdeadbeef", "value": "10"}});
    match unsigned_from_response(&resp, ChainFamily::Evm(EvmNetwork::BscMainnet)).unwrap() {
        UnsignedTx::Evm { network, to, data, value } => {
            assert_eq!(network, EvmNetwork::BscMainnet);
            assert_eq!(to, "0xabc");
            assert_eq!(data.as_deref(), Some("0xdeadbeef"));
            assert_eq!(value, "10");
        }
        other @ UnsignedTx::Solana { .. } => panic!("expected EVM, got {other:?}"),
    }
    let bare = json!({"tx": {"to": "0xabc"}});
    match unsigned_from_response(&bare, ChainFamily::Evm(EvmNetwork::BaseMainnet)).unwrap() {
        UnsignedTx::Evm { data, value, .. } => {
            assert_eq!(data, None);
            assert_eq!(value, "0");
        }
        other @ UnsignedTx::Solana { .. } => panic!("expected EVM, got {other:?}"),
    }
}

#[test]
fn a_solana_response_yields_the_hex_blob() {
    match unsigned_from_response(&json!({"tx": {"data": "0011aabb"}}), ChainFamily::Solana).unwrap() {
        UnsignedTx::Solana { tx_blob_hex } => assert_eq!(tx_blob_hex, "0011aabb"),
        other @ UnsignedTx::Evm { .. } => panic!("expected Solana, got {other:?}"),
    }
}

#[test]
fn a_response_missing_its_transaction_is_reported() {
    let evm = ChainFamily::Evm(EvmNetwork::EthereumMainnet);
    let err = unsigned_from_response(&json!({"estimation": {}}), evm).unwrap_err();
    assert!(err.contains("missing unsigned"), "got: {err}");
    assert_eq!(
        unsigned_from_response(&json!({"tx": {}}), evm).unwrap_err(),
        "EVM unsigned tx missing `to`"
    );
    assert_eq!(
        unsigned_from_response(&json!({"tx": {}}), ChainFamily::Solana).unwrap_err(),
        "Solana unsigned tx missing hex `data` blob"
    );
}

// ── swap ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_swap_defaults_sender_and_recipient_to_the_wallet_and_stores_a_quote() {
    let rig = ServiceRig::new();
    rig.backend.set_swap(Ok(evm_tx_response()));
    let quote = rig.service.quote_swap(swap(1)).await.unwrap();
    assert_eq!(quote.kind, Web3QuoteKind::Swap);
    assert_eq!(quote.quote, evm_tx_response(), "the backend payload is passed through");
    assert!(quote.expires_at_ms > crate::quote::now_ms());
    let (op, body) = rig.backend.requests().remove(0);
    assert_eq!(op, "swap");
    assert_eq!(body["senderAddress"], sample_address(WalletChain::Evm));
    assert_eq!(body["tokenOutRecipient"], sample_address(WalletChain::Evm));
    assert_eq!(body["slippage"], "auto");
    assert_eq!(body["chainId"], 1);
    assert_eq!(rig.service.stored_quotes().len(), 1);
}

#[tokio::test]
async fn a_solana_swap_uses_the_solana_account_and_explicit_fields_win() {
    let rig = ServiceRig::new();
    rig.backend.set_swap(Ok(json!({"tx": {"data": "00"}})));
    let mut params = swap(SOLANA);
    params.sender_address = Some("sender".to_string());
    params.token_out_recipient = Some("recipient".to_string());
    params.slippage = Some("0.5".to_string());
    rig.service.quote_swap(params).await.unwrap();
    let body = &rig.backend.requests()[0].1;
    assert_eq!(body["senderAddress"], "sender");
    assert_eq!(body["tokenOutRecipient"], "recipient");
    assert_eq!(body["slippage"], "0.5");

    let rig = ServiceRig::new();
    rig.backend.set_swap(Ok(json!({"tx": {"data": "00"}})));
    rig.service.quote_swap(swap(SOLANA)).await.unwrap();
    assert_eq!(rig.backend.requests()[0].1["senderAddress"], sample_address(WalletChain::Solana));
}

#[tokio::test]
async fn a_swap_on_an_unsignable_chain_is_rejected_before_the_backend() {
    let rig = ServiceRig::new();
    let err = rig.service.quote_swap(swap(999_999)).await.unwrap_err();
    assert!(err.contains("not signable"), "got: {err}");
    assert!(rig.backend.requests().is_empty());
}

#[tokio::test]
async fn swap_failures_from_the_wallet_and_backend_are_surfaced() {
    let rig = ServiceRig::new();
    rig.rig.accounts.set(Ok(FakeWalletAccounts::unconfigured()));
    assert_eq!(rig.service.quote_swap(swap(1)).await.unwrap_err(), WALLET_NOT_CONFIGURED_MESSAGE);

    let mut status = configured_status();
    status.accounts.retain(|a| a.chain != WalletChain::Evm);
    rig.rig.accounts.set(Ok(status));
    assert_eq!(
        rig.service.quote_swap(swap(1)).await.unwrap_err(),
        "wallet has no derived account for the requested chain"
    );

    let rig = ServiceRig::new();
    rig.backend.set_swap(Err("web3 swap quote failed: 401".to_string()));
    assert_eq!(rig.service.quote_swap(swap(1)).await.unwrap_err(), "web3 swap quote failed: 401");

    rig.backend.set_swap(Ok(json!({"estimation": {}})));
    assert!(rig.service.quote_swap(swap(1)).await.unwrap_err().contains("missing unsigned"));
    assert!(rig.service.stored_quotes().is_empty());
}

// ── bridge ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_same_chain_bridge_is_rejected() {
    let rig = ServiceRig::new();
    let err = rig.service.quote_bridge(bridge(1, 1)).await.unwrap_err();
    assert!(err.contains("different source and destination"), "got: {err}");
    assert!(rig.backend.requests().is_empty());
}

#[tokio::test]
async fn a_bridge_defaults_each_side_to_the_wallet_account_on_that_chain() {
    let rig = ServiceRig::new();
    rig.backend.set_bridge(Ok(evm_tx_response()));
    let quote = rig.service.quote_bridge(bridge(1, SOLANA)).await.unwrap();
    assert_eq!(quote.kind, Web3QuoteKind::Bridge);
    let (op, body) = rig.backend.requests().remove(0);
    assert_eq!(op, "bridge");
    let evm = sample_address(WalletChain::Evm);
    let sol = sample_address(WalletChain::Solana);
    assert_eq!(body["srcChainOrderAuthorityAddress"], evm);
    assert_eq!(body["dstChainOrderAuthorityAddress"], sol);
    assert_eq!(body["dstChainTokenOutRecipient"], sol);
    assert_eq!(body["dstChainTokenOutAmount"], "auto");
}

#[tokio::test]
async fn a_bridge_to_a_chain_we_cannot_sign_on_falls_back_to_the_source_address() {
    let rig = ServiceRig::new();
    rig.backend.set_bridge(Ok(evm_tx_response()));
    rig.service.quote_bridge(bridge(1, 999_999)).await.unwrap();
    let body = &rig.backend.requests()[0].1;
    assert_eq!(body["dstChainTokenOutRecipient"], sample_address(WalletChain::Evm));
    assert_eq!(body["dstChainOrderAuthorityAddress"], sample_address(WalletChain::Evm));

    // Likewise when we can sign there but have no account for it.
    let rig = ServiceRig::new();
    rig.backend.set_bridge(Ok(evm_tx_response()));
    let mut status = configured_status();
    status.accounts.retain(|a| a.chain != WalletChain::Solana);
    rig.rig.accounts.set(Ok(status));
    rig.service.quote_bridge(bridge(1, SOLANA)).await.unwrap();
    assert_eq!(rig.backend.requests()[0].1["dstChainTokenOutRecipient"], sample_address(WalletChain::Evm));
}

#[tokio::test]
async fn explicit_bridge_fields_win_and_the_source_family_decides_the_unsigned_shape() {
    let rig = ServiceRig::new();
    // Source is Solana, so the unsigned transaction is a hex blob.
    rig.backend.set_bridge(Ok(json!({"tx": {"data": "0011"}})));
    let mut params = bridge(SOLANA, 1);
    params.dst_chain_token_out_amount = Some("100".to_string());
    params.dst_chain_token_out_recipient = Some("r".to_string());
    params.src_chain_order_authority_address = Some("s".to_string());
    params.dst_chain_order_authority_address = Some("d".to_string());
    rig.service.quote_bridge(params).await.unwrap();
    let body = &rig.backend.requests()[0].1;
    assert_eq!(body["dstChainTokenOutAmount"], "100");
    assert_eq!(body["dstChainTokenOutRecipient"], "r");
    assert_eq!(body["srcChainOrderAuthorityAddress"], "s");
    assert_eq!(body["dstChainOrderAuthorityAddress"], "d");
    assert!(matches!(
        &rig.service.stored_quotes()[0].unsigned,
        UnsignedTx::Solana { tx_blob_hex } if tx_blob_hex == "0011"
    ));
}

#[tokio::test]
async fn bridge_input_and_backend_failures_are_surfaced() {
    let rig = ServiceRig::new();
    let err = rig.service.quote_bridge(bridge(999_999, 1)).await.unwrap_err();
    assert_eq!(err, "source chain id 999999 is not signable by the local wallet");
    rig.backend.set_bridge(Err("web3 bridge quote failed: 500".to_string()));
    assert_eq!(rig.service.quote_bridge(bridge(1, 10)).await.unwrap_err(), "web3 bridge quote failed: 500");
}

// ── dapp calls ───────────────────────────────────────────────────────────

#[tokio::test]
async fn a_dapp_call_stores_the_calldata_and_a_summary() {
    let rig = ServiceRig::new();
    let quote = rig
        .service
        .prepare_dapp_call(DappCallParams {
            contract_address: " 0x1111111111111111111111111111111111111111 ".to_string(),
            calldata: " 0xabcd ".to_string(),
            value_raw: Some("5".to_string()),
            evm_network: Some(EvmNetwork::PolygonMainnet),
        })
        .await
        .unwrap();
    assert_eq!(quote.kind, Web3QuoteKind::DappCall);
    assert_eq!(quote.quote["type"], "dapp_call");
    assert_eq!(quote.quote["network"], "polygon_mainnet");
    assert_eq!(quote.quote["calldata"], "0xabcd");
    assert_eq!(quote.quote["valueRaw"], "5");
    assert!(matches!(
        &rig.service.stored_quotes()[0].unsigned,
        UnsignedTx::Evm { network: EvmNetwork::PolygonMainnet, data: Some(d), value, .. } if d == "0xabcd" && value == "5"
    ));
}

#[tokio::test]
async fn a_dapp_call_rejects_bad_input() {
    let rig = ServiceRig::new();
    let call = |contract: &str, calldata: &str| DappCallParams {
        contract_address: contract.to_string(),
        calldata: calldata.to_string(),
        value_raw: None,
        evm_network: None,
    };
    let to = "0x1111111111111111111111111111111111111111";
    let err = rig.service.prepare_dapp_call(call("  ", "0xabcd")).await.unwrap_err();
    assert!(err.contains("contract_address is empty"), "got: {err}");
    let err = rig.service.prepare_dapp_call(call(to, "notHex")).await.unwrap_err();
    assert!(err.contains("0x-prefixed hex"), "got: {err}");
    for bad in ["0xabc", "0xzz"] {
        assert_eq!(
            rig.service.prepare_dapp_call(call(to, bad)).await.unwrap_err(),
            "calldata must be valid even-length hex"
        );
    }
    rig.rig.accounts.set(Ok(FakeWalletAccounts::unconfigured()));
    assert_eq!(
        rig.service.prepare_dapp_call(call(to, "0xabcd")).await.unwrap_err(),
        WALLET_NOT_CONFIGURED_MESSAGE
    );
}

// ── routes and the quote store ───────────────────────────────────────────

#[tokio::test]
async fn routes_pass_the_backend_payload_through() {
    let rig = ServiceRig::new();
    rig.backend.set_routes(Ok(json!({"chains": [1, 56]})));
    assert_eq!(rig.service.routes().await.unwrap(), json!({"chains": [1, 56]}));
    rig.backend.set_routes(Err("web3 routes failed: offline".to_string()));
    assert_eq!(rig.service.routes().await.unwrap_err(), "web3 routes failed: offline");
}

#[tokio::test]
async fn stored_quotes_are_stamped_with_the_scopes_owner() {
    let rig = ServiceRig::new();
    rig.rig.scope.set(Some(crate::test_support::owner_a()));
    rig.service
        .prepare_dapp_call(DappCallParams {
            contract_address: "0x1111111111111111111111111111111111111111".to_string(),
            calldata: "0x".to_string(),
            value_raw: None,
            evm_network: None,
        })
        .await
        .unwrap();
    use crate::quote::Quoted as _;
    assert_eq!(rig.service.stored_quotes()[0].owner().cloned(), Some(crate::test_support::owner_a()));
}
