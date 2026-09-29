//! Tests for the EVM chain module, driven against canned JSON-RPC answers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tinywallet_bus::wire::TransactionSpec;

use super::{
    evm_balance, execute_evm_quote, lookup_tx, sign_and_broadcast_evm, tx_receipt, tx_status,
};
use crate::crypto::defaults::EvmNetwork;
use crate::crypto::execution::{PreparedKind, PreparedStatus, TxState};
use crate::crypto::wallet::WalletChain;
use crate::test_support::{Call, Rig, prepared_quote, sample_address};
use tinywallet_crypto::rpc::NetworkId;

const ETH: EvmNetwork = EvmNetwork::EthereumMainnet;
const TO: &str = "0x1111111111111111111111111111111111111111";

fn hash() -> String {
    format!("0x{}", "aa".repeat(32))
}

// ── reads ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_confirmed_status_counts_confirmations_from_the_head() {
    let rig = Rig::new();
    rig.transport
        .on_rpc("eth_getTransactionReceipt", json!({"status": "0x1", "blockNumber": "0x10"}))
        .on_rpc("eth_blockNumber", json!("0x12"));
    let info = tx_status(&rig.engine, ETH, "0xabc").await.unwrap();
    assert_eq!(info.state, TxState::Confirmed);
    assert_eq!(info.block_number, Some(16));
    // head 0x12 (18) - block 16 + 1 = 3 confirmations.
    assert_eq!(info.confirmations, Some(3));
}

#[tokio::test]
async fn a_reverted_receipt_is_failed_and_a_missing_status_counts_as_success() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", json!({"status": "0x0", "blockNumber": "0x1"}));
    rig.transport.on_rpc("eth_blockNumber", json!("0x1"));
    assert_eq!(tx_status(&rig.engine, ETH, "0xabc").await.unwrap().state, TxState::Failed);

    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", json!({}));
    let info = tx_status(&rig.engine, ETH, "0xabc").await.unwrap();
    assert_eq!(info.state, TxState::Confirmed);
    assert_eq!(info.block_number, None);
    assert_eq!(info.confirmations, None, "no block number, so nothing to count from");
}

#[tokio::test]
async fn no_receipt_is_pending_when_the_tx_is_known_and_not_found_otherwise() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", Value::Null);
    rig.transport.on_rpc("eth_getTransactionByHash", json!({"hash": "0xabc"}));
    assert_eq!(tx_status(&rig.engine, ETH, "0xabc").await.unwrap().state, TxState::Pending);

    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", Value::Null);
    rig.transport.on_rpc("eth_getTransactionByHash", Value::Null);
    assert_eq!(tx_status(&rig.engine, ETH, "0xabc").await.unwrap().state, TxState::NotFound);
}

#[tokio::test]
async fn a_receipt_reports_fee_gas_and_success() {
    let rig = Rig::new();
    rig.transport.on_rpc(
        "eth_getTransactionReceipt",
        json!({"status": "0x1", "blockNumber": "0x10", "gasUsed": "0x5208", "effectiveGasPrice": "0x3b9aca00"}),
    );
    let info = tx_receipt(&rig.engine, ETH, "0xabc").await.unwrap();
    assert!(info.found);
    assert_eq!(info.success, Some(true));
    assert_eq!(info.block_number, Some(16));
    assert_eq!(info.gas_used.as_deref(), Some("21000"));
    // 21000 * 1 gwei
    assert_eq!(info.fee_raw.as_deref(), Some("21000000000000"));
    assert_eq!(info.raw["status"], "0x1", "the provider payload is passed through");
}

#[tokio::test]
async fn a_receipt_without_price_data_has_no_fee() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", json!({"status": "0x1", "gasUsed": "0x5208"}));
    let info = tx_receipt(&rig.engine, ETH, "0xabc").await.unwrap();
    assert_eq!(info.fee_raw, None);
    assert_eq!(info.block_number, None);
}

#[tokio::test]
async fn a_pending_receipt_is_found_when_the_node_knows_the_tx() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", Value::Null);
    rig.transport.on_rpc("eth_getTransactionByHash", json!({"hash": "0xabc"}));
    let info = tx_receipt(&rig.engine, ETH, "0xabc").await.unwrap();
    assert!(info.found);
    assert_eq!(info.success, None);

    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionReceipt", Value::Null);
    rig.transport.on_rpc("eth_getTransactionByHash", Value::Null);
    assert!(!tx_receipt(&rig.engine, ETH, "0xabc").await.unwrap().found);
}

#[tokio::test]
async fn lookup_reports_the_found_flag() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionByHash", json!({"hash": "0xabc"}));
    assert!(lookup_tx(&rig.engine, ETH, "0xabc").await.unwrap().found);
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getTransactionByHash", Value::Null);
    assert!(!lookup_tx(&rig.engine, ETH, "0xabc").await.unwrap().found);
}

#[tokio::test]
async fn balance_parses_the_hex_wei_and_reports_a_bad_reply() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getBalance", json!("0xde0b6b3a7640000"));
    assert_eq!(evm_balance(&rig.engine, ETH, TO).await.unwrap(), 1_000_000_000_000_000_000);
    assert_eq!(
        rig.transport.first_rpc("eth_getBalance").unwrap(),
        json!([TO, "latest"])
    );

    let rig = Rig::new();
    rig.transport.on_rpc("eth_getBalance", json!(12));
    let err = evm_balance(&rig.engine, ETH, TO).await.unwrap_err();
    assert!(err.starts_with("wallet RPC invalid result for eth_getBalance:"), "{err}");
}

#[tokio::test]
async fn requests_are_routed_by_the_networks_chain_id() {
    let rig = Rig::new();
    rig.transport.on_rpc("eth_getBalance", json!("0x1"));
    evm_balance(&rig.engine, EvmNetwork::BaseMainnet, TO).await.unwrap();
    assert!(matches!(
        &rig.transport.calls()[0],
        Call::JsonRpc { network, .. } if *network == NetworkId::evm(8453)
    ));
}

// ── broadcast ────────────────────────────────────────────────────────────

#[tokio::test]
async fn sign_and_broadcast_signs_the_estimated_transaction_and_sends_it() {
    let rig = Rig::new();
    rig.script_evm_node("0x1");
    rig.signer.set_raw("0xf86c");
    let result =
        sign_and_broadcast_evm(&rig.engine, ETH, TO, Some("0xabcdef".to_string()), "0").await.unwrap();
    assert_eq!(result.transaction_hash, hash());
    assert!(result.explorer_url.unwrap().starts_with("https://etherscan.io/tx/0xaaaa"));
    // 21000 gas * 1 gwei.
    assert_eq!(result.fee_raw.as_deref(), Some("21000000000000"));
    match &rig.signer.transactions()[0] {
        TransactionSpec::Evm { to, data_hex, nonce, gas_limit, gas_price_wei, chain_id, value_wei } => {
            assert_eq!(to, TO);
            assert_eq!(data_hex, "0xabcdef");
            assert_eq!((*nonce, *gas_limit, *chain_id), (7, 21_000, 1));
            assert_eq!(gas_price_wei, "1000000000");
            assert_eq!(value_wei, "0");
        }
        other => panic!("expected an EVM spec, got {other:?}"),
    }
    // The signer's raw transaction is what was broadcast.
    assert_eq!(rig.transport.first_rpc("eth_sendRawTransaction").unwrap(), json!(["0xf86c"]));
    // The nonce is read from the pending pool so back-to-back sends do not collide.
    assert_eq!(
        rig.transport.first_rpc("eth_getTransactionCount").unwrap(),
        json!([sample_address(WalletChain::Evm), "pending"])
    );
}

#[tokio::test]
async fn sign_and_broadcast_validates_before_touching_the_node() {
    let rig = Rig::new();
    let err = sign_and_broadcast_evm(&rig.engine, ETH, TO, Some("nothex".into()), "0").await.unwrap_err();
    assert_eq!(err, "calldata must be 0x-prefixed hex");
    let err = sign_and_broadcast_evm(&rig.engine, ETH, "nope", None, "0").await.unwrap_err();
    assert!(err.starts_with("invalid EVM target address 'nope'"), "{err}");
    let err = sign_and_broadcast_evm(&rig.engine, ETH, TO, None, "lots").await.unwrap_err();
    assert!(err.starts_with("invalid native value 'lots'"), "{err}");
    assert!(rig.transport.calls().is_empty());
}

#[tokio::test]
async fn implausible_node_numbers_are_reported_not_truncated() {
    let too_big = json!("0x10000000000000000");
    for (method, needle) in [
        ("eth_getTransactionCount", "implausible nonce"),
        ("eth_estimateGas", "implausible gas limit"),
        ("eth_chainId", "implausible chain_id"),
    ] {
        let rig = Rig::new();
        for (m, ok) in [
            ("eth_chainId", json!("0x1")),
            ("eth_getTransactionCount", json!("0x7")),
            ("eth_gasPrice", json!("0x3b9aca00")),
            ("eth_estimateGas", json!("0x5208")),
        ] {
            rig.transport.on_rpc(m, if m == method { too_big.clone() } else { ok });
        }
        let err = sign_and_broadcast_evm(&rig.engine, ETH, TO, None, "0").await.unwrap_err();
        assert!(err.contains(needle), "{method}: {err}");
    }
}

#[tokio::test]
async fn a_node_error_propagates_verbatim() {
    let rig = Rig::new();
    rig.transport.on_rpc_error("eth_chainId", "wallet RPC error for eth_chainId: rate limited");
    let err = sign_and_broadcast_evm(&rig.engine, ETH, TO, None, "0").await.unwrap_err();
    assert_eq!(err, "wallet RPC error for eth_chainId: rate limited");
}

// ── quotes ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_token_quote_sends_zero_value_to_the_contract_with_calldata() {
    let rig = Rig::new();
    rig.script_evm_node("0x1");
    let mut quote = prepared_quote("q_tok", WalletChain::Evm, PreparedKind::TokenTransfer);
    quote.to_address = TO.to_string();
    quote.amount_raw = "5000000".to_string();
    quote.token_address = Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string());
    let result = execute_evm_quote(&rig.engine, quote).await.unwrap();
    assert_eq!(result.status, PreparedStatus::Broadcasted);
    assert_eq!(result.transaction.estimated_fee_raw, "21000000000000");
    match &rig.signer.transactions()[0] {
        TransactionSpec::Evm { to, value_wei, data_hex, .. } => {
            assert_eq!(to.to_lowercase(), "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48");
            assert_eq!(value_wei, "0");
            assert!(data_hex.starts_with("0xa9059cbb"));
        }
        other => panic!("expected an EVM spec, got {other:?}"),
    }
}

#[tokio::test]
async fn a_token_quote_without_a_contract_is_refused() {
    let rig = Rig::new();
    let quote = prepared_quote("q_tok", WalletChain::Evm, PreparedKind::TokenTransfer);
    assert_eq!(
        execute_evm_quote(&rig.engine, quote).await.unwrap_err(),
        "prepared token transfer is missing token_address"
    );
    let mut bad_contract = prepared_quote("q_tok", WalletChain::Evm, PreparedKind::TokenTransfer);
    bad_contract.token_address = Some("nope".to_string());
    let err = execute_evm_quote(&rig.engine, bad_contract).await.unwrap_err();
    assert!(err.starts_with("invalid ERC20 token contract address 'nope'"), "{err}");
    let mut bad_recipient = prepared_quote("q_tok", WalletChain::Evm, PreparedKind::NativeTransfer);
    bad_recipient.to_address = "nope".to_string();
    let err = execute_evm_quote(&rig.engine, bad_recipient).await.unwrap_err();
    assert!(err.starts_with("invalid EVM recipient address 'nope'"), "{err}");
}
