//! Tests for the wallet engine's read and write operations, driven against
//! canned chain answers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tinywallet_bus::wire::TransactionSpec;

use super::{
    ExecutePreparedParams, PrepareTransferParams, PreparedKind, PreparedStatus, ProviderStatus,
};
use crate::crypto::defaults::EvmNetwork;
use crate::crypto::wallet::WalletChain;
use crate::quote::WALLET_NOT_CONFIGURED_MESSAGE;
use crate::test_support::{
    FakeWalletAccounts, Rig, SignerCall, configured_status, owner_a, owner_b, prepared_quote,
    sample_address,
};

const TO_EVM: &str = "0x1111111111111111111111111111111111111111";

fn transfer(chain: WalletChain, amount: &str) -> PrepareTransferParams {
    PrepareTransferParams {
        chain,
        to_address: TO_EVM.to_string(),
        amount_raw: amount.to_string(),
        asset_symbol: None,
        evm_network: None,
    }
}

// ── reads ────────────────────────────────────────────────────────────────

#[test]
fn network_defaults_come_from_the_host_endpoints() {
    let rig = Rig::new();
    let rows = rig.engine.network_defaults();
    assert_eq!(rows.len(), EvmNetwork::ALL.len() + 3);
    assert!(rows.iter().any(|r| r.rpc_url == "https://rpc.test/solana"));
}

#[test]
fn supported_assets_lists_default_erc20s_and_l2() {
    let rig = Rig::new();
    let assets = rig.engine.supported_assets();
    assert!(
        assets
            .iter()
            .any(|a| a.symbol == "USDC" && a.evm_network == Some(EvmNetwork::BaseMainnet))
    );
    assert!(assets.iter().any(|a| a.symbol == "ETH" && a.native));
    assert!(
        assets
            .iter()
            .any(|a| a.symbol == "USDT" && a.chain == WalletChain::Tron)
    );
}

#[test]
fn the_supported_solana_usdc_follows_the_cluster() {
    let rig = Rig::new();
    rig.endpoints
        .set_cluster(crate::crypto::defaults::SolanaCluster::Devnet);
    let usdc = rig
        .engine
        .supported_assets()
        .into_iter()
        .find(|a| a.chain == WalletChain::Solana && a.symbol == "USDC")
        .unwrap();
    assert_eq!(
        usdc.contract_address.as_deref(),
        Some("4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU")
    );
}

/// Script every chain's probe endpoint to answer healthily.
fn script_healthy_chains(rig: &Rig) {
    rig.transport
        .on_rpc("eth_blockNumber", json!("0x12d687"))
        .on_rpc("getHealth", json!("ok"))
        .on_get("blocks/tip/height", "850000\n")
        .on_post(
            "wallet/getnowblock",
            &json!({"blockID": "00ab", "block_header": {}}).to_string(),
        );
}

fn row(rows: &[super::ChainStatus], chain: WalletChain) -> &super::ChainStatus {
    rows.iter().find(|r| r.chain == chain).unwrap()
}

#[tokio::test]
async fn chain_status_reports_missing_providers_without_accounts() {
    let rig = Rig::new();
    script_healthy_chains(&rig);
    let mut status = configured_status();
    status.accounts.retain(|a| a.chain != WalletChain::Btc);
    rig.accounts.set(Ok(status));
    let rows = rig.engine.chain_status().await.unwrap();
    assert_eq!(rows.len(), EvmNetwork::ALL.len() + 3);
    let btc = row(&rows, WalletChain::Btc);
    assert!(!btc.configured);
    assert_eq!(btc.provider_status, ProviderStatus::Missing);
    assert_eq!(btc.error, None, "no account is not an endpoint failure");
    let base = rows
        .iter()
        .find(|r| r.evm_network == Some(EvmNetwork::BaseMainnet))
        .unwrap();
    assert!(base.configured);
    assert_eq!(base.rpc_url, "https://rpc.test/base_mainnet");
    assert_eq!(
        row(&rows, WalletChain::Solana).provider_status,
        ProviderStatus::Ready
    );
    // A chain with no account is not probed.
    assert!(
        !rig.transport
            .calls()
            .iter()
            .any(|c| matches!(c, Call::RestGet { .. })),
        "the BTC endpoint must not be contacted without an account"
    );
}

#[tokio::test]
async fn chain_status_is_ready_only_once_every_endpoint_answers_its_probe() {
    let rig = Rig::new();
    script_healthy_chains(&rig);
    let rows = rig.engine.chain_status().await.unwrap();
    assert!(rows.iter().all(|r| r.provider_status == ProviderStatus::Ready));
    assert!(rows.iter().all(|r| r.error.is_none()), "{rows:?}");

    // One cheap call per row, on that row's own network.
    let calls = rig.transport.calls();
    for network in EvmNetwork::ALL {
        assert!(
            calls.iter().any(|c| matches!(
                c,
                Call::JsonRpc { network: n, method, .. }
                    if method == "eth_blockNumber"
                        && *n == NetworkId::evm(network.chain_id())
            )),
            "no eth_blockNumber probe for {network:?}"
        );
    }
    assert!(calls.iter().any(|c| matches!(
        c,
        Call::JsonRpc { method, .. } if method == "getHealth"
    )));
    assert!(calls.iter().any(|c| matches!(
        c,
        Call::RestGet { path, .. } if path == "blocks/tip/height"
    )));
    assert!(calls.iter().any(|c| matches!(
        c,
        Call::RestPost { path, .. } if path == "wallet/getnowblock"
    )));
}

#[tokio::test]
async fn chain_status_reports_an_unreachable_endpoint_with_its_error() {
    let rig = Rig::new();
    rig.transport
        .on_rpc("eth_blockNumber", json!("0x1"))
        .on_rpc_error("getHealth", "node is behind by 42 slots")
        .on_get_error("blocks/tip/height", "wallet REST GET transport failed: refused")
        .on_post_unreachable("wallet/getnowblock", "wallet REST POST transport failed: timeout");
    let rows = rig.engine.chain_status().await.unwrap();

    let unhealthy = [
        (WalletChain::Solana, "node is behind by 42 slots"),
        (WalletChain::Btc, "wallet REST GET transport failed: refused"),
        (WalletChain::Tron, "wallet REST POST transport failed: timeout"),
    ];
    for (chain, message) in unhealthy {
        let r = row(&rows, chain);
        assert!(r.configured, "the account is still there");
        assert_eq!(r.provider_status, ProviderStatus::Missing, "{chain:?}");
        assert_eq!(r.error.as_deref(), Some(message), "{chain:?}");
    }
    let evm: Vec<_> = rows.iter().filter(|r| r.chain == WalletChain::Evm).collect();
    assert!(evm.iter().all(|r| r.provider_status == ProviderStatus::Ready));
}

#[tokio::test]
async fn chain_status_rejects_an_answer_that_is_not_a_chain_tip() {
    let rig = Rig::new();
    script_healthy_chains(&rig);
    // Reachable, but not saying what a tip says: a stub or captive portal.
    rig.transport.on_rpc("eth_blockNumber", json!({"oops": true}));
    let rows = rig.engine.chain_status().await.unwrap();
    let evm = row(&rows, WalletChain::Evm);
    assert_eq!(evm.provider_status, ProviderStatus::Missing);
    assert!(
        evm.error.as_deref().unwrap().contains("eth_blockNumber"),
        "{evm:?}"
    );

    let rig = Rig::new();
    script_healthy_chains(&rig);
    rig.transport.on_get("blocks/tip/height", "<html>");
    rig.transport
        .on_post("wallet/getnowblock", &json!({"Error": "no block"}).to_string());
    let rows = rig.engine.chain_status().await.unwrap();
    let btc = row(&rows, WalletChain::Btc);
    assert_eq!(btc.provider_status, ProviderStatus::Missing);
    assert!(btc.error.as_deref().unwrap().contains("tip height"), "{btc:?}");
    let tron = row(&rows, WalletChain::Tron);
    assert_eq!(tron.provider_status, ProviderStatus::Missing);
    assert!(tron.error.as_deref().unwrap().contains("getnowblock"), "{tron:?}");
}

#[test]
fn a_healthy_chain_status_row_serializes_without_an_error_member() {
    let healthy = super::ChainStatus {
        chain: WalletChain::Btc,
        evm_network: None,
        configured: true,
        provider_status: ProviderStatus::Ready,
        rpc_url: "https://rpc.test/btc".to_string(),
        error: None,
    };
    assert_eq!(
        serde_json::to_value(&healthy).unwrap(),
        json!({
            "chain": "btc", "configured": true, "providerStatus": "ready",
            "rpcUrl": "https://rpc.test/btc"
        })
    );
    let failed = super::ChainStatus {
        provider_status: ProviderStatus::Missing,
        error: Some("refused".to_string()),
        ..healthy
    };
    let value = serde_json::to_value(&failed).unwrap();
    assert_eq!(value["providerStatus"], "missing");
    assert_eq!(value["error"], "refused");
}

#[tokio::test]
async fn chain_status_surfaces_a_host_failure() {
    let rig = Rig::new();
    rig.accounts.set(Err("keyring locked".to_string()));
    assert_eq!(
        rig.engine.chain_status().await.unwrap_err(),
        "keyring locked"
    );
}

#[tokio::test]
async fn balances_fan_the_evm_account_into_eth_base_and_bsc_rows() {
    let rig = Rig::new();
    // 1e18 wei on every displayed network.
    rig.transport
        .on_rpc("eth_getBalance", json!("0xde0b6b3a7640000"));
    rig.transport.on_get(
        &format!("address/{}", sample_address(WalletChain::Btc)),
        &json!({
            "chain_stats": {"funded_txo_sum": 150_000_000u64, "spent_txo_sum": 50_000_000u64},
            "mempool_stats": {"funded_txo_sum": 10u64, "spent_txo_sum": 0u64}
        })
        .to_string(),
    );
    rig.transport.on_rpc(
        "getBalance",
        json!({"context": {"slot": 1}, "value": 2_500_000_000u64}),
    );
    rig.transport.on_post(
        "wallet/getaccount",
        &json!({"balance": 3_000_000u64}).to_string(),
    );

    let rows = rig.engine.balances().await.unwrap();

    let evm: Vec<_> = rows
        .iter()
        .filter(|r| r.chain == WalletChain::Evm)
        .collect();
    assert_eq!(evm.len(), 3, "{evm:?}");
    let networks: Vec<_> = evm.iter().filter_map(|r| r.evm_network).collect();
    assert_eq!(
        networks,
        vec![
            EvmNetwork::EthereumMainnet,
            EvmNetwork::BaseMainnet,
            EvmNetwork::BscMainnet
        ]
    );
    let bnb = evm
        .iter()
        .find(|r| r.evm_network == Some(EvmNetwork::BscMainnet))
        .unwrap();
    assert_eq!(bnb.asset_symbol, "BNB");
    assert_eq!(bnb.raw, "1000000000000000000");
    assert_eq!(bnb.formatted, "1.000000000000000000");
    assert_eq!(bnb.provider_status, ProviderStatus::Ready);

    let one = |chain| rows.iter().find(|r| r.chain == chain).unwrap();
    assert_eq!(one(WalletChain::Btc).raw, "100000010");
    assert_eq!(one(WalletChain::Btc).formatted, "1.00000010");
    assert_eq!(one(WalletChain::Solana).raw, "2500000000");
    assert_eq!(one(WalletChain::Solana).formatted, "2.500000000");
    assert_eq!(one(WalletChain::Tron).raw, "3000000");
    assert_eq!(one(WalletChain::Tron).asset_symbol, "TRX");
}

#[tokio::test]
async fn a_failing_provider_yields_a_zero_missing_row_not_an_error() {
    let rig = Rig::new();
    // Nothing scripted: every chain read fails.
    let rows = rig.engine.balances().await.unwrap();
    assert_eq!(rows.len(), 3 + 3);
    for row in &rows {
        assert_eq!(row.raw, "0", "{row:?}");
        assert_eq!(row.provider_status, ProviderStatus::Missing);
    }
}

#[tokio::test]
async fn balances_need_a_configured_wallet() {
    let rig = Rig::new();
    rig.accounts.set(Ok(FakeWalletAccounts::unconfigured()));
    assert_eq!(
        rig.engine.balances().await.unwrap_err(),
        WALLET_NOT_CONFIGURED_MESSAGE
    );
}

#[tokio::test]
async fn tx_reads_reject_an_empty_hash() {
    let rig = Rig::new();
    for result in [
        rig.engine
            .tx_status(WalletChain::Evm, None, "   ")
            .await
            .map(|_| ()),
        rig.engine
            .tx_receipt(WalletChain::Evm, None, "")
            .await
            .map(|_| ()),
        rig.engine
            .lookup_tx(WalletChain::Evm, None, " ")
            .await
            .map(|_| ()),
    ] {
        assert_eq!(result.unwrap_err(), "tx hash is empty");
    }
}

#[tokio::test]
async fn tx_reads_dispatch_to_the_evm_btc_and_solana_clients() {
    let rig = Rig::new();
    rig.transport
        .on_rpc("eth_getTransactionReceipt", Value::Null);
    rig.transport
        .on_rpc("eth_getTransactionByHash", json!({"hash": "0xabc"}));
    let evm = rig
        .engine
        .tx_status(WalletChain::Evm, Some(EvmNetwork::BaseMainnet), " 0xabc ")
        .await
        .unwrap();
    assert_eq!(evm.hash, "0xabc", "the hash is trimmed");
    assert_eq!(evm.evm_network, Some(EvmNetwork::BaseMainnet));

    rig.transport.on_get(
        "tx/deadbeef/status",
        &json!({"confirmed": false}).to_string(),
    );
    let btc = rig
        .engine
        .tx_status(WalletChain::Btc, None, "deadbeef")
        .await
        .unwrap();
    assert_eq!(btc.chain, WalletChain::Btc);

    rig.transport.on_rpc(
        "getSignatureStatuses",
        json!({"context": {"slot": 0}, "value": [null]}),
    );
    let sol = rig
        .engine
        .tx_status(WalletChain::Solana, None, "sig")
        .await
        .unwrap();
    assert_eq!(sol.chain, WalletChain::Solana);
}

#[tokio::test]
async fn tx_reads_dispatch_to_the_tron_and_receipt_clients() {
    let rig = Rig::new();
    rig.transport
        .on_rpc("eth_getTransactionReceipt", Value::Null);
    rig.transport
        .on_rpc("eth_getTransactionByHash", json!({"hash": "0xabc"}));
    rig.transport
        .on_post("wallet/gettransactioninfobyid", &json!({}).to_string());
    rig.transport
        .on_post("wallet/gettransactionbyid", &json!({}).to_string());
    let tron = rig
        .engine
        .tx_receipt(WalletChain::Tron, None, "id")
        .await
        .unwrap();
    assert!(!tron.found);
    let looked = rig
        .engine
        .lookup_tx(WalletChain::Tron, None, "id")
        .await
        .unwrap();
    assert!(!looked.found);

    rig.transport.on_rpc("getTransaction", Value::Null);
    let receipt = rig
        .engine
        .tx_receipt(WalletChain::Solana, None, "sig")
        .await
        .unwrap();
    assert!(!receipt.found);
    let raw = rig
        .engine
        .lookup_tx(WalletChain::Solana, None, "sig")
        .await
        .unwrap();
    assert!(!raw.found);

    rig.transport
        .on_get("tx/deadbeef", &json!({"txid": "deadbeef"}).to_string());
    let btc_lookup = rig
        .engine
        .lookup_tx(WalletChain::Btc, None, "deadbeef")
        .await
        .unwrap();
    assert!(btc_lookup.found);
    let btc_receipt = rig
        .engine
        .tx_receipt(WalletChain::Btc, None, "deadbeef")
        .await
        .unwrap();
    assert!(btc_receipt.found);

    let evm_receipt = rig
        .engine
        .tx_receipt(WalletChain::Evm, None, "0xabc")
        .await
        .unwrap();
    assert!(evm_receipt.found);
    let evm_lookup = rig
        .engine
        .lookup_tx(WalletChain::Evm, None, "0xabc")
        .await
        .unwrap();
    assert!(evm_lookup.found);
}

// ── prepare ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn prepare_transfer_stamps_a_quote_from_the_wallet_account() {
    let rig = Rig::new();
    let quote = rig
        .engine
        .prepare_transfer(transfer(WalletChain::Evm, "1000"))
        .await
        .unwrap();
    assert_eq!(quote.kind, PreparedKind::NativeTransfer);
    assert_eq!(quote.from_address, sample_address(WalletChain::Evm));
    assert_eq!(quote.to_address, TO_EVM);
    assert_eq!(quote.asset_symbol, "ETH");
    assert_eq!(quote.amount_formatted, "0.000000000000001000");
    assert_eq!(quote.evm_network, Some(EvmNetwork::EthereumMainnet));
    assert_eq!(quote.status, PreparedStatus::AwaitingConfirmation);
    assert!(quote.quote_id.starts_with("q_"));
    assert!(quote.expires_at_ms > quote.created_at_ms);
    assert!(
        quote.notes[0].contains("ethereum-mainnet"),
        "{:?}",
        quote.notes
    );
    assert_eq!(rig.engine.prepared_quotes().len(), 1);
    // The owner gate data never leaves the process.
    let wire = serde_json::to_value(&quote).unwrap();
    assert!(wire.get("owner").is_none());
    assert_eq!(wire["quoteId"], json!(quote.quote_id));
}

#[tokio::test]
async fn prepare_transfer_picks_token_assets_and_networks() {
    let rig = Rig::new();
    let mut params = transfer(WalletChain::Evm, "5000000");
    params.asset_symbol = Some(" usdc ".to_string());
    params.evm_network = Some(EvmNetwork::BaseMainnet);
    let quote = rig.engine.prepare_transfer(params).await.unwrap();
    assert_eq!(quote.kind, PreparedKind::TokenTransfer);
    assert_eq!(
        quote.token_address.as_deref(),
        Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
    );
    assert_eq!(quote.evm_network, Some(EvmNetwork::BaseMainnet));
    assert_eq!(quote.estimated_fee_raw, "1950000000000000");
}

#[tokio::test]
async fn prepare_transfer_rejects_bad_input() {
    let rig = Rig::new();
    let mut unknown = transfer(WalletChain::Evm, "1");
    unknown.asset_symbol = Some("NOPE".to_string());
    assert_eq!(
        rig.engine.prepare_transfer(unknown).await.unwrap_err(),
        "unsupported asset_symbol 'NOPE' for chain 'evm'"
    );
    assert_eq!(
        rig.engine
            .prepare_transfer(transfer(WalletChain::Evm, "0"))
            .await
            .unwrap_err(),
        "transfer amount must be greater than zero"
    );
    assert!(
        rig.engine
            .prepare_transfer(transfer(WalletChain::Evm, "x"))
            .await
            .is_err()
    );
    let mut bad_address = transfer(WalletChain::Evm, "1");
    bad_address.to_address = "nope".to_string();
    assert!(rig.engine.prepare_transfer(bad_address).await.is_err());
    assert!(rig.engine.prepared_quotes().is_empty());
}

#[tokio::test]
async fn prepare_transfer_needs_an_account_for_the_chain() {
    let rig = Rig::new();
    rig.accounts.set(Ok(FakeWalletAccounts::unconfigured()));
    assert_eq!(
        rig.engine
            .prepare_transfer(transfer(WalletChain::Evm, "1"))
            .await
            .unwrap_err(),
        WALLET_NOT_CONFIGURED_MESSAGE
    );
    let mut status = configured_status();
    status.accounts.retain(|a| a.chain != WalletChain::Evm);
    rig.accounts.set(Ok(status));
    assert_eq!(
        rig.engine
            .prepare_transfer(transfer(WalletChain::Evm, "1"))
            .await
            .unwrap_err(),
        "no wallet account derived for chain 'evm'"
    );
}

#[tokio::test]
async fn prepare_transfer_rejects_token_transfers_on_bitcoin() {
    // Bitcoin's catalogue holds only the native asset, so a symbol other than
    // BTC is unknown; the explicit guard is the belt to that pair of braces.
    let rig = Rig::new();
    let mut params = transfer(WalletChain::Btc, "1");
    params.to_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
    params.asset_symbol = Some("USDT".to_string());
    assert!(
        rig.engine
            .prepare_transfer(params)
            .await
            .unwrap_err()
            .contains("unsupported asset_symbol")
    );
    let mut native = transfer(WalletChain::Btc, "5000");
    native.to_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
    let quote = rig.engine.prepare_transfer(native).await.unwrap();
    assert_eq!(quote.evm_network, None);
    assert!(quote.notes[0].contains("on btc using"), "{:?}", quote.notes);
}

#[tokio::test]
async fn prepare_stamps_the_owner_the_scope_reports() {
    let rig = Rig::new();
    rig.scope.set(Some(owner_a()));
    let quote = rig
        .engine
        .prepare_transfer(transfer(WalletChain::Evm, "1000"))
        .await
        .unwrap();
    assert_eq!(quote.owner, Some(owner_a()));
}

// ── execute ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn execute_requires_the_confirmed_flag() {
    let rig = Rig::new();
    let err = rig
        .engine
        .execute_prepared(ExecutePreparedParams {
            quote_id: "missing".into(),
            confirmed: false,
        })
        .await
        .unwrap_err();
    assert!(err.contains("confirmed: true"), "{err}");
}

#[tokio::test]
async fn execute_broadcasts_a_native_evm_transfer_through_the_signer() {
    let rig = Rig::new();
    rig.script_evm_node("0x1");
    let quote = rig
        .engine
        .prepare_transfer(transfer(WalletChain::Evm, "1000"))
        .await
        .unwrap();
    let executed = rig
        .engine
        .execute_prepared(ExecutePreparedParams {
            quote_id: quote.quote_id.clone(),
            confirmed: true,
        })
        .await
        .unwrap();
    assert_eq!(executed.status, PreparedStatus::Broadcasted);
    assert_eq!(executed.transaction_hash, format!("0x{}", "aa".repeat(32)));
    assert_eq!(
        executed.explorer_url.as_deref(),
        Some(format!("https://etherscan.io/tx/0x{}", "aa".repeat(32)).as_str())
    );
    let estimate = rig.transport.first_rpc("eth_estimateGas").unwrap();
    assert_eq!(estimate[0]["to"], TO_EVM);
    let specs = rig.signer.transactions();
    assert_eq!(specs.len(), 1);
    assert!(
        matches!(&specs[0], TransactionSpec::Evm { to, value_wei, chain_id: 1, .. } if to == TO_EVM && value_wei == "1000")
    );
    assert!(
        rig.engine.prepared_quotes().is_empty(),
        "the quote is consumed"
    );
}

#[tokio::test]
async fn a_failed_execute_restores_the_quote_so_it_can_be_retried() {
    let rig = Rig::new();
    rig.script_evm_node("0x1");
    rig.signer.fail_transaction("module unavailable");
    let quote = rig
        .engine
        .prepare_transfer(transfer(WalletChain::Evm, "1000"))
        .await
        .unwrap();
    let params = || ExecutePreparedParams {
        quote_id: quote.quote_id.clone(),
        confirmed: true,
    };
    assert_eq!(
        rig.engine.execute_prepared(params()).await.unwrap_err(),
        "module unavailable"
    );
    assert_eq!(rig.engine.prepared_quotes().len(), 1, "restored");
    // The restored quote is retryable, and fails again for the same cause.
    rig.signer.fail_transaction("still down");
    assert_eq!(
        rig.engine.execute_prepared(params()).await.unwrap_err(),
        "still down"
    );
    assert_eq!(rig.engine.prepared_quotes().len(), 1);
}

#[tokio::test]
async fn execute_dispatches_each_chain_to_its_executor() {
    // BTC with no UTXOs: the executor ran, and said so.
    let rig = Rig::new();
    rig.transport.on_get(
        &format!("address/{}/utxo", sample_address(WalletChain::Btc)),
        "[]",
    );
    let mut btc = prepared_quote("q_btc", WalletChain::Btc, PreparedKind::NativeTransfer);
    btc.to_address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string();
    btc.amount_raw = "50000".to_string();
    rig.engine.quotes.insert(btc);
    let err = rig
        .engine
        .execute_prepared(ExecutePreparedParams {
            quote_id: "q_btc".into(),
            confirmed: true,
        })
        .await
        .unwrap_err();
    assert!(err.contains("no spendable UTXOs"), "{err}");

    // Solana: derive succeeds, blockhash read fails (nothing scripted).
    let mut sol = prepared_quote("q_sol", WalletChain::Solana, PreparedKind::NativeTransfer);
    sol.to_address = "Vote111111111111111111111111111111111111111".to_string();
    rig.engine.quotes.insert(sol);
    assert!(
        rig.engine
            .execute_prepared(ExecutePreparedParams {
                quote_id: "q_sol".into(),
                confirmed: true
            })
            .await
            .is_err()
    );
    assert!(
        rig.signer
            .calls()
            .contains(&SignerCall::Derive(WalletChain::Solana))
    );

    // Tron: the signer derives the account first.
    let mut tron = prepared_quote("q_tron", WalletChain::Tron, PreparedKind::NativeTransfer);
    tron.to_address = "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH".to_string();
    rig.engine.quotes.insert(tron);
    assert!(
        rig.engine
            .execute_prepared(ExecutePreparedParams {
                quote_id: "q_tron".into(),
                confirmed: true
            })
            .await
            .is_err()
    );
    assert!(
        rig.signer
            .calls()
            .contains(&SignerCall::Derive(WalletChain::Tron))
    );
}

#[tokio::test]
async fn cross_owner_execution_is_indistinguishable_from_not_found() {
    let rig = Rig::new();
    rig.engine.quotes.insert({
        let mut q = prepared_quote("q_x", WalletChain::Evm, PreparedKind::NativeTransfer);
        q.owner = Some(owner_a());
        q
    });
    let params = |id: &str| ExecutePreparedParams {
        quote_id: id.to_string(),
        confirmed: true,
    };

    rig.scope.set(Some(owner_b()));
    let mismatch = rig
        .engine
        .execute_prepared(params("q_x"))
        .await
        .unwrap_err();
    let missing = rig
        .engine
        .execute_prepared(params("q_nope"))
        .await
        .unwrap_err();
    assert_eq!(mismatch, "quote 'q_x' not found");
    assert_eq!(missing, "quote 'q_nope' not found");
    assert_eq!(
        rig.engine.prepared_quotes().len(),
        1,
        "a mismatched caller cannot poison the store"
    );

    // A caller with no chat context cannot pick up a chat quote either.
    rig.scope.set(None);
    assert_eq!(
        rig.engine
            .execute_prepared(params("q_x"))
            .await
            .unwrap_err(),
        "quote 'q_x' not found"
    );

    // The owner gets past the gate; what fails afterwards is the chain, not the oracle.
    rig.scope.set(Some(owner_a()));
    let err = rig
        .engine
        .execute_prepared(params("q_x"))
        .await
        .unwrap_err();
    assert_ne!(err, "quote 'q_x' not found");
}

#[tokio::test]
async fn a_no_context_flow_executes_a_no_context_quote() {
    let rig = Rig::new();
    rig.engine.quotes.insert(prepared_quote(
        "q_bg",
        WalletChain::Evm,
        PreparedKind::NativeTransfer,
    ));
    let err = rig
        .engine
        .execute_prepared(ExecutePreparedParams {
            quote_id: "q_bg".into(),
            confirmed: true,
        })
        .await
        .unwrap_err();
    assert_ne!(err, "quote 'q_bg' not found", "the owner gate passed");
}

#[tokio::test]
async fn the_evm_chain_id_must_match_the_quoted_network() {
    let rig = Rig::new();
    // The quote says Base (8453), the node answers Ethereum (1).
    rig.script_evm_node("0x1");
    let mut params = transfer(WalletChain::Evm, "1000");
    params.evm_network = Some(EvmNetwork::BaseMainnet);
    let quote = rig.engine.prepare_transfer(params).await.unwrap();
    let err = rig
        .engine
        .execute_prepared(ExecutePreparedParams {
            quote_id: quote.quote_id,
            confirmed: true,
        })
        .await
        .unwrap_err();
    assert!(err.contains("chain_id mismatch"), "{err}");
    assert!(
        rig.signer.transactions().is_empty(),
        "nothing was signed for the wrong chain"
    );
}

#[tokio::test]
async fn an_erc20_transfer_pays_the_contract_zero_with_the_recipient_in_calldata() {
    let rig = Rig::new();
    rig.script_evm_node("0x1");
    let mut params = transfer(WalletChain::Evm, "5000000");
    params.asset_symbol = Some("USDC".to_string());
    let quote = rig.engine.prepare_transfer(params).await.unwrap();
    rig.engine
        .execute_prepared(ExecutePreparedParams {
            quote_id: quote.quote_id,
            confirmed: true,
        })
        .await
        .unwrap();
    let estimate = rig.transport.first_rpc("eth_estimateGas").unwrap();
    assert_eq!(
        estimate[0]["to"].as_str().unwrap().to_lowercase(),
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    );
    assert!(
        estimate[0]["data"]
            .as_str()
            .unwrap()
            .starts_with("0xa9059cbb")
    );
    match &rig.signer.transactions()[0] {
        TransactionSpec::Evm {
            value_wei,
            data_hex,
            ..
        } => {
            assert_eq!(value_wei, "0");
            assert!(data_hex.starts_with("0xa9059cbb"));
        }
        other => panic!("expected an EVM spec, got {other:?}"),
    }
}
