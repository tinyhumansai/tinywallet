//! Tests for the Bitcoin chain module, driven against canned Esplora answers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::json;
use tinywallet_bus::wire::TransactionSpec;

use super::{
    EsploraUtxo, estimated_vbytes, execute_btc_quote, lookup_tx, native_balance, plan_spend,
    tx_receipt, tx_status, validate_btc_address, validate_btc_sender_address,
};
use crate::crypto::execution::{PreparedKind, PreparedStatus, TxState};
use crate::crypto::wallet::WalletChain;
use crate::test_support::{Call, Rig, prepared_quote, sample_address};

const RECIPIENT: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const TXID: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

fn utxo(txid: &str, value: u64) -> EsploraUtxo {
    EsploraUtxo {
        txid: txid.to_string(),
        vout: 0,
        value,
    }
}

fn btc_quote(amount: &str) -> crate::crypto::execution::PreparedTransaction {
    let mut quote = prepared_quote("q_btc", WalletChain::Btc, PreparedKind::NativeTransfer);
    quote.to_address = RECIPIENT.to_string();
    quote.amount_raw = amount.to_string();
    quote.asset_symbol = "BTC".to_string();
    quote
}

fn utxo_path() -> String {
    format!("address/{}/utxo", sample_address(WalletChain::Btc))
}

// ── addresses ────────────────────────────────────────────────────────────

#[test]
fn a_known_p2wpkh_address_validates() {
    assert_eq!(validate_btc_address(RECIPIENT).unwrap(), RECIPIENT);
}

#[test]
fn a_testnet_address_is_rejected_naming_the_network() {
    let err = validate_btc_address("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx").unwrap_err();
    assert!(err.contains("not on mainnet"), "got: {err}");
}

#[test]
fn a_p2tr_address_is_a_valid_recipient_but_not_a_valid_sender() {
    let p2tr = "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr";
    assert_eq!(validate_btc_address(p2tr).unwrap(), p2tr);
    let err = validate_btc_sender_address(p2tr).unwrap_err();
    assert!(err.contains("P2WPKH"), "got: {err}");
    assert!(
        err.contains("not supported as a sender"),
        "the message should name the role: {err}"
    );
}

// ── fee sizing and UTXO selection ────────────────────────────────────────

const RATE: u64 = 20;

#[test]
fn vbytes_follow_the_input_and_output_counts() {
    // 10.5 vB of overhead (rounded up), 68 vB per P2WPKH input, 31 vB per output.
    assert_eq!(estimated_vbytes(1, 2), 141, "the classic 1-in 2-out size");
    assert_eq!(estimated_vbytes(1, 1), 110);
    assert_eq!(estimated_vbytes(3, 2), 277);
    assert_eq!(estimated_vbytes(5, 1), 382);
}

#[test]
fn selection_is_largest_first_and_returns_change() {
    let utxos = vec![utxo("a", 5000), utxo("b", 10_000), utxo("c", 1_000)];
    let plan = plan_spend(&utxos, 6_000, RATE).unwrap();
    assert_eq!(plan.selected.len(), 1);
    assert_eq!(plan.selected[0].txid, "b");
    assert_eq!(plan.fee_sats, 20 * 141);
    assert_eq!(plan.change_sats, 10_000 - 6_000 - 2_820);
}

#[test]
fn a_single_input_pays_the_classic_fee() {
    let plan = plan_spend(&[utxo("a", 100_000)], 50_000, RATE).unwrap();
    assert_eq!(plan.fee_sats, 2_820);
    assert_eq!(plan.change_sats, 47_180);
}

#[test]
fn selecting_several_inputs_pays_a_larger_fee_than_one() {
    let utxos: Vec<_> = ["a", "b", "c", "d", "e"]
        .into_iter()
        .map(|id| utxo(id, 30_000))
        .collect();
    let single = plan_spend(&utxos, 20_000, RATE).unwrap();
    let multi = plan_spend(&utxos, 70_000, RATE).unwrap();
    assert_eq!(single.selected.len(), 1);
    assert_eq!(multi.selected.len(), 3);
    assert_eq!(multi.fee_sats, RATE * estimated_vbytes(3, 2));
    assert!(multi.fee_sats > single.fee_sats);
    // Everything spent is accounted for: amount, fee and change.
    assert_eq!(70_000 + multi.fee_sats + multi.change_sats, 90_000);
}

#[test]
fn selection_adds_an_input_when_the_first_cannot_cover_the_fee_it_needs() {
    // 10_000 covers the 9_000 amount but not the 1-in fee on top of it, so a
    // second input is pulled in, and the fee is sized for both.
    let plan = plan_spend(&[utxo("a", 10_000), utxo("b", 3_000)], 9_000, RATE).unwrap();
    assert_eq!(plan.selected.len(), 2);
    assert!(plan.fee_sats >= RATE * estimated_vbytes(2, 1));
    assert_eq!(9_000 + plan.fee_sats + plan.change_sats, 13_000);
}

#[test]
fn dust_change_is_dropped_and_folded_into_the_fee() {
    // The 1-in 2-out fee is 2_820. Leave 500 sats of change: below dust.
    let plan = plan_spend(&[utxo("a", 50_000)], 50_000 - 2_820 - 500, RATE).unwrap();
    assert_eq!(plan.change_sats, 0, "no change output for dust");
    assert_eq!(plan.fee_sats, 2_820 + 500, "the dust goes to the miner");
}

#[test]
fn change_is_kept_only_above_the_dust_threshold() {
    let at_dust = plan_spend(&[utxo("a", 50_000)], 50_000 - 2_820 - 546, RATE).unwrap();
    assert_eq!(at_dust.change_sats, 0, "546 sats is still dust");
    let above = plan_spend(&[utxo("a", 50_000)], 50_000 - 2_820 - 547, RATE).unwrap();
    assert_eq!(above.change_sats, 547);
    assert_eq!(above.fee_sats, 2_820);
}

#[test]
fn a_change_free_spend_that_only_covers_the_one_output_fee_is_accepted() {
    // Total covers amount + the 1-output fee (2_200) but not the 2-output fee.
    let plan = plan_spend(&[utxo("a", 50_000)], 50_000 - 2_200, RATE).unwrap();
    assert_eq!(plan.selected.len(), 1);
    assert_eq!(plan.change_sats, 0);
    assert_eq!(plan.fee_sats, 2_200);
}

#[test]
fn selection_errors_when_funds_are_insufficient() {
    let err = plan_spend(&[utxo("a", 1_000)], 5_000, RATE).unwrap_err();
    assert_eq!(
        err,
        "insufficient BTC: have 1000 sats, need 7200 (amount 5000 + fee 2200)"
    );
}

#[test]
fn the_insufficient_error_prices_every_input_it_would_need_to_spend() {
    let err = plan_spend(&[utxo("a", 3_000), utxo("b", 3_000)], 10_000, RATE).unwrap_err();
    // Two inputs, one output: 20 * 178 = 3_560.
    assert_eq!(
        err,
        "insufficient BTC: have 6000 sats, need 13560 (amount 10000 + fee 3560)"
    );
}

#[test]
fn selection_reports_overflow_rather_than_wrapping() {
    assert_eq!(
        plan_spend(&[], u64::MAX, RATE).unwrap_err(),
        "amount + fee overflow"
    );
    assert_eq!(
        plan_spend(&[], 1, u64::MAX).unwrap_err(),
        "amount + fee overflow"
    );
    // Two outputs that together exceed u64 before reaching the target.
    let half = 1u64 << 63;
    let err = plan_spend(&[utxo("a", half), utxo("b", half)], u64::MAX - 1_000, 1).unwrap_err();
    assert_eq!(err, "utxo sum overflow");
}

// ── balance ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn balance_is_confirmed_plus_mempool() {
    let rig = Rig::new();
    rig.transport.on_get(
        &format!("address/{RECIPIENT}"),
        &json!({
            "chain_stats": {"funded_txo_sum": 1000u64, "spent_txo_sum": 400u64},
            "mempool_stats": {"funded_txo_sum": 50u64, "spent_txo_sum": 70u64}
        })
        .to_string(),
    );
    // Confirmed 600; the mempool spends more than it funds, which saturates to 0.
    assert_eq!(native_balance(&rig.engine, RECIPIENT).await.unwrap(), 600);
    assert!(native_balance(&rig.engine, "nope").await.is_err());
}

// ── execute ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn execute_selects_utxos_hands_the_spec_to_the_signer_and_broadcasts() {
    let rig = Rig::new();
    rig.transport.on_get(
        &utxo_path(),
        &json!([{"txid": TXID, "vout": 0, "value": 100_000u64}]).to_string(),
    );
    rig.transport.on_post("tx", TXID);
    rig.signer.set_raw("0200000000010abc");

    let result = execute_btc_quote(&rig.engine, btc_quote("50000"))
        .await
        .unwrap();

    assert_eq!(result.status, PreparedStatus::Broadcasted);
    assert_eq!(result.transaction_hash, TXID);
    assert_eq!(result.transaction.estimated_fee_raw, (20 * 141).to_string());
    assert_eq!(
        result.explorer_url.as_deref(),
        Some(format!("https://blockstream.info/tx/{TXID}").as_str())
    );
    let specs = rig.signer.transactions();
    assert_eq!(specs.len(), 1);
    match &specs[0] {
        TransactionSpec::Btc {
            from,
            to,
            amount_sat,
            fee_sat,
            utxos,
        } => {
            assert_eq!(from, sample_address(WalletChain::Btc));
            assert_eq!(to, RECIPIENT);
            assert_eq!(*amount_sat, 50_000);
            assert_eq!(*fee_sat, 2820);
            assert_eq!(utxos.len(), 1);
            assert_eq!(utxos[0].txid, TXID);
            assert_eq!(utxos[0].value, 100_000);
        }
        other => panic!("expected a BTC spec, got {other:?}"),
    }
    // The signer's `raw` is what got broadcast, as text/plain.
    assert!(rig.transport.calls().iter().any(|c| matches!(
        c,
        Call::RestPost { path, body, content_type, .. }
            if path == "tx" && body == "0200000000010abc" && content_type == "text/plain"
    )));
}

#[tokio::test]
async fn execute_sizes_the_fee_for_every_input_it_spends() {
    let rig = Rig::new();
    let utxos: Vec<_> = (0u32..3)
        .map(|vout| json!({"txid": TXID, "vout": vout, "value": 30_000u64}))
        .collect();
    rig.transport
        .on_get(&utxo_path(), &json!(utxos).to_string());
    rig.transport.on_post("tx", TXID);

    let result = execute_btc_quote(&rig.engine, btc_quote("70000"))
        .await
        .unwrap();

    // 3 inputs and 2 outputs: 277 vB at 20 sat/vB.
    assert_eq!(result.transaction.estimated_fee_raw, "5540");
    match &rig.signer.transactions()[0] {
        TransactionSpec::Btc { fee_sat, utxos, .. } => {
            assert_eq!(*fee_sat, 5_540);
            assert_eq!(utxos.len(), 3);
        }
        other => panic!("expected a BTC spec, got {other:?}"),
    }
}

#[tokio::test]
async fn execute_hands_the_signer_the_dust_folded_fee() {
    let rig = Rig::new();
    rig.transport.on_get(
        &utxo_path(),
        &json!([{"txid": TXID, "vout": 0, "value": 50_000u64}]).to_string(),
    );
    rig.transport.on_post("tx", TXID);
    // 50_000 - 47_000 = 3_000 left, 2_820 of it fee and 180 of it dust change.
    let result = execute_btc_quote(&rig.engine, btc_quote("47000"))
        .await
        .unwrap();
    assert_eq!(result.transaction.estimated_fee_raw, "3000");
    match &rig.signer.transactions()[0] {
        TransactionSpec::Btc { fee_sat, .. } => assert_eq!(*fee_sat, 3_000),
        other => panic!("expected a BTC spec, got {other:?}"),
    }
}

#[tokio::test]
async fn execute_refuses_when_there_are_no_spendable_utxos() {
    let rig = Rig::new();
    rig.transport.on_get(&utxo_path(), "[]");
    let err = execute_btc_quote(&rig.engine, btc_quote("50000"))
        .await
        .unwrap_err();
    assert!(err.contains("no spendable UTXOs"), "got: {err}");
    assert!(rig.signer.transactions().is_empty());
}

#[tokio::test]
async fn execute_refuses_when_the_utxos_do_not_cover_amount_and_fee() {
    let rig = Rig::new();
    rig.transport.on_get(
        &utxo_path(),
        &json!([{"txid": TXID, "vout": 1, "value": 100u64}]).to_string(),
    );
    let err = execute_btc_quote(&rig.engine, btc_quote("50000"))
        .await
        .unwrap_err();
    assert!(err.contains("insufficient BTC"), "got: {err}");
}

#[tokio::test]
async fn execute_rejects_token_transfers_and_bad_amounts_and_addresses() {
    let rig = Rig::new();
    let mut token = btc_quote("1");
    token.kind = PreparedKind::TokenTransfer;
    assert_eq!(
        execute_btc_quote(&rig.engine, token).await.unwrap_err(),
        "BTC only supports native transfers; got kind TokenTransfer"
    );
    let err = execute_btc_quote(&rig.engine, btc_quote("lots"))
        .await
        .unwrap_err();
    assert!(err.starts_with("invalid BTC amount 'lots'"), "{err}");
    let mut p2tr_sender = btc_quote("1");
    p2tr_sender.from_address =
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr".to_string();
    assert!(
        execute_btc_quote(&rig.engine, p2tr_sender)
            .await
            .unwrap_err()
            .contains("P2WPKH")
    );
    let mut bad_to = btc_quote("1");
    bad_to.to_address = "nope".to_string();
    assert!(execute_btc_quote(&rig.engine, bad_to).await.is_err());
}

#[tokio::test]
async fn a_signer_failure_is_surfaced_verbatim_and_nothing_is_broadcast() {
    let rig = Rig::new();
    rig.transport.on_get(
        &utxo_path(),
        &json!([{"txid": TXID, "vout": 0, "value": 100_000u64}]).to_string(),
    );
    rig.signer
        .fail_transaction("failed to sign BTC transaction: module unavailable");
    let err = execute_btc_quote(&rig.engine, btc_quote("50000"))
        .await
        .unwrap_err();
    assert_eq!(err, "failed to sign BTC transaction: module unavailable");
    assert!(
        !rig.transport
            .calls()
            .iter()
            .any(|c| matches!(c, Call::RestPost { .. }))
    );
}

// ── reads ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_confirmed_transaction_counts_confirmations_from_the_tip() {
    let rig = Rig::new();
    rig.transport
        .on_get(
            "tx/abc/status",
            &json!({"confirmed": true, "block_height": 800_000u64}).to_string(),
        )
        .on_get("blocks/tip/height", "800002\n");
    let info = tx_status(&rig.engine, "abc").await.unwrap();
    assert_eq!(info.state, TxState::Confirmed);
    assert_eq!(info.block_number, Some(800_000));
    assert_eq!(info.confirmations, Some(3));
}

#[tokio::test]
async fn confirmations_are_unknown_when_the_tip_cannot_be_read() {
    let rig = Rig::new();
    rig.transport.on_get(
        "tx/abc/status",
        &json!({"confirmed": true, "block_height": 5u64}).to_string(),
    );
    let info = tx_status(&rig.engine, "abc").await.unwrap();
    assert_eq!(info.state, TxState::Confirmed);
    assert_eq!(info.confirmations, None);
    // A confirmed status with no height has nothing to count from.
    let rig = Rig::new();
    rig.transport
        .on_get("tx/abc/status", &json!({"confirmed": true}).to_string());
    assert_eq!(
        tx_status(&rig.engine, "abc").await.unwrap().confirmations,
        None
    );
}

#[tokio::test]
async fn an_unconfirmed_transaction_is_pending_and_a_404_is_not_found() {
    let rig = Rig::new();
    rig.transport
        .on_get("tx/mem/status", &json!({"confirmed": false}).to_string());
    rig.transport.on_get_error(
        "tx/gone/status",
        "wallet REST GET HTTP failure: status=404 Not Found body=nope",
    );
    rig.transport.on_get_error(
        "tx/boom/status",
        "wallet REST GET transport failed: refused",
    );
    let pending = tx_status(&rig.engine, "mem").await.unwrap();
    assert_eq!(pending.state, TxState::Pending);
    assert_eq!(pending.confirmations, Some(0));
    assert_eq!(
        tx_status(&rig.engine, "gone").await.unwrap().state,
        TxState::NotFound
    );
    let err = tx_status(&rig.engine, "boom").await.unwrap_err();
    assert_eq!(
        err, "wallet REST GET transport failed: refused",
        "other failures propagate"
    );
}

#[tokio::test]
async fn receipts_carry_the_fee_and_only_confirmed_ones_report_success() {
    let rig = Rig::new();
    rig.transport.on_get(
        "tx/done",
        &json!({"fee": 1234u64, "status": {"confirmed": true, "block_height": 9u64}}).to_string(),
    );
    rig.transport.on_get(
        "tx/mem",
        &json!({"fee": 10u64, "status": {"confirmed": false}}).to_string(),
    );
    rig.transport
        .on_get_error("tx/gone", "wallet REST GET HTTP failure: status=404 body=x");
    rig.transport
        .on_get_error("tx/boom", "wallet REST GET transport failed: refused");
    let done = tx_receipt(&rig.engine, "done").await.unwrap();
    assert!(done.found);
    assert_eq!(done.success, Some(true));
    assert_eq!(done.block_number, Some(9));
    assert_eq!(done.fee_raw.as_deref(), Some("1234"));
    assert_eq!(tx_receipt(&rig.engine, "mem").await.unwrap().success, None);
    assert!(!tx_receipt(&rig.engine, "gone").await.unwrap().found);
    assert!(tx_receipt(&rig.engine, "boom").await.is_err());
}

#[tokio::test]
async fn lookup_reports_found_not_found_and_propagates_other_errors() {
    let rig = Rig::new();
    rig.transport
        .on_get("tx/here", &json!({"txid": "here"}).to_string());
    rig.transport.on_get_error(
        "tx/gone",
        "wallet REST GET HTTP failure: status=404 body=Transaction not found",
    );
    rig.transport
        .on_get_error("tx/boom", "wallet REST GET transport failed: refused");
    let here = lookup_tx(&rig.engine, "here").await.unwrap();
    assert!(here.found);
    assert_eq!(here.raw["txid"], "here");
    assert!(!lookup_tx(&rig.engine, "gone").await.unwrap().found);
    assert!(lookup_tx(&rig.engine, "boom").await.is_err());
}

#[tokio::test]
async fn an_undecodable_reply_reports_the_body() {
    let rig = Rig::new();
    rig.transport.on_get("tx/junk/status", "<html>");
    let err = tx_status(&rig.engine, "junk").await.unwrap_err();
    assert!(err.starts_with("wallet REST GET decode failed:"), "{err}");
    assert!(err.ends_with("body=<html>"), "{err}");
}
