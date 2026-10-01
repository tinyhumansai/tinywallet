//! Tests for the Tron chain module: the node-built transaction is verified
//! before the signer sees it, and the canned `TronGrid` answers are built with
//! the same protobuf the real node speaks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Value, json};
use tinywallet_bus::wire::TransactionSpec;
use tinywallet_crypto::TronTransfer;
use tinywallet_crypto::tx::proto::encode_varint;
use tinywallet_crypto::tx::tron::recompute_txid;

use super::{
    CreateTransactionResponse, TRC20_FEE_LIMIT_SUN, encode_trc20_transfer_param,
    execute_tron_quote, lookup_tx, native_balance, pad_left_32, tron_address_to_hex,
    tron_transaction_spec, tx_receipt, tx_status, validate_tron_address,
};
use crate::crypto::execution::{PreparedKind, PreparedStatus, TxState};
use crate::crypto::wallet::WalletChain;
use crate::test_support::{Call, Rig, SignerCall, prepared_quote, sample_address};

const RECIPIENT: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
const CONTRACT: &str = "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH";

// ── protobuf builders for canned node answers ────────────────────────────

fn push_varint_field(out: &mut Vec<u8>, number: u64, value: u64) {
    out.extend(encode_varint(number << 3));
    out.extend(encode_varint(value));
}

fn push_bytes_field(out: &mut Vec<u8>, number: u64, value: &[u8]) {
    out.extend(encode_varint((number << 3) | 2));
    out.extend(encode_varint(value.len() as u64));
    out.extend(value);
}

fn tron_raw_contract(kind: u64, type_name: &str, payload: &[u8]) -> String {
    let mut any = Vec::new();
    push_bytes_field(
        &mut any,
        1,
        format!("type.googleapis.com/protocol.{type_name}").as_bytes(),
    );
    push_bytes_field(&mut any, 2, payload);
    let mut contract = Vec::new();
    push_varint_field(&mut contract, 1, kind);
    push_bytes_field(&mut contract, 2, &any);
    let mut raw = Vec::new();
    push_bytes_field(&mut raw, 11, &contract);
    hex::encode(raw)
}

fn native_raw(recipient_hex: &str, amount: u64) -> String {
    let mut payload = Vec::new();
    push_bytes_field(&mut payload, 2, &hex::decode(recipient_hex).unwrap());
    push_varint_field(&mut payload, 3, amount);
    tron_raw_contract(1, "TransferContract", &payload)
}

fn trc20_raw_with_values(
    contract_hex: &str,
    parameter_hex: &str,
    call_value: Option<u64>,
    fee_limit: Option<u64>,
) -> String {
    let mut payload = Vec::new();
    push_bytes_field(&mut payload, 2, &hex::decode(contract_hex).unwrap());
    if let Some(call_value) = call_value {
        push_varint_field(&mut payload, 3, call_value);
    }
    let mut data = hex::decode("a9059cbb").unwrap();
    data.extend(hex::decode(parameter_hex).unwrap());
    push_bytes_field(&mut payload, 4, &data);
    let mut raw = hex::decode(tron_raw_contract(31, "TriggerSmartContract", &payload)).unwrap();
    if let Some(fee_limit) = fee_limit {
        push_varint_field(&mut raw, 18, fee_limit);
    }
    hex::encode(raw)
}

fn trc20_raw(contract_hex: &str, parameter_hex: &str) -> String {
    trc20_raw_with_values(
        contract_hex,
        parameter_hex,
        Some(0),
        Some(TRC20_FEE_LIMIT_SUN),
    )
}

fn created(raw: &str) -> Value {
    json!({"txID": recompute_txid(raw).unwrap(), "raw_data": {"contract": []}, "raw_data_hex": raw})
}

fn tron_quote(kind: PreparedKind) -> crate::crypto::execution::PreparedTransaction {
    let mut quote = prepared_quote("q_tron", WalletChain::Tron, kind);
    quote.to_address = RECIPIENT.to_string();
    quote.amount_raw = "1000000".to_string();
    if kind == PreparedKind::TokenTransfer {
        quote.token_address = Some(RECIPIENT.to_string());
        quote.amount_raw = "5000000".to_string();
    }
    quote
}

/// Script the node so a native transfer for `quote` builds, and the broadcast
/// succeeds.
fn script_native(rig: &Rig, amount: u64) {
    let raw = native_raw(&tron_address_to_hex(RECIPIENT).unwrap(), amount);
    rig.transport
        .on_post("wallet/createtransaction", &created(&raw).to_string());
    rig.transport.on_post(
        "wallet/broadcasttransaction",
        &json!({"result": true, "txid": "ab".repeat(32)}).to_string(),
    );
}

// ── addresses and encoding ───────────────────────────────────────────────

#[test]
fn a_known_address_validates_and_a_btc_address_does_not() {
    assert_eq!(validate_tron_address(RECIPIENT).unwrap(), RECIPIENT);
    let err = validate_tron_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap_err();
    assert!(err.contains("invalid"), "got: {err}");
}

#[test]
fn hex_addresses_carry_the_41_prefix() {
    let h = tron_address_to_hex(RECIPIENT).unwrap();
    assert!(h.starts_with("41"), "expected the 0x41 prefix, got: {h}");
    assert_eq!(h.len(), 42);
}

#[test]
fn a_decoded_address_of_the_wrong_length_is_not_accepted() {
    // A valid base58check payload with the Tron prefix but only 20 bytes.
    let short = bs58::encode([0x41; 20]).with_check().into_string();
    assert!(tron_address_to_hex(&short).is_err());
}

#[test]
fn the_trc20_parameter_pads_the_address_and_the_amount() {
    let to_hex = tron_address_to_hex(RECIPIENT).unwrap();
    let param = encode_trc20_transfer_param(&to_hex, 12345).unwrap();
    assert_eq!(param.len(), 128, "two 32-byte words, hex-encoded");
    assert!(
        param.starts_with("000000000000000000000000"),
        "12-byte zero padding: {param}"
    );
    assert!(param.ends_with("00003039"), "12345 = 0x3039: {param}");
    assert!(
        encode_trc20_transfer_param("zz", 1)
            .unwrap_err()
            .starts_with("invalid hex addr")
    );
    assert_eq!(
        encode_trc20_transfer_param("41aa", 1).unwrap_err(),
        "expected 21-byte Tron address, got 2"
    );
}

#[test]
fn padding_left_extends_short_input_and_truncates_long_input() {
    let p = pad_left_32(&[1, 2, 3]);
    assert_eq!(p.len(), 32);
    assert_eq!(&p[..29], &[0u8; 29]);
    assert_eq!(&p[29..], &[1, 2, 3]);
    let long: Vec<u8> = (0..40).collect();
    assert_eq!(pad_left_32(&long), long[8..].to_vec());
}

// ── verification of the node-built transaction ───────────────────────────

#[test]
fn specs_bind_native_and_trc20_verification_fields() {
    let recipient_hex = tron_address_to_hex(RECIPIENT).unwrap();
    let contract_hex = tron_address_to_hex(CONTRACT).unwrap();

    let native_raw_hex = native_raw(&recipient_hex, 1_000_000);
    let native_txid = recompute_txid(&native_raw_hex).unwrap();
    let native_tx = CreateTransactionResponse {
        tx_id: native_txid.clone(),
        raw_data: json!({}),
        raw_data_hex: native_raw_hex.clone(),
    };
    let native = tron_transaction_spec(
        &native_tx,
        RECIPIENT.to_string(),
        &TronTransfer::Native {
            amount_sun: 1_000_000,
        },
    )
    .unwrap();
    assert_eq!(
        native,
        TransactionSpec::Tron {
            raw_data_hex: native_raw_hex,
            expected_to: RECIPIENT.to_string(),
            expected_txid: native_txid,
            // Carried through so the signer re-verifies it against the bytes
            // rather than trusting this side's check.
            transfer: TronTransfer::Native {
                amount_sun: 1_000_000
            },
        }
    );

    let parameter = "01".repeat(64);
    let token_raw = trc20_raw(&contract_hex, &parameter);
    let token_txid = recompute_txid(&token_raw).unwrap();
    let token_tx = CreateTransactionResponse {
        tx_id: token_txid.clone(),
        raw_data: json!({}),
        raw_data_hex: token_raw.clone(),
    };
    let transfer = TronTransfer::Trc20 {
        parameter_hex: parameter.clone(),
    };
    let token = tron_transaction_spec(&token_tx, CONTRACT.to_string(), &transfer).unwrap();
    assert_eq!(
        token,
        TransactionSpec::Tron {
            raw_data_hex: token_raw,
            expected_to: CONTRACT.to_string(),
            expected_txid: token_txid,
            transfer,
        }
    );

    assert!(
        tron_transaction_spec(
            &native_tx,
            RECIPIENT.to_string(),
            &TronTransfer::Native { amount_sun: 2 }
        )
        .unwrap_err()
        .contains("different native amount")
    );
    assert!(
        tron_transaction_spec(
            &token_tx,
            CONTRACT.to_string(),
            &TronTransfer::Trc20 {
                parameter_hex: "02".repeat(64)
            },
        )
        .unwrap_err()
        .contains("different TRC20 transfer data")
    );
}

#[test]
fn a_node_that_alters_call_value_or_fee_limit_is_rejected() {
    let contract_hex = tron_address_to_hex(CONTRACT).unwrap();
    let parameter = "01".repeat(64);
    for (raw_data_hex, expected_error) in [
        (
            trc20_raw_with_values(
                &contract_hex,
                &parameter,
                Some(1),
                Some(TRC20_FEE_LIMIT_SUN),
            ),
            "non-zero TRC20 call_value",
        ),
        (
            trc20_raw_with_values(
                &contract_hex,
                &parameter,
                Some(0),
                Some(TRC20_FEE_LIMIT_SUN + 1),
            ),
            "different fee_limit",
        ),
    ] {
        let altered = CreateTransactionResponse {
            tx_id: recompute_txid(&raw_data_hex).unwrap(),
            raw_data: json!({}),
            raw_data_hex,
        };
        let error = tron_transaction_spec(
            &altered,
            CONTRACT.to_string(),
            &TronTransfer::Trc20 {
                parameter_hex: parameter.clone(),
            },
        )
        .unwrap_err();
        assert!(error.contains(expected_error), "{error}");
    }
}

#[test]
fn a_matching_value_hidden_in_an_unrelated_field_does_not_satisfy_verification() {
    let recipient_hex = tron_address_to_hex(RECIPIENT).unwrap();
    let contract_hex = tron_address_to_hex(CONTRACT).unwrap();
    // The selected contract pays somebody else 2 sun; a decoy field elsewhere
    // holds the requested recipient and amount.
    let mut spoofed_raw = hex::decode(native_raw(&contract_hex, 2)).unwrap();
    let mut decoy = hex::decode(&recipient_hex).unwrap();
    decoy.extend(encode_varint(1_000_000));
    push_bytes_field(&mut spoofed_raw, 10, &decoy);
    let spoofed_raw = hex::encode(spoofed_raw);
    let spoofed = CreateTransactionResponse {
        tx_id: recompute_txid(&spoofed_raw).unwrap(),
        raw_data: json!({}),
        raw_data_hex: spoofed_raw,
    };
    let error = tron_transaction_spec(
        &spoofed,
        RECIPIENT.to_string(),
        &TronTransfer::Native {
            amount_sun: 1_000_000,
        },
    )
    .unwrap_err();
    assert!(error.contains("requested recipient"), "{error}");
}

#[test]
fn undecodable_raw_data_is_reported() {
    let tx = CreateTransactionResponse {
        tx_id: "x".into(),
        raw_data: json!({}),
        raw_data_hex: "zz".into(),
    };
    let error = tron_transaction_spec(
        &tx,
        RECIPIENT.to_string(),
        &TronTransfer::Native { amount_sun: 1 },
    )
    .unwrap_err();
    assert!(error.starts_with("invalid Tron raw_data_hex:"), "{error}");
}

// ── execute ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_native_transfer_is_built_verified_signed_and_broadcast() {
    let rig = Rig::new();
    script_native(&rig, 1_000_000);
    rig.signer.set_raw(&"11".repeat(65));
    let result = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap();
    assert_eq!(result.status, PreparedStatus::Broadcasted);
    assert_eq!(result.transaction_hash, "ab".repeat(32));
    assert_eq!(
        result.explorer_url.as_deref(),
        Some(format!("https://tronscan.org/#/transaction/{}", "ab".repeat(32)).as_str())
    );

    // The node was asked to build it with hex addresses.
    let create: Value =
        serde_json::from_str(&rig.transport.posts_to("wallet/createtransaction")[0]).unwrap();
    assert_eq!(
        create["owner_address"],
        tron_address_to_hex(sample_address(WalletChain::Tron)).unwrap()
    );
    assert_eq!(
        create["to_address"],
        tron_address_to_hex(RECIPIENT).unwrap()
    );
    assert_eq!(create["amount"], 1_000_000);
    assert_eq!(
        rig.transport.posts_to("wallet/triggersmartcontract").len(),
        0
    );

    // The signer got a verified spec, and its signature is what was broadcast.
    assert!(
        matches!(&rig.signer.transactions()[0], TransactionSpec::Tron { expected_to, .. } if expected_to == RECIPIENT)
    );
    let broadcast: Value =
        serde_json::from_str(&rig.transport.posts_to("wallet/broadcasttransaction")[0]).unwrap();
    assert_eq!(broadcast["signature"], json!(["11".repeat(65)]));
    assert_eq!(broadcast["visible"], false);
    assert!(rig.transport.calls().iter().any(
        |c| matches!(c, Call::RestPost { content_type, .. } if content_type == "application/json")
    ));
}

#[tokio::test]
async fn a_trc20_transfer_pays_the_contract_and_carries_the_recipient_in_the_parameter() {
    let rig = Rig::new();
    let to_hex = tron_address_to_hex(RECIPIENT).unwrap();
    let parameter = encode_trc20_transfer_param(&to_hex, 5_000_000).unwrap();
    let raw = trc20_raw(&tron_address_to_hex(RECIPIENT).unwrap(), &parameter);
    rig.transport.on_post(
        "wallet/triggersmartcontract",
        &json!({"transaction": created(&raw)}).to_string(),
    );
    rig.transport.on_post(
        "wallet/broadcasttransaction",
        &json!({"result": true}).to_string(),
    );

    let result = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::TokenTransfer))
        .await
        .unwrap();

    let trigger: Value =
        serde_json::from_str(&rig.transport.posts_to("wallet/triggersmartcontract")[0]).unwrap();
    assert_eq!(trigger["function_selector"], "transfer(address,uint256)");
    assert_eq!(trigger["parameter"].as_str().unwrap().len(), 128);
    assert_eq!(trigger["fee_limit"], TRC20_FEE_LIMIT_SUN);
    assert_eq!(trigger["call_value"], 0);
    assert_eq!(rig.transport.posts_to("wallet/createtransaction").len(), 0);
    // Without a `txid` in the reply, the node-built transaction's id is used.
    assert_eq!(result.transaction_hash, recompute_txid(&raw).unwrap());
}

#[tokio::test]
async fn a_node_rejection_is_surfaced_with_its_code_and_message() {
    let rig = Rig::new();
    let raw = native_raw(&tron_address_to_hex(RECIPIENT).unwrap(), 1_000_000);
    rig.transport
        .on_post("wallet/createtransaction", &created(&raw).to_string());
    rig.transport.on_post(
        "wallet/broadcasttransaction",
        &json!({"result": false, "code": "BANDWIDTH_ERROR", "message": "not enough bandwidth"})
            .to_string(),
    );
    let err = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        "Tron broadcast rejected: code=BANDWIDTH_ERROR message=not enough bandwidth"
    );
}

#[tokio::test]
async fn a_tampering_node_is_caught_before_the_signer_sees_anything() {
    let rig = Rig::new();
    // The node returns a transaction paying 2 sun instead of the requested 1_000_000.
    script_native(&rig, 2);
    let err = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert!(err.starts_with("Tron node response rejected:"), "{err}");
    assert!(
        rig.signer.transactions().is_empty(),
        "the signer never saw the decoy"
    );
    assert_eq!(
        rig.transport.posts_to("wallet/broadcasttransaction").len(),
        0
    );
}

#[tokio::test]
async fn the_account_the_signer_derives_must_match_the_quote() {
    let rig = Rig::new();
    rig.signer.derive_as(RECIPIENT);
    let err = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert_eq!(
        err,
        format!(
            "Tron key derivation mismatch: derived {RECIPIENT} but expected {}",
            sample_address(WalletChain::Tron)
        )
    );
    assert_eq!(rig.transport.calls().len(), 0);
    assert!(
        rig.signer
            .calls()
            .contains(&SignerCall::Derive(WalletChain::Tron))
    );
}

#[tokio::test]
async fn quote_input_is_validated_before_any_network_call() {
    let rig = Rig::new();
    let mut bad_amount = tron_quote(PreparedKind::NativeTransfer);
    bad_amount.amount_raw = "many".into();
    assert!(
        execute_tron_quote(&rig.engine, bad_amount)
            .await
            .unwrap_err()
            .starts_with("invalid Tron amount 'many'")
    );
    let mut too_big = tron_quote(PreparedKind::NativeTransfer);
    too_big.amount_raw = u128::MAX.to_string();
    script_native(&rig, 1);
    assert!(
        execute_tron_quote(&rig.engine, too_big)
            .await
            .unwrap_err()
            .contains("exceeds u64")
    );
    let mut no_contract = tron_quote(PreparedKind::TokenTransfer);
    no_contract.token_address = None;
    assert_eq!(
        execute_tron_quote(&rig.engine, no_contract)
            .await
            .unwrap_err(),
        "TRC20 transfer missing token_address"
    );
    let mut bad_contract = tron_quote(PreparedKind::TokenTransfer);
    bad_contract.token_address = Some("nope".into());
    assert!(execute_tron_quote(&rig.engine, bad_contract).await.is_err());
    let mut bad_to = tron_quote(PreparedKind::NativeTransfer);
    bad_to.to_address = "nope".into();
    assert!(execute_tron_quote(&rig.engine, bad_to).await.is_err());
    let mut bad_from = tron_quote(PreparedKind::NativeTransfer);
    bad_from.from_address = "nope".into();
    assert!(execute_tron_quote(&rig.engine, bad_from).await.is_err());
}

#[tokio::test]
async fn transport_failures_are_passed_through() {
    let rig = Rig::new();
    rig.transport.on_post_unreachable(
        "wallet/createtransaction",
        "wallet REST POST transport failed: refused",
    );
    let err = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert_eq!(err, "wallet REST POST transport failed: refused");
    let rig = Rig::new();
    rig.transport
        .on_post("wallet/createtransaction", "not json");
    let err = execute_tron_quote(&rig.engine, tron_quote(PreparedKind::NativeTransfer))
        .await
        .unwrap_err();
    assert!(err.starts_with("wallet REST POST decode failed:"), "{err}");
}

// ── reads ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn balance_reads_sun_and_defaults_an_unfunded_account_to_zero() {
    let rig = Rig::new();
    rig.transport.on_post(
        "wallet/getaccount",
        &json!({"balance": 3_000_000u64}).to_string(),
    );
    assert_eq!(
        native_balance(&rig.engine, RECIPIENT).await.unwrap(),
        3_000_000
    );
    let body: Value =
        serde_json::from_str(&rig.transport.posts_to("wallet/getaccount")[0]).unwrap();
    assert_eq!(body["address"], tron_address_to_hex(RECIPIENT).unwrap());
    assert_eq!(body["visible"], false);
    assert!(native_balance(&rig.engine, "nope").await.is_err());

    let unfunded = Rig::new();
    unfunded.transport.on_post("wallet/getaccount", "{}");
    assert_eq!(
        native_balance(&unfunded.engine, RECIPIENT).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn a_mined_transaction_reports_its_result_and_block() {
    let rig = Rig::new();
    rig.transport.on_post(
        "wallet/gettransactioninfobyid",
        &json!({"id": "ab", "blockNumber": 555u64, "receipt": {"result": "SUCCESS", "energy_usage_total": 77u64}, "fee": 1100u64}).to_string(),
    );
    let status = tx_status(&rig.engine, "ab").await.unwrap();
    assert_eq!(
        (status.state, status.block_number),
        (TxState::Confirmed, Some(555))
    );
    let receipt = tx_receipt(&rig.engine, "ab").await.unwrap();
    assert!(receipt.found);
    assert_eq!(receipt.success, Some(true));
    assert_eq!(receipt.fee_raw.as_deref(), Some("1100"));
    assert_eq!(receipt.gas_used.as_deref(), Some("77"));
    assert_eq!(receipt.block_number, Some(555));
    let body: Value =
        serde_json::from_str(&rig.transport.posts_to("wallet/gettransactioninfobyid")[0]).unwrap();
    assert_eq!(body, json!({"value": "ab"}));
}

#[tokio::test]
async fn a_reverted_contract_call_is_failed_and_a_bare_transfer_is_a_success() {
    let rig = Rig::new();
    rig.transport.on_post(
        "wallet/gettransactioninfobyid",
        &json!({"blockNumber": 1u64, "receipt": {"result": "REVERT"}}).to_string(),
    );
    assert_eq!(
        tx_status(&rig.engine, "x").await.unwrap().state,
        TxState::Failed
    );
    assert_eq!(
        tx_receipt(&rig.engine, "x").await.unwrap().success,
        Some(false)
    );

    let bare = Rig::new();
    bare.transport.on_post(
        "wallet/gettransactioninfobyid",
        &json!({"blockNumber": 1u64}).to_string(),
    );
    assert_eq!(
        tx_status(&bare.engine, "x").await.unwrap().state,
        TxState::Confirmed
    );
    assert_eq!(
        tx_receipt(&bare.engine, "x").await.unwrap().success,
        Some(true)
    );
}

#[tokio::test]
async fn an_unmined_transaction_is_pending_when_the_node_knows_it_and_not_found_otherwise() {
    let rig = Rig::new();
    rig.transport.on_post("wallet/gettransactioninfobyid", "{}");
    rig.transport.on_post(
        "wallet/gettransactionbyid",
        &json!({"txID": "ab", "raw_data": {}}).to_string(),
    );
    assert_eq!(
        tx_status(&rig.engine, "ab").await.unwrap().state,
        TxState::Pending
    );
    let found = lookup_tx(&rig.engine, "ab").await.unwrap();
    assert!(found.found);
    assert!(!tx_receipt(&rig.engine, "ab").await.unwrap().found);

    let unknown = Rig::new();
    unknown
        .transport
        .on_post("wallet/gettransactioninfobyid", "{}");
    unknown.transport.on_post("wallet/gettransactionbyid", "{}");
    assert_eq!(
        tx_status(&unknown.engine, "ab").await.unwrap().state,
        TxState::NotFound
    );
    assert!(!lookup_tx(&unknown.engine, "ab").await.unwrap().found);
}
