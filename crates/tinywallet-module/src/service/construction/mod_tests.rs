//! Construction facts bind to exact encoded bytes, with bounded and validated public input.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use serde_json::json;
use tinywallet::Chain;

fn request() -> EvmConstructionRequest {
    let key = tinywallet::key::derive(Chain::Evm,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "m/44'/60'/0'/0/0").unwrap();
    serde_json::from_value(json!({
        "public_key":{"key_hex":super::super::public_key_hex(Chain::Evm, key.secret_bytes()).unwrap()},
        "chain_id":1,"nonce":7,"gas_limit":21000,"gas_price_wei":"30000000000",
        "intent":{"kind":"native_transfer","to":"0x3535353535353535353535353535353535353535","amount_wei":"1000000000000000000"}
    })).unwrap()
}

#[test]
fn native_facts_and_payload_match_existing_builder_and_sender_derivation() {
    let request = request();
    let result = construct(&request).unwrap();
    let expected = build_unsigned(&SigningRequest {
        transaction: result.transaction.clone(),
        public_key: request.public_key,
    })
    .unwrap();
    assert_eq!(result.unsigned, expected);
    assert_eq!(
        result.approval.sender,
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    assert_eq!(result.approval.max_native_debit_wei, "1000630000000000000");
    assert_eq!(result.approval.native_value_wei, "1000000000000000000");
    assert_eq!(result.approval.calldata_hex, "0x");
    assert!(result.approval.token_contract.is_none());
}

#[test]
fn full_uint256_token_value_is_encoded_without_native_value_or_host_calldata() {
    let mut request = request();
    request.intent = EvmIntent::Erc20Transfer {
        token: "0x1111111111111111111111111111111111111111".into(),
        to: "0x3535353535353535353535353535353535353535".into(),
        amount_raw: " 000340282366920938463463374607431768211456 ".into(),
    };
    let result = construct(&request).unwrap();
    assert_eq!(
        result.approval.token_amount_raw.as_deref(),
        Some("340282366920938463463374607431768211456")
    );
    assert_eq!(result.approval.native_value_wei, "0");
    assert_eq!(
        result.approval.max_native_debit_wei,
        result.approval.max_fee_wei
    );
    let expected = tinywallet::abi::encode_erc20_transfer(
        &result.approval.recipient,
        result.approval.token_amount_raw.as_deref().unwrap(),
    )
    .unwrap();
    assert_eq!(result.approval.calldata_hex, expected);
    assert!(
        matches!(result.transaction,TransactionSpec::Evm { to,value_wei,data_hex,.. }
        if Some(to.as_str())==result.approval.token_contract.as_deref() && value_wei=="0" && data_hex==expected)
    );
}

#[test]
fn explicit_contract_call_preserves_destination_value_and_normalized_calldata() {
    let mut request = request();
    request.intent = EvmIntent::ContractCall {
        to: "0x1111111111111111111111111111111111111111".into(),
        value_wei: " 0005 ".into(),
        data_hex: " 0xAAbb ".into(),
    };
    let result = construct(&request).unwrap();
    assert_eq!(result.approval.calldata_hex, "0xaabb");
    assert_eq!(result.approval.native_value_wei, "5");
    assert_eq!(result.approval.max_native_debit_wei, "630000000000005");
    assert!(result.approval.token_amount_raw.is_none());
}

#[test]
fn construction_rejects_invalid_points_limits_overflows_and_malformed_amounts() {
    let base = request();
    for edit in [0, 1, 2, 3, 4, 5, 6, 7] {
        let mut request = base.clone();
        match edit {
            0 => request.chain_id = 0,
            1 => request.gas_limit = 0,
            2 => request.public_key.key_hex = "00".repeat(33),
            3 => request.public_key.key_hex = "00".into(),
            4 => request.gas_price_wei = "invalid".into(),
            5 => request.gas_price_wei = u128::MAX.to_string(),
            6 => {
                request.intent = EvmIntent::NativeTransfer {
                    to: recipient(),
                    amount_wei: u128::MAX.to_string(),
                }
            }
            _ => {
                request.intent = EvmIntent::NativeTransfer {
                    to: recipient(),
                    amount_wei: "0".into(),
                }
            }
        }
        assert!(construct(&request).is_err(), "edit {edit}");
    }
    for data in [
        "0x€a".into(),
        "0x1".into(),
        "00".repeat(MAX_CALLDATA_BYTES + 1),
        "x".repeat(MAX_CONSTRUCTION_BYTES),
    ] {
        let mut request = base.clone();
        request.intent = EvmIntent::ContractCall {
            to: recipient(),
            value_wei: "0".into(),
            data_hex: data,
        };
        assert!(construct(&request).is_err());
    }
    for amount in [
        "",
        "0",
        "-1",
        "1.5",
        "not-amount",
        "115792089237316195423570985008687907853269984665640564039457584007913129639936",
    ] {
        let mut request = base.clone();
        request.intent = EvmIntent::Erc20Transfer {
            token: recipient(),
            to: recipient(),
            amount_raw: amount.into(),
        };
        assert!(construct(&request).is_err());
    }
    let mut request = base;
    request.intent = EvmIntent::NativeTransfer {
        to: "invalid".into(),
        amount_wei: "1".into(),
    };
    assert!(construct(&request).is_err());
}

fn recipient() -> String {
    "0x3535353535353535353535353535353535353535".into()
}

#[test]
fn request_budget_refuses_before_allocating_serialized_output() {
    let mut budget = Budget(0);
    assert!(std::io::Write::write_all(&mut budget, &vec![0; MAX_CONSTRUCTION_BYTES]).is_ok());
    assert!(std::io::Write::write_all(&mut budget, b"x").is_err());
    assert!(std::io::Write::flush(&mut budget).is_ok());
    assert!(std::io::Write::write_all(&mut Budget(usize::MAX), b"x").is_err());
}
