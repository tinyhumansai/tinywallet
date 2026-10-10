//! Construction wire forms stay pure, strict and free of ordinary secret fields.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use super::*;
use serde_json::json;

#[test]
fn construction_request_preserves_intent_tags_and_rejects_secret_or_unknown_fields() {
    let request = json!({"public_key":{"key_hex":"02"},"chain_id":1,"nonce":7,"gas_limit":21000,"gas_price_wei":"1",
        "intent":{"kind":"native_transfer","to":"0xfixture","amount_wei":"5"}});
    let decoded: EvmConstructionRequest = serde_json::from_value(request.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), request);
    for field in ["mnemonic", "secret", "approval_granted"] {
        let mut bad = request.clone();
        bad[field] = json!("must-not-be-accepted");
        assert!(serde_json::from_value::<EvmConstructionRequest>(bad).is_err());
    }
    for intent in [
        json!({"kind":"erc20_transfer","token":"token","to":"recipient","amount_raw":"5"}),
        json!({"kind":"contract_call","to":"contract","value_wei":"0","data_hex":"0x"}),
    ] {
        let decoded: EvmIntent = serde_json::from_value(intent.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), intent);
    }
    let mut bad = request;
    bad["intent"]["mnemonic"] = json!("fixture");
    assert!(serde_json::from_value::<EvmConstructionRequest>(bad).is_err());
}

#[test]
fn constructed_response_reuses_existing_transaction_and_signing_payload_wire() {
    let wire = json!({"transaction":{"kind":"evm","to":"recipient","value_wei":"5","data_hex":"0x","nonce":7,"gas_limit":21000,"gas_price_wei":"1","chain_id":1},
        "unsigned":{"payloads":[{"bytes_hex":"00","scheme":"secp256k1_prehash"}]},
        "approval":{"sender":"sender","chain_id":1,"nonce":7,"gas_limit":21000,"gas_price_wei":"1","max_fee_wei":"21000","max_native_debit_wei":"21005","native_value_wei":"5","recipient":"recipient","token_contract":null,"token_amount_raw":null,"calldata_hex":"0x"}});
    let decoded: ConstructedEvmTransaction = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), wire);
}
