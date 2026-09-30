//! Wire-shape tests for the x402 types: the fee-payer/memo accessors, the
//! settlement response, and a full `PaymentPayload` for each chain.
//!
//! Ported from the host application's x402 suite, which exercised these types before they
//! were extracted here. The selection and CAIP-2 rules live in `types.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crate::wire::{
    AssetCheck, SUPPORTED_USDC, check_usdc,
    BASE_MAINNET_CAIP2, EvmAuthorization, EvmPaymentProof, PaymentExtra, PaymentPayload,
    PaymentProof, PaymentRequired, PaymentRequirements, ResourceInfo, SOLANA_MAINNET_CAIP2,
    SettlementResponse, SolanaPaymentProof, USDC_BASE_MAINNET, USDC_ETHEREUM_MAINNET,
    USDC_MINT_MAINNET,
};

fn requirement(network: &str, asset: &str, extra: Option<PaymentExtra>) -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".to_string(),
        network: network.to_string(),
        amount: "1000".to_string(),
        asset: asset.to_string(),
        pay_to: "Recipient".to_string(),
        max_timeout_seconds: 60,
        extra,
    }
}

fn payload(accepted: PaymentRequirements, proof: PaymentProof) -> PaymentPayload {
    PaymentPayload {
        x402_version: 2,
        resource: None,
        accepted,
        payload: proof,
        extensions: serde_json::Map::new(),
    }
}

#[test]
fn a_challenge_with_extras_round_trips() {
    let challenge = PaymentRequired {
        x402_version: 2,
        error: Some("PAYMENT-SIGNATURE header is required".to_string()),
        resource: ResourceInfo {
            url: "https://api.example.com/data".to_string(),
            description: Some("Premium data".to_string()),
            mime_type: Some("application/json".to_string()),
        },
        accepts: vec![requirement(
            SOLANA_MAINNET_CAIP2,
            USDC_MINT_MAINNET,
            Some(PaymentExtra {
                fee_payer: Some("EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd".to_string()),
                memo: Some("pi_3abc123".to_string()),
                name: None,
                version: None,
            }),
        )],
        extensions: serde_json::Map::new(),
    };

    let json = serde_json::to_string(&challenge).unwrap();
    let parsed: PaymentRequired = serde_json::from_str(&json).unwrap();

    assert_eq!(
        parsed.error.as_deref(),
        Some("PAYMENT-SIGNATURE header is required")
    );
    assert_eq!(
        parsed.resource.mime_type.as_deref(),
        Some("application/json")
    );
    let accepted = &parsed.accepts[0];
    assert_eq!(
        accepted.fee_payer_pubkey(),
        Some("EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd")
    );
    assert_eq!(accepted.memo_value(), Some("pi_3abc123"));
}

#[test]
fn extra_accessors_return_the_server_supplied_values() {
    let req = requirement(
        SOLANA_MAINNET_CAIP2,
        USDC_MINT_MAINNET,
        Some(PaymentExtra {
            fee_payer: Some("FeePayer123".to_string()),
            memo: Some("order_456".to_string()),
            name: None,
            version: None,
        }),
    );
    assert_eq!(req.fee_payer_pubkey(), Some("FeePayer123"));
    assert_eq!(req.memo_value(), Some("order_456"));
}

#[test]
fn extra_accessors_are_none_when_the_server_sent_no_extras() {
    let req = requirement(SOLANA_MAINNET_CAIP2, USDC_MINT_MAINNET, None);
    assert_eq!(req.fee_payer_pubkey(), None);
    assert_eq!(req.memo_value(), None);

    let partial = requirement(
        SOLANA_MAINNET_CAIP2,
        USDC_MINT_MAINNET,
        Some(PaymentExtra {
            fee_payer: None,
            memo: None,
            name: Some("USD Coin".to_string()),
            version: Some("2".to_string()),
        }),
    );
    assert_eq!(partial.fee_payer_pubkey(), None);
    assert_eq!(partial.memo_value(), None);
}

#[test]
fn network_predicates_distinguish_mainnets_from_other_chains() {
    let sol = requirement(SOLANA_MAINNET_CAIP2, USDC_MINT_MAINNET, None);
    assert!(sol.is_solana_mainnet());
    assert!(!sol.is_base_mainnet());

    let base = requirement(BASE_MAINNET_CAIP2, USDC_BASE_MAINNET, None);
    assert!(base.is_base_mainnet());
    assert_eq!(base.evm_chain_id(), Some(8453));

    let eth = requirement("eip155:1", USDC_ETHEREUM_MAINNET, None);
    assert!(!eth.is_base_mainnet());
    assert_eq!(eth.evm_chain_id(), Some(1));
}

#[test]
fn a_successful_settlement_deserializes() {
    let json = r#"{
        "success": true,
        "transaction": "4vJ9YFuPzUgdLkWYJf3Kqf",
        "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "payer": "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd"
    }"#;
    let resp: SettlementResponse = serde_json::from_str(json).unwrap();
    assert!(resp.success);
    assert_eq!(resp.transaction, "4vJ9YFuPzUgdLkWYJf3Kqf");
    assert_eq!(
        resp.payer.as_deref(),
        Some("EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd")
    );
    assert!(resp.error_reason.is_none());
}

#[test]
fn a_failed_settlement_carries_its_camel_case_error_reason() {
    let json = r#"{
        "success": false,
        "transaction": "",
        "network": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "payer": "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd",
        "errorReason": "insufficient_funds"
    }"#;
    let resp: SettlementResponse = serde_json::from_str(json).unwrap();
    assert!(!resp.success);
    assert_eq!(resp.error_reason.as_deref(), Some("insufficient_funds"));
}

#[test]
fn an_evm_payload_carries_the_signature_and_authorization_but_no_transaction() {
    let proof = PaymentProof::Evm(EvmPaymentProof {
        signature: "0xdeadbeef".to_string(),
        authorization: EvmAuthorization {
            from: "0xaaaa".to_string(),
            to: "0xbbbb".to_string(),
            value: "1000000".to_string(),
            valid_after: "0".to_string(),
            valid_before: "99999999".to_string(),
            nonce: "0xabcd".to_string(),
        },
    });
    let accepted = requirement(BASE_MAINNET_CAIP2, USDC_BASE_MAINNET, None);

    let json = serde_json::to_string(&payload(accepted, proof)).unwrap();

    assert!(json.contains("\"signature\":\"0xdeadbeef\""), "{json}");
    assert!(json.contains("\"authorization\""), "{json}");
    assert!(!json.contains("\"transaction\""), "{json}");
    assert!(json.contains("\"x402Version\":2"), "{json}");
}

#[test]
fn a_solana_payload_carries_the_transaction_but_no_signature() {
    let proof = PaymentProof::Solana(SolanaPaymentProof {
        transaction: "base64tx".to_string(),
    });
    let accepted = requirement(SOLANA_MAINNET_CAIP2, USDC_MINT_MAINNET, None);

    let json = serde_json::to_string(&payload(accepted, proof)).unwrap();

    assert!(json.contains("\"transaction\":\"base64tx\""), "{json}");
    assert!(!json.contains("\"signature\""), "{json}");
    assert!(
        !json.contains("\"resource\""),
        "an absent resource is omitted: {json}"
    );
}

// ---------------------------------------------------------------------------
// The network -> USDC allowlist
// ---------------------------------------------------------------------------

#[test]
fn usdc_is_accepted_on_every_known_network() {
    use crate::wire::{
        BASE_SEPOLIA_CAIP2, ETHEREUM_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2, USDC_BASE_SEPOLIA,
        USDC_MINT_DEVNET,
    };
    let pairs = [
        (SOLANA_MAINNET_CAIP2, USDC_MINT_MAINNET),
        (SOLANA_DEVNET_CAIP2, USDC_MINT_DEVNET),
        (BASE_MAINNET_CAIP2, USDC_BASE_MAINNET),
        (BASE_SEPOLIA_CAIP2, USDC_BASE_SEPOLIA),
        (ETHEREUM_MAINNET_CAIP2, USDC_ETHEREUM_MAINNET),
    ];
    assert_eq!(pairs.len(), SUPPORTED_USDC.len());
    for (network, asset) in pairs {
        assert_eq!(check_usdc(network, asset), AssetCheck::Allowed, "{network}");
    }
}

#[test]
fn an_evm_asset_is_compared_without_regard_to_case() {
    assert_eq!(
        check_usdc(BASE_MAINNET_CAIP2, &USDC_BASE_MAINNET.to_lowercase()),
        AssetCheck::Allowed
    );
}

#[test]
fn a_solana_mint_is_compared_exactly() {
    assert_eq!(
        check_usdc(SOLANA_MAINNET_CAIP2, &USDC_MINT_MAINNET.to_lowercase()),
        AssetCheck::WrongAsset
    );
}

#[test]
fn an_unknown_network_is_not_accepted_even_with_a_known_asset() {
    assert_eq!(
        check_usdc("eip155:137", USDC_BASE_MAINNET),
        AssetCheck::UnknownNetwork
    );
    assert_eq!(
        check_usdc("solana:someOtherCluster", USDC_MINT_MAINNET),
        AssetCheck::UnknownNetwork
    );
}

#[test]
fn another_asset_on_a_known_network_is_not_accepted() {
    // USDC's Base contract is not USDC on Ethereum, and neither is a made-up token.
    assert_eq!(
        check_usdc(BASE_MAINNET_CAIP2, USDC_ETHEREUM_MAINNET),
        AssetCheck::WrongAsset
    );
    assert_eq!(
        check_usdc(SOLANA_MAINNET_CAIP2, "NotUsdcMint1111111111111111111111111111111"),
        AssetCheck::WrongAsset
    );
}
