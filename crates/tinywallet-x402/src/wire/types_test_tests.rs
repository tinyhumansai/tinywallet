#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    BASE_MAINNET_CAIP2, PaymentChain, PaymentRequired, PaymentRequirements, SOLANA_MAINNET_CAIP2,
    X402_VERSION,
};

fn requirement(scheme: &str, network: &str) -> PaymentRequirements {
    PaymentRequirements {
        scheme: scheme.to_string(),
        network: network.to_string(),
        amount: "1000000".to_string(),
        asset: super::USDC_MINT_MAINNET.to_string(),
        pay_to: "11111111111111111111111111111111".to_string(),
        max_timeout_seconds: 60,
        extra: None,
    }
}

fn challenge(accepts: Vec<PaymentRequirements>) -> PaymentRequired {
    PaymentRequired {
        x402_version: X402_VERSION,
        error: None,
        resource: super::ResourceInfo {
            url: "https://example.test/thing".to_string(),
            description: None,
            mime_type: None,
        },
        accepts,
        extensions: serde_json::Map::new(),
    }
}

#[test]
fn only_the_exact_scheme_is_selected() {
    // A server may offer schemes this crate cannot pay; picking one of
    // those would produce a proof the facilitator rejects.
    let c = challenge(vec![requirement("upto", SOLANA_MAINNET_CAIP2)]);
    assert!(c.solana_exact_requirement().is_none());
    assert!(c.best_exact_requirement().is_none());
}

#[test]
fn requirements_are_matched_by_network_prefix_not_exact_string() {
    // CAIP-2 names a specific chain, so devnet and mainnet differ — but
    // both are Solana, and the selector must accept either.
    let c = challenge(vec![requirement("exact", super::SOLANA_DEVNET_CAIP2)]);
    assert!(c.solana_exact_requirement().is_some());

    let c = challenge(vec![requirement("exact", super::BASE_SEPOLIA_CAIP2)]);
    assert!(c.evm_exact_requirement().is_some());
}

#[test]
fn solana_is_preferred_when_both_are_offered() {
    // Pinning the documented order: which chain a payer spends from is
    // observable behaviour, not an implementation detail.
    let c = challenge(vec![
        requirement("exact", BASE_MAINNET_CAIP2),
        requirement("exact", SOLANA_MAINNET_CAIP2),
    ]);
    let (_, chain) = c.best_exact_requirement().unwrap();
    assert_eq!(chain, PaymentChain::Solana);
}

#[test]
fn evm_is_used_when_it_is_the_only_option() {
    let c = challenge(vec![requirement("exact", BASE_MAINNET_CAIP2)]);
    let (req, chain) = c.best_exact_requirement().unwrap();
    assert_eq!(chain, PaymentChain::Evm);
    assert_eq!(req.evm_chain_id(), Some(8453));
}

#[test]
fn the_evm_chain_id_is_parsed_from_the_caip2_network() {
    assert_eq!(
        requirement("exact", "eip155:1").evm_chain_id(),
        Some(1),
        "ethereum mainnet"
    );
    assert_eq!(
        requirement("exact", SOLANA_MAINNET_CAIP2).evm_chain_id(),
        None,
        "a Solana network has no EVM chain id"
    );
    assert_eq!(
        requirement("exact", "eip155:notanumber").evm_chain_id(),
        None
    );
}

#[test]
fn amounts_stay_strings_through_a_json_round_trip() {
    // The reason the protocol uses strings: a u64 amount through a
    // double-based JSON parser can come back as a different number.
    let mut req = requirement("exact", SOLANA_MAINNET_CAIP2);
    req.amount = "18446744073709551615".to_string(); // u64::MAX
    let json = serde_json::to_string(&req).unwrap();
    let back: PaymentRequirements = serde_json::from_str(&json).unwrap();
    assert_eq!(back.amount, "18446744073709551615");
}

#[test]
fn the_wire_shape_is_camel_case() {
    // The header payload is read by facilitators in other languages, so
    // the field names are part of the contract.
    let json = serde_json::to_string(&requirement("exact", SOLANA_MAINNET_CAIP2)).unwrap();
    assert!(json.contains("\"payTo\""), "{json}");
    assert!(json.contains("\"maxTimeoutSeconds\""), "{json}");
    assert!(!json.contains("pay_to"), "{json}");
}

#[test]
fn a_payment_proof_serialises_untagged() {
    // The facilitator sees the chain-specific object directly, with no
    // enum discriminant wrapping it.
    let solana = super::PaymentProof::Solana(super::SolanaPaymentProof {
        transaction: "base64tx".to_string(),
    });
    let json = serde_json::to_string(&solana).unwrap();
    assert_eq!(json, r#"{"transaction":"base64tx"}"#);

    let evm = super::PaymentProof::Evm(super::EvmPaymentProof {
        signature: "0xsig".to_string(),
        authorization: super::EvmAuthorization {
            from: "0xa".to_string(),
            to: "0xb".to_string(),
            value: "1".to_string(),
            valid_after: "0".to_string(),
            valid_before: "99".to_string(),
            nonce: "0xn".to_string(),
        },
    });
    let json = serde_json::to_string(&evm).unwrap();
    assert!(json.starts_with(r#"{"signature":"0xsig""#), "{json}");
    assert!(json.contains("\"validBefore\""), "{json}");
}

#[test]
fn optional_fields_are_omitted_rather_than_sent_as_null() {
    let json = serde_json::to_string(&requirement("exact", SOLANA_MAINNET_CAIP2)).unwrap();
    assert!(!json.contains("extra"), "absent extras are omitted: {json}");
}

#[test]
fn a_challenge_round_trips() {
    let c = challenge(vec![requirement("exact", SOLANA_MAINNET_CAIP2)]);
    let json = serde_json::to_string(&c).unwrap();
    let back: PaymentRequired = serde_json::from_str(&json).unwrap();
    assert_eq!(back.x402_version, X402_VERSION);
    assert_eq!(back.accepts.len(), 1);
    assert_eq!(back.resource.url, "https://example.test/thing");
}

#[test]
fn unknown_extension_fields_are_preserved_not_rejected() {
    // Unlike the document spec, this is a protocol other implementations
    // extend, so an unknown key must not fail the parse.
    let json = r#"{
            "x402Version": 2,
            "resource": { "url": "https://example.test" },
            "accepts": [],
            "extensions": { "somethingNew": true }
        }"#;
    let parsed: PaymentRequired = serde_json::from_str(json).unwrap();
    assert!(parsed.extensions.contains_key("somethingNew"));
}
