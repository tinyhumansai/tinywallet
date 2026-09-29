//! Wire types for the x402 protocol (v2).
//!
//! All header payloads are standard-base64-encoded JSON. Network identifiers
//! use CAIP-2 format (e.g. `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp`).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The protocol version this module implements.
pub const X402_VERSION: u8 = 2;

/// Response header carrying the v2 402 challenge.
pub const HEADER_PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";
/// The v1 spelling of the challenge header, still sent by some servers.
pub const HEADER_PAYMENT_REQUIRED_V1: &str = "X-PAYMENT-REQUIRED";
/// Request header carrying the v2 payment proof.
pub const HEADER_PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";
/// The v1 spelling of the payment-proof header.
pub const HEADER_PAYMENT_SIGNATURE_V1: &str = "X-PAYMENT";
/// Response header carrying the settlement result.
pub const HEADER_PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// CAIP-2 identifier for Solana mainnet-beta.
pub const SOLANA_MAINNET_CAIP2: &str = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp";
/// CAIP-2 identifier for Solana devnet.
pub const SOLANA_DEVNET_CAIP2: &str = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";

/// USDC SPL mint on Solana mainnet-beta.
pub const USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
/// USDC SPL mint on Solana devnet. Differs from mainnet.
pub const USDC_MINT_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

/// The SPL Token program id.
pub const SPL_TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
/// The SPL Memo program id, used for payment uniqueness.
pub const SPL_MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
/// The Compute Budget program id.
pub const COMPUTE_BUDGET_PROGRAM: &str = "ComputeBudget111111111111111111111111111111";

// EVM / Base chain constants (CAIP-2 format: eip155:<chain_id>)
/// CAIP-2 identifier for Base mainnet.
pub const BASE_MAINNET_CAIP2: &str = "eip155:8453";
/// CAIP-2 identifier for Base Sepolia.
pub const BASE_SEPOLIA_CAIP2: &str = "eip155:84532";
/// CAIP-2 identifier for Ethereum mainnet.
pub const ETHEREUM_MAINNET_CAIP2: &str = "eip155:1";

/// USDC contract on Base mainnet.
pub const USDC_BASE_MAINNET: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
/// USDC contract on Base Sepolia.
pub const USDC_BASE_SEPOLIA: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
/// USDC contract on Ethereum mainnet.
pub const USDC_ETHEREUM_MAINNET: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

// ---------------------------------------------------------------------------
// 402 challenge — server → client (PAYMENT-REQUIRED header)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The 402 challenge a server sends: what it will accept, and for what.
pub struct PaymentRequired {
    /// See the x402 v2 specification.
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub error: Option<String>,
    /// See the x402 v2 specification.
    pub resource: ResourceInfo,
    /// See the x402 v2 specification.
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    /// See the x402 v2 specification.
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The resource a payment buys access to.
pub struct ResourceInfo {
    /// See the x402 v2 specification.
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub mime_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// One payment option a server will accept.
pub struct PaymentRequirements {
    /// See the x402 v2 specification.
    pub scheme: String,
    /// See the x402 v2 specification.
    pub network: String,
    /// Amount in atomic token units, as a decimal string (1 USDC = `1000000`).
    ///
    /// A string rather than a number — see the module docs.
    /// See the x402 v2 specification.
    pub amount: String,
    /// Token mint address (Solana) or contract address (EVM).
    /// See the x402 v2 specification.
    pub asset: String,
    /// Recipient wallet address.
    /// See the x402 v2 specification.
    pub pay_to: String,
    /// See the x402 v2 specification.
    pub max_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub extra: Option<PaymentExtra>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// Scheme-specific extras a server attaches to a requirement.
pub struct PaymentExtra {
    /// Facilitator pubkey that will co-sign as fee payer (Solana).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub fee_payer: Option<String>,
    /// Required memo value for transaction uniqueness (Solana).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub memo: Option<String>,
    /// EIP-712 domain name for the token contract (EVM, e.g. "USD Coin").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub name: Option<String>,
    /// EIP-712 domain version for the token contract (EVM, e.g. "2").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub version: Option<String>,
}

// ---------------------------------------------------------------------------
// Payment proof — client → server (PAYMENT-SIGNATURE header)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The proof a client sends back after paying.
pub struct PaymentPayload {
    /// See the x402 v2 specification.
    pub x402_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub resource: Option<ResourceInfo>,
    /// See the x402 v2 specification.
    pub accepted: PaymentRequirements,
    /// See the x402 v2 specification.
    pub payload: PaymentProof,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    /// See the x402 v2 specification.
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

/// Chain-specific payment proof. Serializes flat (untagged) so the facilitator
/// sees either `{ "transaction": "..." }` (Solana) or
/// `{ "signature": "0x...", "authorization": {...} }` (EVM).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
/// A chain-specific payment proof.
///
/// Serialises untagged, so a facilitator sees the chain's object directly.
pub enum PaymentProof {
    /// A Solana partially-signed transaction.
    Solana(SolanaPaymentProof),
    /// An EVM EIP-3009 authorisation.
    Evm(EvmPaymentProof),
}

/// Solana `exact` scheme payload — a partially-signed `VersionedTransaction`
/// serialized as standard base64. The facilitator adds its fee-payer signature
/// and broadcasts.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// Solana `exact` proof: a partially-signed transaction, base64.
///
/// The facilitator adds its fee-payer signature and broadcasts.
pub struct SolanaPaymentProof {
    /// See the x402 v2 specification.
    pub transaction: String,
}

/// EVM `exact` scheme payload — a signed EIP-3009 `transferWithAuthorization`
/// or plain ERC-20 transfer authorization for the facilitator to submit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// EVM `exact` proof: a signed EIP-3009 authorisation for the
/// facilitator to submit.
pub struct EvmPaymentProof {
    /// See the x402 v2 specification.
    pub signature: String,
    /// See the x402 v2 specification.
    pub authorization: EvmAuthorization,
}

/// EIP-3009 `transferWithAuthorization` parameters signed by the token holder.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// EIP-3009 `transferWithAuthorization` parameters signed by the token
/// holder.
///
/// `valid_after`, `valid_before` and `nonce` are what stop the
/// authorisation being replayable — see the module docs.
pub struct EvmAuthorization {
    /// See the x402 v2 specification.
    pub from: String,
    /// See the x402 v2 specification.
    pub to: String,
    /// See the x402 v2 specification.
    pub value: String,
    /// See the x402 v2 specification.
    pub valid_after: String,
    /// See the x402 v2 specification.
    pub valid_before: String,
    /// See the x402 v2 specification.
    pub nonce: String,
}

// ---------------------------------------------------------------------------
// Settlement response — server → client (PAYMENT-RESPONSE header)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// The settlement result a server returns once the payment landed.
pub struct SettlementResponse {
    /// See the x402 v2 specification.
    pub success: bool,
    /// Base58 transaction signature (Solana) or hex tx hash (EVM).
    /// See the x402 v2 specification.
    pub transaction: String,
    /// See the x402 v2 specification.
    pub network: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub payer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub error_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// See the x402 v2 specification.
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    /// See the x402 v2 specification.
    pub extensions: serde_json::Map<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

impl PaymentRequired {
    /// Find the first `accepts` entry whose network starts with `"solana:"` and
    /// whose scheme is `"exact"`.
    #[must_use]
    pub fn solana_exact_requirement(&self) -> Option<&PaymentRequirements> {
        self.accepts
            .iter()
            .find(|r| r.scheme == "exact" && r.network.starts_with("solana:"))
    }

    /// Find the first `accepts` entry whose network starts with `"eip155:"` and
    /// whose scheme is `"exact"`.
    #[must_use]
    pub fn evm_exact_requirement(&self) -> Option<&PaymentRequirements> {
        self.accepts
            .iter()
            .find(|r| r.scheme == "exact" && r.network.starts_with("eip155:"))
    }

    /// The preferred payment option: **Solana first, then EVM**.
    ///
    /// The order matters to a payer with funds on both chains, so it is stated
    /// plainly here. The implementation this was extracted from carried a doc
    /// comment claiming the opposite ("prefer EVM (Base), fall back to
    /// Solana") while the code checked Solana first; the code's behaviour is
    /// preserved and the comment corrected, since changing which chain a payer
    /// spends from is not a documentation fix.
    #[must_use]
    pub fn best_exact_requirement(&self) -> Option<(&PaymentRequirements, PaymentChain)> {
        if let Some(sol) = self.solana_exact_requirement() {
            Some((sol, PaymentChain::Solana))
        } else if let Some(evm) = self.evm_exact_requirement() {
            Some((evm, PaymentChain::Evm))
        } else {
            None
        }
    }
}

/// Which chain family a payment requirement targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Which chain family a payment requirement targets.
pub enum PaymentChain {
    /// A Solana `exact`-scheme payment.
    Solana,
    /// An EVM `exact`-scheme payment.
    Evm,
}

impl PaymentRequirements {
    /// Whether this requirement targets Solana mainnet-beta.
    #[must_use]
    pub fn is_solana_mainnet(&self) -> bool {
        self.network == SOLANA_MAINNET_CAIP2
    }

    /// Whether this requirement targets Base mainnet.
    #[must_use]
    pub fn is_base_mainnet(&self) -> bool {
        self.network == BASE_MAINNET_CAIP2
    }

    /// Parse the EVM chain ID from an `eip155:<chain_id>` network string.
    #[must_use]
    pub fn evm_chain_id(&self) -> Option<u64> {
        self.network
            .strip_prefix("eip155:")
            .and_then(|s| s.parse().ok())
    }

    /// The facilitator pubkey that will co-sign as fee payer, if the server
    /// named one.
    #[must_use]
    pub fn fee_payer_pubkey(&self) -> Option<&str> {
        self.extra.as_ref()?.fee_payer.as_deref()
    }

    /// The memo the server requires for transaction uniqueness, if any.
    #[must_use]
    pub fn memo_value(&self) -> Option<&str> {
        self.extra.as_ref()?.memo.as_deref()
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{
        BASE_MAINNET_CAIP2, PaymentChain, PaymentRequired, PaymentRequirements,
        SOLANA_MAINNET_CAIP2, X402_VERSION,
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
}
