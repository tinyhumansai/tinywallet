//! Wire types for the x402 `sign-in-with-x` extension (CAIP-122).
//!
//! A server that needs to know *who* is calling, rather than to be paid,
//! answers 402 with this extension in `PAYMENT-REQUIRED.extensions`. The client
//! signs the described sign-in message and retries with the
//! `SIGN-IN-WITH-X` header: base64 of a [`SiwxPayload`].

use serde::{Deserialize, Serialize};

/// The extension key in `PaymentRequired.extensions`.
pub const SIGN_IN_WITH_X: &str = "sign-in-with-x";

/// The request header carrying the signed proof.
pub const HEADER_SIGN_IN_WITH_X: &str = "SIGN-IN-WITH-X";

/// The server's `sign-in-with-x` declaration. Its JSON `schema` is not read.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxExtension {
    /// The message fields the server issued.
    pub info: SiwxInfo,
    /// The chains, and signature types, the server verifies.
    pub supported_chains: Vec<SiwxSupportedChain>,
}

/// The message fields a server issues for one sign-in (EIP-4361 / CAIP-122).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxInfo {
    /// The host (and port) asking for the sign-in.
    pub domain: String,
    /// The resource the sign-in is for.
    pub uri: String,
    /// A human-readable statement shown with the message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// The message version; `"1"`.
    pub version: String,
    /// The server's single-use nonce.
    pub nonce: String,
    /// RFC 3339 issue time.
    pub issued_at: String,
    /// RFC 3339 time after which the signed message is void.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// RFC 3339 time before which the signed message is not valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// The server's request identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// URIs the sign-in grants access to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
}

/// One chain a server accepts a sign-in from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxSupportedChain {
    /// CAIP-2 chain id, such as `eip155:8453`.
    pub chain_id: String,
    /// The signature type: `eip191` for EVM accounts, `ed25519` for Solana.
    #[serde(rename = "type")]
    pub kind: String,
    /// The verification scheme, when the server names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
}

/// The signed proof, sent base64-encoded in the `SIGN-IN-WITH-X` header.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiwxPayload {
    /// As issued.
    pub domain: String,
    /// The signing account, EIP-55 checksummed.
    pub address: String,
    /// As issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    /// As issued.
    pub uri: String,
    /// As issued.
    pub version: String,
    /// The chosen CAIP-2 chain id.
    pub chain_id: String,
    /// The chosen signature type.
    #[serde(rename = "type")]
    pub kind: String,
    /// As issued.
    pub nonce: String,
    /// As issued.
    pub issued_at: String,
    /// As issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    /// As issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    /// As issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// As issued.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<Vec<String>>,
    /// The `0x` hex signature over the sign-in message.
    pub signature: String,
}
