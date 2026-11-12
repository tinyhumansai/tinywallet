//! The x402 machine-payment protocol (v2).
//!
//! x402 revives HTTP's long-unused `402 Payment Required`. A server answers a
//! request with a 402 and a `PAYMENT-REQUIRED` header describing what it will
//! accept; the client pays, retries with a `PAYMENT-SIGNATURE` header carrying
//! the proof, and the server settles it through a facilitator and answers with
//! `PAYMENT-RESPONSE`.
//!
//! This module owns the **wire types** — the header payloads and the rules for
//! reading them. Every header payload is standard-base64-encoded JSON, and
//! networks are named in [CAIP-2] form (`solana:…`, `eip155:8453`).
//!
//! ## Amounts are strings, and that is not laziness
//!
//! [`PaymentRequirements::amount`] is a `String` of atomic units, not a number.
//! JSON numbers are IEEE 754 doubles in most parsers, which cannot represent
//! every `u64` exactly — and a token amount that survives a round trip through
//! a JavaScript facilitator only approximately is a payment for the wrong sum.
//! The protocol carries them as decimal strings for that reason, and so does
//! this module.
//!
//! ## Which networks and assets are payable
//!
//! The server names the network and asset it wants, so [`check_usdc`] holds the
//! allowlist ([`SUPPORTED_USDC`]): USDC on the networks this crate knows, nothing
//! else. The selection helpers on [`PaymentRequired`] do not consult it; the
//! `protocol` module does before it selects or signs.
//!
//! ## The client signs an authorisation; the facilitator broadcasts
//!
//! In both supported schemes the payer never broadcasts. On Solana it hands
//! over a partially-signed transaction that the facilitator co-signs as fee
//! payer; on EVM it signs an EIP-3009 `transferWithAuthorization` the
//! facilitator submits. So a payment proof is a *capability someone else will
//! exercise* — which is why [`EvmAuthorization`] carries `valid_after`,
//! `valid_before` and a `nonce`: without them an authorisation would be
//! replayable indefinitely.
//!
//! [CAIP-2]: https://chainagnostic.org/CAIPs/caip-2

mod assets;
mod siwx;
#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
mod types;

pub use assets::{AssetCheck, SUPPORTED_USDC, check_usdc};
pub use siwx::{
    HEADER_SIGN_IN_WITH_X, SIGN_IN_WITH_X, SiwxExtension, SiwxInfo, SiwxPayload, SiwxSupportedChain,
};
pub use types::{
    BASE_MAINNET_CAIP2, BASE_SEPOLIA_CAIP2, COMPUTE_BUDGET_PROGRAM, EIP2612_GAS_SPONSORING,
    ETHEREUM_MAINNET_CAIP2, EvmAuthorization, EvmPaymentProof, HEADER_PAYMENT_REQUIRED,
    HEADER_PAYMENT_REQUIRED_V1, HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SIGNATURE,
    HEADER_PAYMENT_SIGNATURE_V1, PERMIT2_ADDRESS, PaymentChain, PaymentExtra, PaymentPayload,
    PaymentProof, PaymentRequired, PaymentRequirements, Permit2Authorization, Permit2PaymentProof,
    ResourceInfo, SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2, SPL_MEMO_PROGRAM, SPL_TOKEN_PROGRAM,
    SettlementResponse, SolanaPaymentProof, TokenPermissions, UPTO_PERMIT2_PROXY_ADDRESS,
    USDC_BASE_MAINNET, USDC_BASE_SEPOLIA, USDC_ETHEREUM_MAINNET, USDC_MINT_DEVNET,
    USDC_MINT_MAINNET, UptoWitness, X402_VERSION,
};
