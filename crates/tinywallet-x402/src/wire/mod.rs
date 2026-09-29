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

mod types;

pub use types::{
    BASE_MAINNET_CAIP2, BASE_SEPOLIA_CAIP2, COMPUTE_BUDGET_PROGRAM, ETHEREUM_MAINNET_CAIP2,
    EvmAuthorization, EvmPaymentProof, HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_REQUIRED_V1,
    HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SIGNATURE, HEADER_PAYMENT_SIGNATURE_V1, PaymentChain,
    PaymentExtra, PaymentPayload, PaymentProof, PaymentRequired, PaymentRequirements, ResourceInfo,
    SOLANA_DEVNET_CAIP2, SOLANA_MAINNET_CAIP2, SPL_MEMO_PROGRAM, SPL_TOKEN_PROGRAM,
    SettlementResponse, SolanaPaymentProof, USDC_BASE_MAINNET, USDC_BASE_SEPOLIA,
    USDC_ETHEREUM_MAINNET, USDC_MINT_DEVNET, USDC_MINT_MAINNET, X402_VERSION,
};
