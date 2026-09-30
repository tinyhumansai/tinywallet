//! The x402 client's error type.

/// Why an x402 payment or request failed.
///
/// The `Display` strings are user-visible (they reach the agent and the UI), so
/// they are pinned by tests.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum X402Error {
    /// The HTTP request itself failed.
    #[error("x402 transport: {0}")]
    Transport(reqwest::Error),
    /// A 402 arrived without a `PAYMENT-REQUIRED` header.
    #[error("402 response missing PAYMENT-REQUIRED header")]
    NoPaymentHeader,
    /// The challenge offers nothing this crate can pay.
    #[error("no supported payment option (Solana exact or EVM exact) in 402 challenge")]
    NoPaymentOption,
    /// One request would cost more than the per-request cap.
    #[error("x402 amount {requested} exceeds per-request cap {cap}")]
    AmountExceedsCap {
        /// The amount asked for.
        requested: u64,
        /// The cap it exceeded.
        cap: u64,
    },
    /// A daily or monthly budget would be exceeded.
    #[error("x402 {period} budget exceeded: {current}/{cap} atomic units")]
    BudgetExceeded {
        /// `"daily"` or `"monthly"`.
        period: &'static str,
        /// Settled so far in the period.
        current: u64,
        /// The period's cap.
        cap: u64,
    },
    /// The challenge names a network this crate does not pay on.
    #[error(
        "x402 network {network} is not supported; payments are accepted only in USDC on known networks"
    )]
    UnsupportedNetwork {
        /// The CAIP-2 network the challenge asked for.
        network: String,
    },
    /// The challenge asks for an asset other than the network's USDC.
    #[error("x402 asset {asset} is not the USDC accepted on {network}")]
    UnsupportedAsset {
        /// The CAIP-2 network the challenge asked for.
        network: String,
        /// The mint or contract it asked to be paid in.
        asset: String,
    },
    /// The request body is a stream, so it cannot be sent again with the payment.
    #[error("x402 request body cannot be replayed for the paid retry; use a buffered body")]
    NonReplayableBody,
    /// The challenge or a header could not be understood.
    #[error("x402 protocol: {0}")]
    Protocol(String),
    /// The wallet could not produce the payment.
    #[error("x402 wallet: {0}")]
    Wallet(String),
}
