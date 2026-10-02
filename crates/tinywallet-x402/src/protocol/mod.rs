//! The x402 client protocol: read a 402 challenge, get it paid, retry.
//!
//! Rail-neutral. Nothing here signs, derives a key or names a chain's
//! transaction format; the step that turns a challenge into a payment proof is
//! the [`PaymentBuilder`] seam, and the crypto rail's implementation lives in
//! [`crate::crypto`].
//!
//! ## Module layout
//!
//! - `error` — the client's error type ([`X402Error`]).
//! - `headers` — parsing the challenge and settlement headers and encoding the
//!   proof.
//! - `builder` — the [`PaymentBuilder`] seam.
//! - `select` — picking the requirement to pay, and the network/asset allowlist.
//! - `proxy` — the [`ProxyPolicy`] seam for outbound HTTP.
//! - `client` — [`X402Client`] and the `handle_402*` entry points.

mod builder;
mod client;
mod error;
mod headers;
mod proxy;
mod select;

pub use builder::PaymentBuilder;
pub use client::{
    X402Client, X402PaymentResult, handle_402, handle_402_and_pay, pay_challenge_header,
};
pub use error::X402Error;
pub use headers::{encode_payment, parse_402_headers, parse_settlement_response};
pub use proxy::ProxyPolicy;

pub(crate) const LOG_PREFIX: &str = "[x402]";

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
