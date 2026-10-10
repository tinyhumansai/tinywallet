//! The `x402_request` agent tool.
//!
//! Unlike a general HTTP tool (which may treat a 402 as a fallback), this one is
//! purpose-built for x402 endpoints: it always expects a payment challenge,
//! surfaces pricing to the agent, and records every payment attempt in the
//! [ledger](crate::ledger).
//!
//! The tool owns no wallet and no proxy configuration. It is built from the
//! same seams the rest of the crate uses: a [`PaymentSigner`] and a
//! [`Transport`] for the crypto rail (or any [`PaymentBuilder`]), and a
//! [`ProxyPolicy`](crate::protocol::ProxyPolicy) for its outbound HTTP.
//!
//! [`PaymentSigner`]: crate::crypto::PaymentSigner
//! [`Transport`]: tinywallet_crypto::rpc::Transport
//! [`PaymentBuilder`]: crate::protocol::PaymentBuilder

mod request;

pub use request::{AuthorizedRequest, ProposedRequest, RequestGuard, X402RequestTool};

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
