//! The rail-neutral half of the confirm-then-execute flow.
//!
//! Nothing here names a payment rail: a quote is an id, an owner and an
//! expiry, and the store enforces the rules around them. A card rail could
//! reuse this module unchanged; that is why it is kept apart from the crypto
//! code under [`crate::crypto`].
//!
//! - [`QuoteStore`] — the capped, TTL'd store with an owner-gated `take_for`.
//! - [`QuoteOwner`] and [`Quoted`] — the vocabulary the store speaks.
//! - [`WALLET_NOT_CONFIGURED_MESSAGE`] — the one error text hosts classify.
//! - [`execute_tool_schema`] (and `to_tool_result` with the `tools` feature) —
//!   the agent-tool plumbing every execute tool shares.

mod store;
mod tool;
mod types;

pub use store::{QuoteStore, now_ms};
pub use tool::execute_tool_schema;
#[cfg(feature = "tools")]
pub use tool::to_tool_result;
pub use types::{QuoteOwner, Quoted, WALLET_NOT_CONFIGURED_MESSAGE};

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
