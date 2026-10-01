//! Seams that are neutral about the payment rail.
//!
//! The crypto-specific seams (signer, accounts, endpoints, backend) live in
//! [`crate::crypto::seams`]; only what a non-crypto rail would also need is
//! here.

use crate::quote::QuoteOwner;

/// Says which chat thread is asking, so a quote can be bound to the thread that
/// prepared it.
///
/// # Contract
///
/// [`QuoteScope::current_owner`] is **synchronous** and is called on the task
/// that runs the tool. A host typically reads a `tokio` task-local, which
/// propagates across `.await` but not across `tokio::spawn`; if the tool loop
/// is ever detached onto a fresh task without re-installing the scope, this
/// silently starts returning `None` and the owner gate becomes a no-op. Keep
/// prepare and execute inline within the scope.
pub trait QuoteScope: Send + Sync {
    /// The owner of the current turn, or `None` for callers outside a chat turn
    /// (CLI, direct RPC, background work). Such callers stay executable without
    /// an owner gate because they have no shared channel a quote id could leak
    /// through.
    fn current_owner(&self) -> Option<QuoteOwner>;
}

/// A scope with no chat context: every caller is anonymous.
///
/// For embedders that have no notion of a chat thread. Quotes prepared under it
/// carry no owner, so only anonymous callers can execute them.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoQuoteScope;

impl QuoteScope for NoQuoteScope {
    fn current_owner(&self) -> Option<QuoteOwner> {
        None
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
