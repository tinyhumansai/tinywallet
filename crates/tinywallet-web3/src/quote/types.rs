//! Vocabulary of the confirm-then-execute flow: who a quote belongs to, what a
//! store needs to know about a quote, and the one error text that means "no
//! wallet yet".

/// Error message returned when the wallet has not been set up yet.
///
/// This is an expected user-state (the user simply has not created a wallet),
/// not an internal failure. Downstream boundaries that surface this condition
/// match against this constant to classify it as an expected user state so it
/// stays out of error trackers. Keep it a shared constant so the producer here
/// and any classifier cannot drift apart.
pub const WALLET_NOT_CONFIGURED_MESSAGE: &str = "wallet is not configured; run wallet setup first";

/// Identity of the chat thread that prepared a quote.
///
/// A prepare/execute flow is keyed by a quote id, and quote ids are visible in
/// the shared chat broadcast (the prepared summary that gets sent back into the
/// channel). A co-channel caller can read another caller's quote id and try to
/// drive its execute from their own agent session. Binding the quote to the
/// originating chat thread closes that gap: execute is only allowed when the
/// caller's owner equals the prepare-time owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteOwner {
    /// The conversation thread the quote was prepared in.
    pub thread_id: String,
    /// The client (connection) that owns the thread.
    pub client_id: String,
}

/// What a [`QuoteStore`](super::QuoteStore) needs to know about a stored quote.
///
/// Implemented by each flow's own quote type, so the store stays generic over
/// what is being confirmed.
pub trait Quoted {
    /// The id a caller presents to execute the quote.
    fn quote_id(&self) -> &str;

    /// The owner stamped at prepare time, or `None` for callers outside a chat
    /// turn (CLI, direct RPC, background work).
    fn owner(&self) -> Option<&QuoteOwner>;

    /// Wall-clock expiry, in milliseconds since the Unix epoch.
    fn expires_at_ms(&self) -> u64;

    /// Move the expiry, used when a failed execute puts the quote back.
    fn set_expires_at_ms(&mut self, expires_at_ms: u64);

    /// Whether the quote has already been executed.
    ///
    /// Defaults to `false`: a quote type with no consumed state never reports
    /// "already executed".
    fn is_consumed(&self) -> bool {
        false
    }
}
