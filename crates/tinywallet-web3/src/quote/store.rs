//! A short-lived, capped, in-memory store of prepared quotes with an
//! owner-gated `take`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use parking_lot::Mutex;

use super::types::{QuoteOwner, Quoted};

const LOG_PREFIX: &str = "[quote]";

/// Milliseconds since the Unix epoch, or `0` if the clock is before it.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
}

/// The prepare-then-execute store.
///
/// Instance-owned rather than a global: a host builds one per flow and hands it
/// to the engine that needs it, so two engines in one process never see each
/// other's quotes.
///
/// # Rules
///
/// - A quote expires `ttl_ms` after it was stored, and the store holds at most
///   `cap` quotes; storing one more evicts the oldest.
/// - [`QuoteStore::take_for`] removes the quote *before* the caller acts on it,
///   so two concurrent confirmations cannot both pass and double-submit. A
///   caller whose action fails hands it back with [`QuoteStore::restore`].
/// - `take_for` checks the owner before status and expiry, and answers a
///   mismatch with exactly the not-found text, so a leaked quote id gives no
///   enumeration oracle.
#[derive(Debug)]
pub struct QuoteStore<T> {
    prefix: &'static str,
    ttl_ms: u64,
    cap: usize,
    counter: AtomicU64,
    quotes: Mutex<Vec<T>>,
}

impl<T: Quoted + Clone> QuoteStore<T> {
    /// A store whose ids start with `prefix`, with the given lifetime and
    /// capacity.
    #[must_use]
    pub const fn new(prefix: &'static str, ttl_ms: u64, cap: usize) -> Self {
        Self {
            prefix,
            ttl_ms,
            cap,
            counter: AtomicU64::new(1),
            quotes: Mutex::new(Vec::new()),
        }
    }

    /// How long a quote lives, in milliseconds.
    #[must_use]
    pub const fn ttl_ms(&self) -> u64 {
        self.ttl_ms
    }

    /// A fresh quote id: `<prefix>_<now_ms>_<counter>`.
    #[must_use]
    pub fn next_id(&self) -> String {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        format!("{}_{}_{}", self.prefix, now_ms(), n)
    }

    /// Store `quote`, dropping expired and consumed quotes and evicting the
    /// oldest when the store is full, and return a copy for the caller.
    pub fn insert(&self, quote: T) -> T {
        let now = now_ms();
        let mut store = self.quotes.lock();
        store.retain(|q| q.expires_at_ms() > now && !q.is_consumed());
        if store.len() >= self.cap {
            store.remove(0);
        }
        store.push(quote.clone());
        quote
    }

    /// Put a quote back after a failed execute, with a fresh lifetime.
    ///
    /// A slow chain call can chew through the original budget, and handing back
    /// an already-expired quote would make the retry impossible.
    pub fn restore(&self, mut quote: T) {
        quote.set_expires_at_ms(now_ms().saturating_add(self.ttl_ms));
        self.insert(quote);
    }

    /// Remove and return the quote if, and only if, `caller` is its owner.
    ///
    /// # Errors
    ///
    /// `quote '<id>' not found` when there is no such quote **or** the owner
    /// does not match (the two are deliberately identical), `quote '<id>'
    /// already executed` for a consumed quote and `quote '<id>' expired` for a
    /// stale one. A caller with no chat context can only take quotes prepared
    /// with no chat context, which stops a background flow from picking up an
    /// interactive user's quote.
    pub fn take_for(&self, quote_id: &str, caller: Option<&QuoteOwner>) -> Result<T, String> {
        let not_found = || format!("quote '{quote_id}' not found");
        let mut store = self.quotes.lock();
        let now = now_ms();
        let pos = store
            .iter()
            .position(|q| q.quote_id() == quote_id)
            .ok_or_else(not_found)?;
        // The owner check comes first so a mismatch is byte-equal to the
        // not-found path, and a mismatched caller cannot poison the store by
        // consuming someone else's quote.
        if store[pos].owner() != caller {
            debug!(
                "{LOG_PREFIX} take_for quote_id={quote_id} owner_mismatch (caller_has_ctx={})",
                caller.is_some()
            );
            return Err(not_found());
        }
        let quote = store.remove(pos);
        if quote.is_consumed() {
            return Err(format!("quote '{quote_id}' already executed"));
        }
        if quote.expires_at_ms() <= now {
            return Err(format!("quote '{quote_id}' expired"));
        }
        Ok(quote)
    }

    /// Every quote that can still be executed.
    #[must_use]
    pub fn live(&self) -> Vec<T> {
        let now = now_ms();
        self.quotes
            .lock()
            .iter()
            .filter(|q| q.expires_at_ms() > now && !q.is_consumed())
            .cloned()
            .collect()
    }

    /// Number of stored quotes, live or not.
    #[must_use]
    pub fn len(&self) -> usize {
        self.quotes.lock().len()
    }

    /// Whether the store holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.quotes.lock().is_empty()
    }
}
