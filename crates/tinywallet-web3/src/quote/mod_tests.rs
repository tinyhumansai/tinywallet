//! Tests for the quote store and its owner gate.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{QuoteOwner, QuoteStore, Quoted, execute_tool_schema, now_ms};

#[derive(Debug, Clone)]
struct Probe {
    id: String,
    owner: Option<QuoteOwner>,
    expires_at_ms: u64,
    consumed: bool,
}

impl Probe {
    fn live(id: &str, owner: Option<QuoteOwner>) -> Self {
        Self {
            id: id.to_string(),
            owner,
            expires_at_ms: now_ms() + 60_000,
            consumed: false,
        }
    }
}

impl Quoted for Probe {
    fn quote_id(&self) -> &str {
        &self.id
    }
    fn owner(&self) -> Option<&QuoteOwner> {
        self.owner.as_ref()
    }
    fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    fn set_expires_at_ms(&mut self, expires_at_ms: u64) {
        self.expires_at_ms = expires_at_ms;
    }
    fn is_consumed(&self) -> bool {
        self.consumed
    }
}

fn owner(name: &str) -> QuoteOwner {
    QuoteOwner {
        thread_id: format!("thread-{name}"),
        client_id: format!("client-{name}"),
    }
}

fn store() -> QuoteStore<Probe> {
    QuoteStore::new("t", 5 * 60 * 1000, 3)
}

#[test]
fn ids_are_unique_and_carry_the_prefix() {
    let store = store();
    let a = store.next_id();
    let b = store.next_id();
    assert_ne!(a, b);
    assert!(a.starts_with("t_"), "{a}");
    assert_eq!(store.ttl_ms(), 300_000);
}

#[test]
fn a_stored_quote_round_trips_once() {
    let store = store();
    store.insert(Probe::live("q1", None));
    assert_eq!(store.len(), 1);
    assert!(!store.is_empty());
    let taken = store.take_for("q1", None).unwrap();
    assert_eq!(taken.id, "q1");
    let err = store.take_for("q1", None).unwrap_err();
    assert_eq!(err, "quote 'q1' not found", "a taken quote is gone");
    assert!(store.is_empty());
}

#[test]
fn an_expired_quote_is_reported_expired() {
    let store = store();
    let mut stale = Probe::live("old", None);
    stale.expires_at_ms = now_ms().saturating_sub(1);
    // Insert directly through `insert`, which only purges *before* pushing.
    store.insert(stale);
    let err = store.take_for("old", None).unwrap_err();
    assert_eq!(err, "quote 'old' expired");
}

#[test]
fn a_consumed_quote_is_reported_executed() {
    let store = store();
    let mut used = Probe::live("used", None);
    used.consumed = true;
    store.insert(used);
    let err = store.take_for("used", None).unwrap_err();
    assert_eq!(err, "quote 'used' already executed");
}

#[test]
fn the_wrong_owner_gets_the_not_found_text_and_leaves_the_quote() {
    let store = store();
    store.insert(Probe::live("q", Some(owner("A"))));
    let mismatch = store.take_for("q", Some(&owner("B"))).unwrap_err();
    let missing = store.take_for("nope", Some(&owner("B"))).unwrap_err();
    assert_eq!(mismatch, "quote 'q' not found");
    assert_eq!(missing, "quote 'nope' not found");
    // The owner still has it: the failed attempt did not consume it.
    assert!(store.take_for("q", Some(&owner("A"))).is_ok());
}

#[test]
fn an_anonymous_caller_cannot_take_a_chat_quote_nor_the_reverse() {
    let store = store();
    store.insert(Probe::live("chat", Some(owner("A"))));
    store.insert(Probe::live("bg", None));
    assert!(store.take_for("chat", None).is_err());
    assert!(store.take_for("bg", Some(&owner("A"))).is_err());
    assert!(store.take_for("bg", None).is_ok());
}

#[test]
fn the_store_evicts_the_oldest_at_capacity() {
    let store = store();
    for id in ["a", "b", "c", "d"] {
        store.insert(Probe::live(id, None));
    }
    assert_eq!(store.len(), 3);
    assert!(store.take_for("a", None).is_err(), "oldest was evicted");
    assert!(store.take_for("d", None).is_ok());
}

#[test]
fn inserting_drops_expired_and_consumed_quotes() {
    let store = store();
    let mut stale = Probe::live("stale", None);
    stale.expires_at_ms = now_ms().saturating_sub(1);
    let mut used = Probe::live("used", None);
    used.consumed = true;
    store.insert(stale);
    store.insert(used);
    store.insert(Probe::live("fresh", None));
    let live: Vec<String> = store.live().into_iter().map(|p| p.id).collect();
    assert_eq!(live, vec!["fresh".to_string()]);
    assert_eq!(store.len(), 1, "expired and consumed quotes were purged");
}

#[test]
fn restore_refreshes_the_lifetime() {
    let store = store();
    let mut nearly_gone = Probe::live("q", None);
    nearly_gone.expires_at_ms = now_ms() + 1;
    store.restore(nearly_gone);
    let taken = store.take_for("q", None).unwrap();
    assert!(
        taken.expires_at_ms > now_ms() + 200_000,
        "lifetime refreshed"
    );
}

#[test]
fn the_execute_schema_requires_the_quote_id_and_confirmation() {
    let schema = execute_tool_schema();
    assert_eq!(
        schema["required"],
        serde_json::json!(["quoteId", "confirmed"])
    );
    assert_eq!(schema["additionalProperties"], false);
}

#[cfg(feature = "tools")]
#[test]
fn tool_results_are_pretty_json_or_the_error_text() {
    use super::to_tool_result;
    let ok = to_tool_result(Ok::<_, String>(serde_json::json!({"a": 1})));
    assert!(!ok.is_error, "{ok:?}");
    assert!(ok.output().contains("\"a\": 1"), "{ok:?}");
    let err = to_tool_result::<()>(Err("boom".to_string()));
    assert!(err.is_error);
    assert_eq!(err.output(), "boom");
}

#[cfg(feature = "tools")]
#[test]
fn an_unserializable_result_becomes_an_error_result() {
    use super::to_tool_result;
    // JSON object keys must be strings, so a map keyed by a tuple cannot be
    // serialized.
    let mut unserializable = std::collections::HashMap::new();
    unserializable.insert((1, 2), 3);
    let result = to_tool_result(Ok::<_, String>(unserializable));
    assert!(result.is_error);
    assert!(
        result
            .output()
            .starts_with("failed to serialize web3 result:"),
        "{}",
        result.output()
    );
}
