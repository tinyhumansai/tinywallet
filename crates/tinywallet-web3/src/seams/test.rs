//! Tests for the rail-neutral seams.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{NoQuoteScope, QuoteScope};

#[test]
fn the_no_op_scope_is_anonymous() {
    assert_eq!(NoQuoteScope.current_owner(), None);
}

/// The scope is a task-local read in every real host; this pins that a scope is
/// usable as a trait object shared across threads.
#[test]
fn a_scope_is_a_shareable_trait_object() {
    let scope: std::sync::Arc<dyn QuoteScope> = std::sync::Arc::new(NoQuoteScope);
    let handle = std::thread::spawn(move || scope.current_owner());
    assert_eq!(handle.join().unwrap(), None);
}
