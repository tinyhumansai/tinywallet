//! Tests for the session seam.

use super::*;

#[test]
fn the_default_scope_has_no_active_session() {
    assert_eq!(NoSession.current_session(), None);
}

#[test]
fn a_scope_is_usable_as_a_shared_trait_object() {
    let scope: std::sync::Arc<dyn SessionScope> = std::sync::Arc::new(NoSession);
    assert_eq!(scope.current_session(), None);
    assert!(format!("{NoSession:?}").starts_with("NoSession"));
}
