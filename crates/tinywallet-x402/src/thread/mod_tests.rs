//! Tests for the thread seam.

use super::*;

#[test]
fn the_default_scope_has_no_active_thread() {
    assert_eq!(NoThread.current_thread(), None);
}

#[test]
fn a_scope_is_usable_as_a_shared_trait_object() {
    let scope: std::sync::Arc<dyn ThreadScope> = std::sync::Arc::new(NoThread);
    assert_eq!(scope.current_thread(), None);
    assert!(format!("{NoThread:?}").starts_with("NoThread"));
}
