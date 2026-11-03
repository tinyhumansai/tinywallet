//! Tests for the module's public storage declaration.

#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn every_stored_item_is_wallet_owned_and_module_scoped() {
    let collections = storage_collections()
        .into_iter()
        .map(|collection| collection.name)
        .collect::<Vec<_>>();
    for collection in &collections {
        assert!(collection.starts_with("wallet."), "{}", collection);
    }
    assert_eq!(
        collections,
        vec![
            "wallet.budgets".to_string(),
            "wallet.migrations".to_string()
        ]
    );
}
