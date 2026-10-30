//! An excluded downstream consumer of the bus-owned collection contract.

#[test]
fn declarations_name_the_wallet_ledger_collections_without_storage_dependencies() {
    let collections = tinywallet_bus::storage::collections();

    assert_eq!(collections.len(), 2);
    assert_eq!(collections[0].name, "wallet.budgets");
    assert_eq!(collections[1].name, "wallet.migrations");
}
