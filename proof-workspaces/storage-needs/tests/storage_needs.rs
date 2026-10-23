//! An excluded downstream consumer of the published storage-needs contract.

#[test]
fn declaration_uses_the_wallet_contract_type_and_only_ledger_resources() {
    let needs: tinywallet_bus::StorageNeeds<'static> = tinywallet_bus::storage_needs();

    assert_eq!(needs.collections.len(), 1);
    let collection = &needs.collections[0];
    assert_eq!(collection.name, "wallet.budgets");
    assert!(collection.indexes.is_empty());
    assert_eq!(collection.ttl_field, None);
    assert_eq!(collection.search, None);
    assert_eq!(needs.stream_prefixes, ["wallet.payments"]);
    assert!(needs.blob_prefixes.is_empty());
    assert!(needs.secret_prefixes.is_empty());
}
