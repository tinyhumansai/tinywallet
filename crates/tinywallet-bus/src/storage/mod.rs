//! Data-only x402 storage vocabulary shared by `TinyWallet` and its host.
//!
//! This module names the current wallet resources and stores the payment
//! record shape plus the host-authored readiness record. Schema declarations
//! and migration behavior belong to the x402 implementation crate.

mod payment;
mod readiness;

use tinystoragedrivers_bus_contract::CollectionSpec;

pub use super::storage_names::{
    BUDGETS_COLLECTION, BUDGETS_VERSION, HOLDS_ID, LEGACY_BUDGET_COLLECTION,
    LEGACY_PAYMENTS_STREAM, MIGRATION_READY_ID, OWNER, PAYMENTS_IMPORT_EPOCH, PAYMENTS_STREAM,
    STORAGE_SCHEMA_VERSION,
};
pub use payment::{StoredPayment, StoredPaymentStatus};
pub use readiness::StorageMigrationReady;

/// Collections the host should ensure in `TinyWallet`'s module storage scope.
#[must_use]
pub fn collections() -> Vec<CollectionSpec> {
    vec![CollectionSpec {
        name: BUDGETS_COLLECTION.to_owned(),
        indexes: Vec::new(),
        ttl_field: None,
        search: None,
    }]
}

#[cfg(test)]
#[path = "readiness_tests.rs"]
mod readiness_tests;
