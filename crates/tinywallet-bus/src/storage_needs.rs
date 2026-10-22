//! The storage resources the x402 ledger requires from its host.

use std::sync::LazyLock;

use crate::storage_names::{BUDGETS_COLLECTION, PAYMENTS_STREAM};
use tinystoragedrivers_bus_contract::CollectionSpec;

/// The storage resources the x402 ledger requests from its host.
///
/// This is `TinyWallet`'s host-facing declaration, not a `TinyStorageDrivers`
/// contract type. TSD v2 publishes the individual storage types and ports but
/// no aggregate `StorageNeeds` type.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct StorageNeeds<'a> {
    /// Collection schemas the module requests.
    pub collections: &'a [CollectionSpec],
    /// Blob key prefixes the module requests.
    pub blob_prefixes: &'a [&'a str],
    /// Stream name prefixes the module requests.
    pub stream_prefixes: &'a [&'a str],
    /// Secret name prefixes the module requests.
    pub secret_prefixes: &'a [&'a str],
}

impl std::fmt::Debug for StorageNeeds<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageNeeds")
            .field("collections", &self.collections.len())
            .field("blob_prefixes", &self.blob_prefixes.len())
            .field("stream_prefixes", &self.stream_prefixes.len())
            .field("secret_prefixes", &"[REDACTED]")
            .finish()
    }
}

/// Compatibility name for the current budget-hold collection.
pub const X402_BUDGET_COLLECTION: &str = BUDGETS_COLLECTION;
/// Compatibility name for the current payment stream.
pub const X402_PAYMENTS_STREAM_PREFIX: &str = PAYMENTS_STREAM;

static COLLECTIONS: LazyLock<[CollectionSpec; 1]> = LazyLock::new(|| {
    [CollectionSpec {
        name: BUDGETS_COLLECTION.to_owned(),
        indexes: Vec::new(),
        ttl_field: None,
        search: None,
    }]
});
static STREAM_PREFIXES: [&str; 1] = [PAYMENTS_STREAM];

/// Return the minimal host storage declaration for x402 ledger persistence.
///
/// It requests one hold-document collection and the payment stream. It
/// requires no indexes, expiry, search, blobs, or secrets. The owned collection
/// schema is initialized once so this borrowed declaration can live for
/// `'static` without copying the canonical storage-driver collection type.
#[must_use]
pub fn storage_needs() -> StorageNeeds<'static> {
    StorageNeeds {
        collections: &COLLECTIONS[..],
        blob_prefixes: &[],
        stream_prefixes: &STREAM_PREFIXES,
        secret_prefixes: &[],
    }
}
