//! Pure storage declarations the host can ensure before starting the module.

#[cfg(feature = "wire")]
use serde::{Deserialize, Serialize};

/// A host-facing declaration for a collection the wallet module uses.
///
/// The host translates this portable name into its own storage-driver type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "wire", derive(Serialize, Deserialize))]
pub struct CollectionDeclaration {
    /// Fully qualified collection name.
    pub name: String,
}

impl CollectionDeclaration {
    /// Declare a collection by its fully qualified name.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[cfg(feature = "wire")]
/// Payment lifecycle state in the canonical `wallet.payments` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoredPaymentStatus {
    /// Signed and sent, not yet settled.
    Pending,
    /// A trusted settlement receipt confirms payment.
    Settled,
    /// A trusted result established that the payment did not settle.
    Failed,
    /// Refused before anything was signed.
    Denied,
}

#[cfg(feature = "wire")]
/// Canonical body stored in the `wallet.payments` stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredPaymentRecord {
    /// Unique id of the attempt. A status change may produce another row with
    /// the same id; callers must preserve stream order and must not deduplicate.
    pub id: String,
    /// The URL the payment bought access to.
    pub url: String,
    /// The asset paid in.
    pub asset: String,
    /// The amount in atomic units of `asset`.
    pub amount_atomic: u64,
    /// The amount formatted for people.
    pub amount_display: String,
    /// Who was paid.
    pub recipient: String,
    /// The network, in CAIP-2 form.
    pub network: String,
    /// The settlement transaction, once reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_signature: Option<String>,
    /// Where the payment stands.
    pub status: StoredPaymentStatus,
    /// When this state was written, in epoch milliseconds.
    pub timestamp_ms: i64,
    /// When an exported authorization becomes unusable, in epoch milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_valid_until_ms: Option<i64>,
    /// Solana's `lastValidBlockHeight` for the exported transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana_last_valid_block_height: Option<u64>,
    /// When the authorization was observed expired, in epoch milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_expired_at_ms: Option<i64>,
    /// The block height at which the expiry was observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_expiry_observed_height: Option<u64>,
    /// The session that made the payment.
    pub session_id: String,
    /// The conversation thread, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    /// The budget hold this entry committed, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub committed_hold: Option<String>,
}

/// Collection names used by the wallet's persistent module storage.
///
/// Migration behavior remains in the x402 implementation. The host only needs
/// these declarations to ensure the collections in its already-bound scope.
#[must_use]
pub fn collections() -> Vec<CollectionDeclaration> {
    vec![
        CollectionDeclaration::new("wallet.budgets"),
        CollectionDeclaration::new("wallet.migrations"),
    ]
}
