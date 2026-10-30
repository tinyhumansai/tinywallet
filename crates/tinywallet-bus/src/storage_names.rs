//! Canonical current and legacy names for wallet-owned storage resources.

/// Collection holding the single budget-hold document.
pub const BUDGETS_COLLECTION: &str = "wallet.budgets";
/// Append-only stream of payment records.
pub const PAYMENTS_STREAM: &str = "wallet.payments";
