//! The x402 spending ledger: what has been paid, and what may still be.
//!
//! Rail-neutral by design. A record says *who was paid how much, when, and with
//! what outcome*; it does not care whether the money moved on a chain or on a
//! card network, which is why nothing here imports a chain type. A future
//! payment rail can share this module unchanged.
//!
//! # Persistence
//!
//! The ledger persists through the runtime-neutral `tinystoragedrivers-api` ports; the
//! host hands in a [`LedgerStorage`] and decides the backend. Records are
//! appended to the `wallet.payments` stream. It is append-only: a payment that
//! changes status is appended again with the same id, and readers see every
//! entry. Entries that no longer parse are skipped with a warning rather than
//! failing the load. A storage that cannot be read refuses to open, since a
//! ledger blind to its history would admit payments past the budget.
//!
//! Entries are `snake_case` objects with every instant an epoch-millisecond
//! `*_ms` field. The ledger applies its own v1 to v2 migration when opened.
//! Hosts can inspect [`collections`] to ensure the module-bound declarations.
//!
//! # Budgets
//!
//! [`PaymentLedger::check_budget`] enforces a per-request cap and daily and
//! monthly totals over settled payments, unresolved signed authorizations, and
//! outstanding reservations. Requests above the per-request cap are refused
//! before reading storage, since shared state cannot change that verdict.
//! A bounded authorization is charged to each
//! calendar window it could have settled in. Once the proof is no longer
//! usable, future non-overlapping windows can admit new spending, while the
//! unresolved amount remains in durable outstanding totals until a trusted
//! receipt resolves it. Rails without trustworthy expiry evidence remain
//! conservatively charged to future windows.
//!
//! # Reservations
//!
//! A payment is checked, signed, sent and only then recorded, and other payments
//! run in between. Checking alone would let two concurrent payments that each fit
//! together overspend. [`reserve`] (or [`PaymentLedger::reserve`]) therefore
//! checks and holds the amount in one critical section, before anything is
//! signed. The hold is a [`Reservation`]: dropped, it releases; committed with
//! [`Reservation::commit_durable`], it turns into the recorded payment.
//!
//! Holds live in one `wallet.budgets/holds` document that every writer on the
//! storage updates by compare-and-swap, so the check-and-hold is atomic across
//! processes, not only across threads. A hold expires after 15 minutes so a
//! crashed process cannot lock budget forever, and a live owner extends the lease
//! with [`PaymentLedger::renew_holds`] every [`HOLD_RENEW_EVERY`]; once the signed authorization is
//! durably recorded, that record protects the budget across restart. Commit
//! entries include the owner-qualified hold key as internal stream metadata.
//! Readers exclude that hold once they see the durable entry, even if the
//! writer is paused before releasing it. Older entries without this metadata
//! remain readable and keep conservative accounting until their holds release.
//!
//! # The process-wide handle
//!
//! Hosts initialise one ledger at boot with [`init_global`] and reach it with
//! [`with_ledger`] / [`with_ledger_mut`]. The handle is the only shared state in
//! this crate.

mod blocking;
#[cfg(test)]
pub(crate) mod faulty;
mod global;
mod persist;
mod reservation;
mod schema;
mod store;
mod types;

#[cfg(test)]
pub(crate) use global::{TEST_LOCK, reset_global};
pub use global::{clear_global, init_global, with_ledger, with_ledger_mut};
pub use persist::{HOLD_RENEW_EVERY, LedgerStorage};
pub use reservation::{Reservation, reserve};
pub use schema::collections;
pub use store::PaymentLedger;
pub use types::{
    BudgetCheck, BudgetRefusal, PaymentRecord, PaymentStatus, ReservationId, SpendingBudget,
    SpendingSummary, format_usdc,
};

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;

#[cfg(test)]
#[path = "mod_authorization_tests.rs"]
mod authorization_test;

#[cfg(test)]
#[path = "mod_holds_tests.rs"]
mod holds_test;

#[cfg(test)]
#[path = "mod_paging_tests.rs"]
mod paging_test;
