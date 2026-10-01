//! The x402 spending ledger: what has been paid, and what may still be.
//!
//! Rail-neutral by design. A record says *who was paid how much, when, and with
//! what outcome*; it does not care whether the money moved on a chain or on a
//! card network, which is why nothing here imports a chain type. A future
//! payment rail can share this module unchanged.
//!
//! # Persistence
//!
//! Records are appended as JSON lines to `<workspace>/x402/payments.jsonl`. The
//! file is append-only: a payment that changes status is written again with the
//! same id, and readers see every line. Unreadable or corrupt lines are skipped
//! with a warning rather than failing the load, since a ledger that refuses to
//! open would block every future payment.
//!
//! # Budgets
//!
//! [`PaymentLedger::check_budget`] enforces a per-request cap and daily and
//! monthly totals over *settled* payments plus outstanding reservations, so a
//! failed or denied attempt does not eat the budget.
//!
//! # Reservations
//!
//! A payment is checked, signed, sent and only then recorded, and other payments
//! run in between. Checking alone would let two concurrent payments that each fit
//! together overspend. [`reserve`] (or [`PaymentLedger::reserve`]) therefore
//! checks and holds the amount in one critical section, before anything is
//! signed. The hold is a [`Reservation`]: dropped, it releases; committed with
//! [`Reservation::commit`], it turns into the recorded payment atomically.
//! Holds live in memory only.
//!
//! # The process-wide handle
//!
//! Hosts initialise one ledger at boot with [`init_global`] and reach it with
//! [`with_ledger`] / [`with_ledger_mut`]. The handle is the only shared state in
//! this crate.

mod global;
mod reservation;
mod store;
mod types;

#[cfg(test)]
pub(crate) use global::{TEST_LOCK, reset_global};
pub use global::{init_global, with_ledger, with_ledger_mut};
pub use reservation::{Reservation, reserve};
pub use store::PaymentLedger;
pub use types::{
    BudgetCheck, BudgetRefusal, PaymentRecord, PaymentStatus, ReservationId, SpendingBudget,
    SpendingSummary,
};

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
