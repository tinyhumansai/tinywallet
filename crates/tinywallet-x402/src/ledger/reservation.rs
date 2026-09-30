//! [`Reservation`]: a hold on the process-wide ledger's budget that cannot leak.

use log::debug;

use super::global::with_ledger_mut;
use super::types::{BudgetCheck, PaymentRecord, ReservationId};

const LOG_PREFIX: &str = "[x402::store]";

/// Budget held for one payment between the budget check and the moment its
/// outcome is recorded.
///
/// Dropping a `Reservation` releases the hold, so an error, an early return or a
/// cancelled future cannot leave part of the budget locked. To keep the amount
/// counted, [`commit`](Self::commit) the outcome instead: the record and the
/// release happen under one lock, so the amount is never missing from the
/// totals and never counted twice.
#[derive(Debug)]
pub struct Reservation {
    id: Option<ReservationId>,
    amount: u64,
}

impl Reservation {
    /// The amount held, in atomic units.
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.amount
    }

    /// Record the payment's outcome and end the hold in one critical section.
    pub fn commit(mut self, record: PaymentRecord) {
        if let Some(id) = self.id.take() {
            if with_ledger_mut(|l| l.commit_reservation(id, record)).is_err() {
                debug!("{LOG_PREFIX} commit skipped: ledger gone");
            }
        }
    }

    /// End the hold without recording anything. The same as dropping it.
    pub fn release(self) {}
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if let Some(id) = self.id.take() {
            // A ledger that was replaced or never set up holds nothing to free.
            let _ = with_ledger_mut(|l| l.release(id));
        }
    }
}

/// Check `amount` against the process-wide ledger's budget and hold it, atomically.
///
/// # Errors
///
/// The outer error is `"x402 payment ledger not initialized"`; the inner one is
/// the [`BudgetCheck`] verdict that refused the amount.
pub fn reserve(amount: u64) -> Result<Result<Reservation, BudgetCheck>, String> {
    with_ledger_mut(|l| {
        l.reserve(amount).map(|id| Reservation {
            id: Some(id),
            amount,
        })
    })
}
