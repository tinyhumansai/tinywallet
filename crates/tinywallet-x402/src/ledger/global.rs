//! The process-wide ledger handle.

use std::sync::{Mutex, MutexGuard, PoisonError};

use log::debug;

use super::persist::LedgerStorage;
use super::store::PaymentLedger;
use super::types::SpendingBudget;

const LOG_PREFIX: &str = "[x402::store]";
const NOT_INITIALISED: &str = "x402 payment ledger not initialized";

static GLOBAL_LEDGER: Mutex<Option<PaymentLedger>> = Mutex::new(None);

/// Run `f`, which blocks on storage (and on the ledger mutex), without holding
/// an async worker hostage.
///
/// On a multi-thread tokio runtime the worker hands its queue to another thread
/// first, so a storage transport that needs this same runtime to make progress
/// (the module's storage bus) cannot be starved by the callers waiting on it.
/// Anywhere else (no runtime, a current-thread runtime) `f` simply runs.
pub(crate) fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(f)
        }
        _ => f(),
    }
}

fn lock() -> MutexGuard<'static, Option<PaymentLedger>> {
    // A panic while holding the guard cannot leave the ledger half-written in a
    // way a reader could not tolerate, so a poisoned lock is recovered rather
    // than turning every later payment into an error.
    GLOBAL_LEDGER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Open the ledger over `storage` and make it the process-wide one, replacing
/// any earlier one.
///
/// The budget is the caller's to choose: where limits come from (defaults,
/// environment, settings) is host policy, and so is the storage backend.
///
/// # Errors
///
/// The storage cannot be opened or read. The previous process-wide ledger, if
/// any, is left in place.
pub fn init_global(
    storage: LedgerStorage,
    session_id: &str,
    budget: SpendingBudget,
) -> Result<(), String> {
    let ledger = blocking(|| PaymentLedger::open(storage, session_id, budget))?;
    blocking(|| *lock() = Some(ledger));
    debug!("{LOG_PREFIX} global ledger initialized");
    Ok(())
}

/// Drop the process-wide ledger after its owner has released all reservations.
pub fn clear_global() {
    blocking(|| *lock() = None);
    debug!("{LOG_PREFIX} global ledger cleared");
}

/// Run `f` over the process-wide ledger.
///
/// # Errors
///
/// `"x402 payment ledger not initialized"` before [`init_global`].
pub fn with_ledger<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&PaymentLedger) -> R,
{
    blocking(|| {
        let guard = lock();
        let ledger = guard.as_ref().ok_or_else(|| NOT_INITIALISED.to_string())?;
        Ok(f(ledger))
    })
}

/// Run `f` over the process-wide ledger, mutably.
///
/// # Errors
///
/// `"x402 payment ledger not initialized"` before [`init_global`].
pub fn with_ledger_mut<F, R>(f: F) -> Result<R, String>
where
    F: FnOnce(&mut PaymentLedger) -> R,
{
    blocking(|| {
        let mut guard = lock();
        let ledger = guard.as_mut().ok_or_else(|| NOT_INITIALISED.to_string())?;
        Ok(f(ledger))
    })
}

/// Serialises the tests that touch the process-wide ledger. An async mutex, so
/// an async test can hold it across its awaits.
#[cfg(test)]
pub(crate) static TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Drop the process-wide ledger, as at process start.
#[cfg(test)]
pub(crate) fn reset_global() {
    *lock() = None;
}

#[cfg(test)]
#[path = "global_tests.rs"]
mod tests;
