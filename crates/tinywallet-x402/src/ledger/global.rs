//! The process-wide ledger handle.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};

use log::debug;

use super::store::PaymentLedger;
use super::types::SpendingBudget;

const LOG_PREFIX: &str = "[x402::store]";
const NOT_INITIALISED: &str = "x402 payment ledger not initialized";

static GLOBAL_LEDGER: Mutex<Option<PaymentLedger>> = Mutex::new(None);

fn lock() -> MutexGuard<'static, Option<PaymentLedger>> {
    // A panic while holding the guard cannot leave the ledger half-written in a
    // way a reader could not tolerate, so a poisoned lock is recovered rather
    // than turning every later payment into an error.
    GLOBAL_LEDGER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Open the ledger under `workspace_dir` and make it the process-wide one,
/// replacing any earlier one.
///
/// The budget is the caller's to choose: where limits come from (defaults,
/// environment, settings) is host policy.
pub fn init_global(workspace_dir: &Path, session_id: &str, budget: SpendingBudget) {
    let ledger = PaymentLedger::new(workspace_dir, session_id, budget);
    *lock() = Some(ledger);
    debug!("{LOG_PREFIX} global ledger initialized");
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
    let guard = lock();
    let ledger = guard.as_ref().ok_or_else(|| NOT_INITIALISED.to_string())?;
    Ok(f(ledger))
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
    let mut guard = lock();
    let ledger = guard.as_mut().ok_or_else(|| NOT_INITIALISED.to_string())?;
    Ok(f(ledger))
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
