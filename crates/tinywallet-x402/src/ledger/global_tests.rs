//! Tests for the process-wide ledger handle and its blocking helper.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn budget() -> SpendingBudget {
    SpendingBudget {
        per_request_max_atomic: 100,
        daily_max_atomic: 1_000,
        monthly_max_atomic: 10_000,
    }
}

#[test]
fn blocking_runs_the_closure_without_a_runtime() {
    assert_eq!(blocking(|| 7), 7);
}

#[tokio::test(flavor = "current_thread")]
async fn blocking_runs_inline_on_a_current_thread_runtime() {
    assert_eq!(blocking(|| 8), 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_yields_the_worker_on_a_multi_thread_runtime() {
    assert_eq!(blocking(|| 9), 9);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_global_ledger_lifecycle_runs_on_a_multi_thread_runtime() {
    let _guard = TEST_LOCK.lock().await;
    reset_global();
    assert!(with_ledger(|_| ()).is_err());
    assert!(with_ledger_mut(|_| ()).is_err());
    init_global(LedgerStorage::memory(), "global-test", budget()).unwrap();
    assert!(with_ledger(|_| ()).is_ok());
    assert!(with_ledger_mut(|_| ()).is_ok());
    clear_global();
    assert!(with_ledger(|_| ()).is_err());
}
