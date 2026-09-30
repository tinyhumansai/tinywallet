//! Tests for the spending ledger: budgets, summaries, persistence, and the
//! process-wide handle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;

use chrono::{DateTime, Duration, TimeZone, Utc};

use super::*;

const SESSION: &str = "session-a";

fn budget() -> SpendingBudget {
    SpendingBudget {
        per_request_max_atomic: 500_000,
        daily_max_atomic: 2_000_000,
        monthly_max_atomic: 10_000_000,
    }
}

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 3, 15, 12, 0, 0).unwrap()
}

fn record(
    amount: u64,
    status: PaymentStatus,
    timestamp: DateTime<Utc>,
    session: &str,
) -> PaymentRecord {
    PaymentRecord {
        id: format!("id-{amount}-{}", timestamp.timestamp()),
        url: "https://api.example.com/data".into(),
        asset: "USDC".into(),
        amount_atomic: amount,
        amount_display: format!("{amount} atomic"),
        recipient: "Recipient".into(),
        network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
        tx_signature: Some("sig123".into()),
        status,
        timestamp,
        session_id: session.into(),
    }
}

fn ledger_in(dir: &tempfile::TempDir) -> PaymentLedger {
    PaymentLedger::new(dir.path(), SESSION, budget())
}

#[test]
fn the_default_budget_is_one_ten_and_a_hundred_usdc() {
    let b = SpendingBudget::default();
    assert_eq!(b.per_request_max_atomic, 1_000_000);
    assert_eq!(b.daily_max_atomic, 10_000_000);
    assert_eq!(b.monthly_max_atomic, 100_000_000);
}

#[test]
fn an_empty_ledger_allows_a_payment_within_the_limits() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = ledger_in(&dir);
    assert_eq!(ledger.check_budget(100_000), BudgetCheck::Allowed);
    assert_eq!(ledger.check_budget_at(now(), 500_000), BudgetCheck::Allowed);
}

#[test]
fn a_payment_over_the_per_request_cap_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        ledger_in(&dir).check_budget(600_000),
        BudgetCheck::ExceedsPerRequest {
            requested: 600_000,
            cap: 500_000
        }
    );
}

#[test]
fn settled_payments_today_count_against_the_daily_budget() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    ledger.record_payment(record(1_800_000, PaymentStatus::Settled, now(), SESSION));
    assert_eq!(
        ledger.check_budget_at(now(), 400_000),
        BudgetCheck::ExceedsDailyBudget {
            current: 1_800_000,
            cap: 2_000_000
        }
    );
    // Exactly reaching the cap is allowed; only exceeding it is not.
    assert_eq!(ledger.check_budget_at(now(), 200_000), BudgetCheck::Allowed);
}

#[test]
fn only_settled_payments_count_against_a_budget() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    for status in [
        PaymentStatus::Failed,
        PaymentStatus::Pending,
        PaymentStatus::Denied,
    ] {
        ledger.record_payment(record(1_800_000, status, now(), SESSION));
    }
    assert_eq!(ledger.check_budget_at(now(), 400_000), BudgetCheck::Allowed);
    assert_eq!(ledger.summary_at(now()), SpendingSummary::default());
}

#[test]
fn yesterdays_payments_count_against_the_month_but_not_the_day() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    let yesterday = now() - Duration::days(1);
    for _ in 0..5 {
        ledger.record_payment(record(
            1_900_000,
            PaymentStatus::Settled,
            yesterday,
            SESSION,
        ));
    }
    // 9.5M settled this month; the daily total is still zero.
    assert_eq!(ledger.check_budget_at(now(), 400_000), BudgetCheck::Allowed);
    assert_eq!(
        ledger.check_budget_at(now(), 500_000),
        BudgetCheck::Allowed,
        "9.5M + 0.5M reaches the monthly cap exactly"
    );
    ledger.record_payment(record(100_000, PaymentStatus::Settled, yesterday, SESSION));
    assert_eq!(
        ledger.check_budget_at(now(), 500_000),
        BudgetCheck::ExceedsMonthlyBudget {
            current: 9_600_000,
            cap: 10_000_000
        }
    );
}

#[test]
fn last_months_payments_do_not_count() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    let last_month = now() - Duration::days(40);
    ledger.record_payment(record(500_000, PaymentStatus::Settled, last_month, SESSION));
    let summary = ledger.summary_at(now());
    assert_eq!(summary.monthly_count, 0);
    assert_eq!(summary.daily_count, 0);
    assert_eq!(summary.session_count, 1, "the session total ignores dates");
}

#[test]
fn the_summary_splits_session_day_and_month() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    ledger.record_payment(record(100_000, PaymentStatus::Settled, now(), SESSION));
    ledger.record_payment(record(200_000, PaymentStatus::Settled, now(), SESSION));
    ledger.record_payment(record(50_000, PaymentStatus::Failed, now(), SESSION));
    ledger.record_payment(record(
        300_000,
        PaymentStatus::Settled,
        now() - Duration::days(2),
        "session-b",
    ));

    let summary = ledger.summary_at(now());
    assert_eq!(summary.session_total_atomic, 300_000);
    assert_eq!(summary.session_count, 2);
    assert_eq!(summary.daily_total_atomic, 300_000);
    assert_eq!(summary.daily_count, 2);
    assert_eq!(summary.monthly_total_atomic, 600_000);
    assert_eq!(summary.monthly_count, 3);

    // The wall-clock variant agrees on what it can: nothing is dated today.
    assert_eq!(ledger.summary().session_count, 2);
}

#[test]
fn recent_payments_are_newest_first_and_limited() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    for amount in [1, 2, 3, 4] {
        ledger.record_payment(record(amount, PaymentStatus::Settled, now(), SESSION));
    }
    let recent = ledger.recent_payments(2);
    assert_eq!(
        recent.iter().map(|r| r.amount_atomic).collect::<Vec<_>>(),
        vec![4, 3]
    );
    assert_eq!(ledger.recent_payments(99).len(), 4);
}

#[test]
fn updating_the_budget_takes_effect() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    assert_eq!(ledger.budget(), &budget());
    ledger.update_budget(SpendingBudget {
        per_request_max_atomic: 10,
        daily_max_atomic: 20,
        monthly_max_atomic: 30,
    });
    assert_eq!(ledger.budget().per_request_max_atomic, 10);
    assert_eq!(
        ledger.check_budget(11),
        BudgetCheck::ExceedsPerRequest {
            requested: 11,
            cap: 10
        }
    );
}

#[test]
fn records_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    {
        let mut ledger = ledger_in(&dir);
        ledger.record_payment(record(100_000, PaymentStatus::Settled, now(), SESSION));
        ledger.record_payment(record(200_000, PaymentStatus::Failed, now(), SESSION));
    }
    let reopened = PaymentLedger::new(dir.path(), "session-b", budget());
    let recent = reopened.recent_payments(10);
    assert_eq!(recent.len(), 2);
    assert_eq!(recent[0].status, PaymentStatus::Failed);
    assert_eq!(recent[1].amount_atomic, 100_000);
    let path = dir.path().join("x402").join("payments.jsonl");
    assert!(path.is_file(), "the JSONL file is under x402/");
}

#[test]
fn corrupt_and_blank_lines_are_skipped_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let good = serde_json::to_string(&record(1, PaymentStatus::Settled, now(), SESSION)).unwrap();
    let path = dir.path().join("x402");
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join("payments.jsonl"),
        format!("{good}\n\nnot json at all\n{{\"id\": 7}}\n{good}\n"),
    )
    .unwrap();
    assert_eq!(ledger_in(&dir).recent_payments(10).len(), 2);
}

#[test]
fn a_file_that_is_not_utf8_does_not_stop_the_load() {
    let dir = tempfile::tempdir().unwrap();
    let good = serde_json::to_string(&record(1, PaymentStatus::Settled, now(), SESSION)).unwrap();
    let path = dir.path().join("x402");
    fs::create_dir_all(&path).unwrap();
    let mut bytes = vec![0xff, 0xfe, b'\n'];
    bytes.extend(good.as_bytes());
    bytes.push(b'\n');
    fs::write(path.join("payments.jsonl"), bytes).unwrap();
    assert_eq!(ledger_in(&dir).recent_payments(10).len(), 1);
}

#[test]
fn a_payment_is_kept_in_memory_when_the_file_cannot_be_written() {
    let dir = tempfile::tempdir().unwrap();
    // `x402` exists as a *file*, so neither the directory nor the ledger file
    // can be created beneath it.
    fs::write(dir.path().join("x402"), b"in the way").unwrap();
    let mut ledger = ledger_in(&dir);
    ledger.record_payment(record(5, PaymentStatus::Settled, now(), SESSION));
    assert_eq!(ledger.recent_payments(10).len(), 1);
}

#[test]
fn a_payment_is_kept_in_memory_when_the_file_cannot_be_opened() {
    let dir = tempfile::tempdir().unwrap();
    // The ledger file's path is a directory: the parent exists, opening fails.
    fs::create_dir_all(dir.path().join("x402").join("payments.jsonl")).unwrap();
    let mut ledger = ledger_in(&dir);
    ledger.record_payment(record(5, PaymentStatus::Settled, now(), SESSION));
    assert_eq!(ledger.recent_payments(10).len(), 1);
}

#[test]
fn a_record_serialises_camel_case_with_snake_case_status() {
    let json = serde_json::to_value(record(7, PaymentStatus::Denied, now(), SESSION)).unwrap();
    assert_eq!(json["amountAtomic"], 7);
    assert_eq!(json["txSignature"], "sig123");
    assert_eq!(json["sessionId"], SESSION);
    assert_eq!(json["status"], "denied");
    let back: PaymentRecord = serde_json::from_value(json).unwrap();
    assert_eq!(back.status, PaymentStatus::Denied);
}

#[test]
fn the_global_ledger_errors_until_initialised_then_works() {
    let _guard = TEST_LOCK.blocking_lock();
    reset_global();

    assert_eq!(
        with_ledger(|_| ()).unwrap_err(),
        "x402 payment ledger not initialized"
    );
    assert_eq!(
        with_ledger_mut(|_| ()).unwrap_err(),
        "x402 payment ledger not initialized"
    );

    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());
    with_ledger_mut(|l| l.record_payment(record(9, PaymentStatus::Settled, Utc::now(), SESSION)))
        .unwrap();
    assert_eq!(with_ledger(|l| l.recent_payments(5).len()).unwrap(), 1);
    assert_eq!(
        with_ledger(|l| l.budget().daily_max_atomic).unwrap(),
        2_000_000
    );

    // Initialising again replaces the ledger with the one on disk.
    init_global(dir.path(), "session-b", SpendingBudget::default());
    assert_eq!(
        with_ledger(|l| l.budget().daily_max_atomic).unwrap(),
        10_000_000
    );
    reset_global();
}

#[test]
fn a_poisoned_global_lock_is_recovered() {
    let _guard = TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());
    let _ = std::panic::catch_unwind(|| {
        let _ = with_ledger(|_| panic!("poison the ledger lock"));
    });
    assert!(with_ledger(|l| l.recent_payments(1).len()).is_ok());
    reset_global();
}

// ---------------------------------------------------------------------------
// Reservations: check and hold in one critical section
// ---------------------------------------------------------------------------

#[test]
fn a_reservation_counts_against_the_daily_budget_until_released() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    // The day allows 2_000_000: four holds of 500_000 fit, a fifth does not.
    let ids: Vec<_> = (0..4)
        .map(|_| ledger.reserve_at(now(), 500_000).unwrap())
        .collect();
    assert_eq!(ledger.reserved_atomic(), 2_000_000);
    assert_eq!(
        ledger.reserve_at(now(), 1).unwrap_err(),
        BudgetCheck::ExceedsDailyBudget {
            current: 2_000_000,
            cap: 2_000_000
        }
    );

    ledger.release(ids[0]);
    assert_eq!(ledger.reserved_atomic(), 1_500_000);
    assert!(ledger.reserve_at(now(), 500_000).is_ok());
}

#[test]
fn a_reservation_counts_against_the_monthly_budget() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = PaymentLedger::new(
        dir.path(),
        SESSION,
        SpendingBudget {
            per_request_max_atomic: 500_000,
            daily_max_atomic: 10_000_000,
            monthly_max_atomic: 600_000,
        },
    );
    ledger.reserve_at(now(), 500_000).unwrap();
    assert_eq!(
        ledger.reserve_at(now(), 500_000).unwrap_err(),
        BudgetCheck::ExceedsMonthlyBudget {
            current: 500_000,
            cap: 600_000
        }
    );
}

#[test]
fn a_refused_reservation_holds_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    assert_eq!(
        ledger.reserve_at(now(), 600_000).unwrap_err(),
        BudgetCheck::ExceedsPerRequest {
            requested: 600_000,
            cap: 500_000
        }
    );
    assert_eq!(ledger.reserved_atomic(), 0);
}

#[test]
fn releasing_an_unknown_reservation_is_harmless() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    let id = ledger.reserve_at(now(), 1_000).unwrap();
    ledger.release(id);
    ledger.release(id);
    assert_eq!(ledger.reserved_atomic(), 0);
}

#[test]
fn committing_a_reservation_records_the_payment_and_frees_the_hold() {
    let dir = tempfile::tempdir().unwrap();
    let mut ledger = ledger_in(&dir);
    let id = ledger.reserve(400_000).unwrap();

    ledger.commit_reservation(id, record(400_000, PaymentStatus::Settled, Utc::now(), SESSION));

    assert_eq!(ledger.reserved_atomic(), 0);
    let summary = ledger.summary();
    assert_eq!(summary.daily_total_atomic, 400_000, "counted once, as settled");
    assert_eq!(ledger.recent_payments(5).len(), 1);
}

#[test]
fn the_ledger_reports_its_own_session_id() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(ledger_in(&dir).session_id(), SESSION);
}

#[test]
fn a_global_reservation_is_released_when_dropped() {
    let _guard = TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());

    let held = reserve(500_000).unwrap().unwrap();
    assert_eq!(held.amount(), 500_000);
    assert_eq!(with_ledger(PaymentLedger::reserved_atomic).unwrap(), 500_000);
    drop(held);
    assert_eq!(with_ledger(PaymentLedger::reserved_atomic).unwrap(), 0);
    reset_global();
}

#[test]
fn a_global_reservation_can_be_released_explicitly() {
    let _guard = TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());

    let held = reserve(500_000).unwrap().unwrap();
    held.release();
    assert_eq!(with_ledger(PaymentLedger::reserved_atomic).unwrap(), 0);
    reset_global();
}

#[test]
fn a_global_reservation_committed_is_recorded_once() {
    let _guard = TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());

    let held = reserve(500_000).unwrap().unwrap();
    held.commit(record(500_000, PaymentStatus::Settled, Utc::now(), SESSION));

    assert_eq!(with_ledger(PaymentLedger::reserved_atomic).unwrap(), 0);
    assert_eq!(
        with_ledger(|l| l.summary().daily_total_atomic).unwrap(),
        500_000
    );
    reset_global();
}

#[test]
fn a_global_reservation_is_refused_over_budget_and_needs_a_ledger() {
    let _guard = TEST_LOCK.blocking_lock();
    reset_global();
    assert_eq!(
        reserve(1).unwrap_err(),
        "x402 payment ledger not initialized"
    );

    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());
    assert_eq!(
        reserve(600_000).unwrap().unwrap_err(),
        BudgetCheck::ExceedsPerRequest {
            requested: 600_000,
            cap: 500_000
        }
    );
    reset_global();
}

#[test]
fn dropping_a_reservation_after_the_ledger_is_gone_is_harmless() {
    let _guard = TEST_LOCK.blocking_lock();
    let dir = tempfile::tempdir().unwrap();
    init_global(dir.path(), SESSION, budget());
    let held = reserve(500_000).unwrap().unwrap();
    reset_global();
    drop(held);

    // A new ledger never inherits an old hold, even if ids were reused.
    init_global(dir.path(), SESSION, budget());
    assert_eq!(with_ledger(PaymentLedger::reserved_atomic).unwrap(), 0);
    reset_global();
}
