//! Authorization retention and durable-write regressions for the ledger.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Duration, TimeZone, Utc};

use super::faulty::append_raw;
use super::*;

const SESSION: &str = "session-a";
static NEXT_TEST_RECORD: AtomicU64 = AtomicU64::new(1);

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
        id: format!(
            "id-{amount}-{}-{}",
            timestamp.timestamp(),
            NEXT_TEST_RECORD.fetch_add(1, Ordering::Relaxed)
        ),
        url: "https://api.example.com/data".into(),
        asset: "USDC".into(),
        amount_atomic: amount,
        amount_display: format!("{amount} atomic"),
        recipient: "Recipient".into(),
        network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
        tx_signature: Some("sig123".into()),
        status,
        timestamp,
        authorization_valid_until: None,
        solana_last_valid_block_height: None,
        authorization_expired_at: None,
        authorization_expiry_observed_height: None,
        session_id: session.into(),
        thread_id: None,
        scheme: None,
    }
}

fn ledger_in(dir: &LedgerStorage) -> PaymentLedger {
    PaymentLedger::open(dir.clone(), SESSION, budget()).unwrap()
}

#[test]
fn expired_authorizations_remain_durable_but_stop_charging_future_windows() {
    let dir = LedgerStorage::memory();
    let mut ledger = PaymentLedger::open(
        dir.clone(),
        SESSION,
        SpendingBudget {
            per_request_max_atomic: 500_000,
            daily_max_atomic: 2_000_000,
            monthly_max_atomic: 10_000_000,
        },
    )
    .unwrap();
    let authorized_at = now();
    let tomorrow = authorized_at + Duration::days(1);
    let next_month = authorized_at + Duration::days(20);
    let mut authorization = record(1_800_000, PaymentStatus::Pending, authorized_at, SESSION);
    authorization.id = "possibly-settled-before-expiry".to_string();
    authorization.authorization_valid_until = Some(authorized_at + Duration::hours(1));
    ledger.try_record_payment(authorization).unwrap();

    assert_eq!(
        ledger.usable_pending_count(tomorrow),
        0,
        "an expired proof no longer occupies a preparation slot"
    );
    assert_eq!(
        ledger.check_budget_at(tomorrow, 300_000),
        BudgetCheck::Allowed,
        "an authorization that cannot be used tomorrow does not charge tomorrow's cap"
    );
    assert_eq!(
        ledger.check_budget_at(next_month, 300_000),
        BudgetCheck::Allowed,
        "an authorization that cannot be used next month does not charge next month's cap"
    );
    assert_eq!(
        ledger.outstanding_atomic(),
        1_800_000,
        "budget-window reclamation never discards durable unresolved value"
    );
    drop(ledger);

    let reopened = ledger_in(&dir);
    assert_eq!(
        reopened.check_budget_at(tomorrow, 300_000),
        BudgetCheck::Allowed,
        "restart preserves the authorization's bound and permits a later window"
    );
    assert_eq!(
        reopened.check_budget_at(next_month, 300_000),
        BudgetCheck::Allowed
    );
    assert_eq!(reopened.outstanding_atomic(), 1_800_000);
}

#[test]
fn bounded_authorization_still_counts_in_its_issue_month() {
    let dir = LedgerStorage::memory();
    let mut ledger = PaymentLedger::open(
        dir.clone(),
        SESSION,
        SpendingBudget {
            per_request_max_atomic: 500_000,
            daily_max_atomic: 3_000_000,
            monthly_max_atomic: 2_000_000,
        },
    )
    .unwrap();
    let mut authorization = record(1_800_000, PaymentStatus::Pending, now(), SESSION);
    authorization.id = "month-overlap".to_string();
    authorization.authorization_valid_until = Some(now() + Duration::hours(1));
    ledger.try_record_payment(authorization).unwrap();

    assert_eq!(
        ledger.check_budget_at(now() + Duration::days(5), 300_000),
        BudgetCheck::ExceedsMonthlyBudget {
            current: 1_800_000,
            cap: 2_000_000,
        },
        "an authorization remains charged to the month it could have settled in"
    );
}

#[test]
fn legacy_expiry_failed_rows_remain_conservatively_budgeted() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    let mut legacy = record(1_800_000, PaymentStatus::Failed, now(), SESSION);
    legacy.id = "legacy-expiry-failed".to_string();
    legacy.authorization_valid_until = Some(now() - Duration::seconds(1));
    ledger.try_record_payment(legacy).unwrap();

    assert_eq!(
        ledger.check_budget_at(now(), 300_000),
        BudgetCheck::ExceedsDailyBudget {
            current: 1_800_000,
            cap: 2_000_000
        },
        "older releases wrote Failed for timeout without settlement evidence"
    );
    drop(ledger);
    let reopened = ledger_in(&dir);
    assert_eq!(
        reopened.outstanding_atomic(),
        1_800_000,
        "the conservative hold survives process restart"
    );
}

#[test]
fn solana_expiry_requires_a_strictly_greater_finalized_height_and_keeps_value() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    let mut authorization = record(1_800_000, PaymentStatus::Pending, now(), SESSION);
    authorization.id = "solana-blockheight-bound".to_string();
    authorization.solana_last_valid_block_height = Some(900);
    ledger.try_record_payment(authorization).unwrap();
    let generation = ledger.generation();

    assert!(
        !ledger
            .observe_solana_expiry(
                generation,
                "solana-blockheight-bound",
                now(),
                900,
                900,
                now()
            )
            .unwrap()
    );
    assert_eq!(ledger.usable_pending_count(now()), 1);

    let observed_at = now() + Duration::days(1);
    assert!(
        ledger
            .observe_solana_expiry(
                generation,
                "solana-blockheight-bound",
                now(),
                900,
                901,
                observed_at
            )
            .unwrap()
    );
    assert_eq!(ledger.usable_pending_count(observed_at), 0);
    assert_eq!(ledger.outstanding_atomic(), 1_800_000);
    assert_eq!(
        ledger.check_budget_at(observed_at + Duration::days(1), 300_000),
        BudgetCheck::Allowed,
        "proven expired authorization does not consume a disjoint future window"
    );
    drop(ledger);

    let reopened = ledger_in(&dir);
    let latest = reopened.payment("solana-blockheight-bound").unwrap();
    assert_eq!(
        latest.timestamp,
        now(),
        "the original issue time is preserved"
    );
    assert_eq!(latest.solana_last_valid_block_height, Some(900));
    assert_eq!(latest.authorization_expiry_observed_height, Some(901));
    assert_eq!(latest.authorization_expired_at, Some(observed_at));
    assert_eq!(reopened.outstanding_atomic(), 1_800_000);
}

#[test]
fn a_late_receipt_wins_over_a_stale_solana_expiry_observation() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    let mut authorization = record(100_000, PaymentStatus::Pending, now(), SESSION);
    authorization.id = "solana-late-receipt".to_string();
    authorization.solana_last_valid_block_height = Some(900);
    ledger.try_record_payment(authorization.clone()).unwrap();

    authorization.status = PaymentStatus::Settled;
    authorization.timestamp += Duration::seconds(1);
    authorization.tx_signature = Some("trusted-receipt".to_string());
    ledger.try_record_payment(authorization).unwrap();
    let generation = ledger.generation();
    assert!(
        !ledger
            .observe_solana_expiry(
                generation,
                "solana-late-receipt",
                now(),
                900,
                901,
                now() + Duration::days(2),
            )
            .unwrap()
    );
    assert_eq!(
        ledger.payment("solana-late-receipt").unwrap().status,
        PaymentStatus::Settled
    );
    assert_eq!(ledger.recent_payments(2).len(), 2);
}

#[test]
fn legacy_unknown_authorizations_remain_conservative_in_future_windows() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    ledger
        .try_record_payment(record(1_800_000, PaymentStatus::Pending, now(), SESSION))
        .unwrap();

    assert_eq!(
        ledger.check_budget_at(now() + Duration::days(1), 300_000),
        BudgetCheck::ExceedsDailyBudget {
            current: 1_800_000,
            cap: 2_000_000,
        },
        "rows without rail-validity proof cannot be released by an assumed TTL"
    );
}

#[test]
fn pending_totals_saturate_instead_of_wrapping() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    ledger.record_payment(record(u64::MAX - 5, PaymentStatus::Pending, now(), SESSION));
    ledger.record_payment(record(10, PaymentStatus::Pending, now(), SESSION));
    assert_eq!(
        ledger.check_budget_at(now(), 1),
        BudgetCheck::ExceedsDailyBudget {
            current: u64::MAX,
            cap: 2_000_000
        }
    );
}

#[test]
fn adding_an_amount_past_the_maximum_cap_is_refused() {
    let dir = LedgerStorage::memory();
    let mut ledger = PaymentLedger::open(
        dir.clone(),
        SESSION,
        SpendingBudget {
            per_request_max_atomic: u64::MAX,
            daily_max_atomic: u64::MAX,
            monthly_max_atomic: u64::MAX,
        },
    )
    .unwrap();
    ledger.record_payment(record(
        u64::MAX - 10,
        PaymentStatus::Pending,
        now(),
        SESSION,
    ));

    assert_eq!(
        ledger.check_budget_at(now(), 20),
        BudgetCheck::ExceedsDailyBudget {
            current: u64::MAX - 10,
            cap: u64::MAX
        },
        "an addition that overflows a maximal configured cap must not wrap into admission"
    );
}

#[test]
fn the_latest_status_for_an_authorization_controls_budget_and_summary() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    let mut authorization = record(1_800_000, PaymentStatus::Pending, now(), SESSION);
    authorization.id = "same-authorization".to_string();
    ledger.record_payment(authorization.clone());

    authorization.status = PaymentStatus::Settled;
    ledger.record_payment(authorization.clone());
    assert_eq!(
        ledger.check_budget_at(now(), 300_000),
        BudgetCheck::ExceedsDailyBudget {
            current: 1_800_000,
            cap: 2_000_000
        }
    );
    assert_eq!(ledger.summary_at(now()).daily_total_atomic, 1_800_000);

    authorization.status = PaymentStatus::Failed;
    authorization.timestamp += Duration::seconds(1);
    ledger.record_payment(authorization);
    assert_eq!(ledger.check_budget_at(now(), 300_000), BudgetCheck::Allowed);
    assert_eq!(ledger.summary_at(now()), SpendingSummary::default());
    assert_eq!(
        ledger.recent_payments(3).len(),
        3,
        "history stays append-only"
    );
}

#[test]
fn a_durable_reservation_commit_survives_reopening_without_double_counting() {
    let _guard = TEST_LOCK.blocking_lock();
    let dir = LedgerStorage::memory();
    init_global(dir.clone(), SESSION, budget()).unwrap();

    reserve(5)
        .unwrap()
        .unwrap()
        .commit_durable(record(5, PaymentStatus::Pending, now(), SESSION))
        .unwrap();
    assert_eq!(with_ledger(PaymentLedger::reserved_atomic).unwrap(), 0);
    assert_eq!(with_ledger(PaymentLedger::pending_count).unwrap(), 1);
    assert_eq!(with_ledger(PaymentLedger::outstanding_atomic).unwrap(), 5);

    reset_global();
    init_global(dir.clone(), SESSION, budget()).unwrap();
    assert_eq!(with_ledger(PaymentLedger::pending_count).unwrap(), 1);
    assert_eq!(with_ledger(PaymentLedger::outstanding_atomic).unwrap(), 5);
    reset_global();
}

#[test]
fn durable_append_after_an_unparseable_stream_entry_still_loads() {
    let dir = LedgerStorage::memory();
    let mut ledger = ledger_in(&dir);
    let mut first = record(100_000, PaymentStatus::Pending, now(), SESSION);
    first.id = "first".to_string();
    ledger.try_record_payment(first).unwrap();

    append_raw(&dir, vec![serde_json::json!({"partial": true})]);

    let mut second = record(200_000, PaymentStatus::Pending, now(), SESSION);
    second.id = "durable-after-partial".to_string();
    ledger.try_record_payment(second).unwrap();

    let reopened = ledger_in(&dir);
    assert_eq!(
        reopened
            .payment("durable-after-partial")
            .unwrap()
            .amount_atomic,
        200_000,
        "a junk entry cannot hide a later exported authorization"
    );
    assert_eq!(reopened.pending_count(), 2);
}
