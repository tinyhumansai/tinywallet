//! Tests for `upto` payments in the ledger: the scheme is kept with the
//! record, and settling for less than the signed ceiling frees the rest.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;

use super::*;

fn budget() -> SpendingBudget {
    SpendingBudget {
        per_request_max_atomic: 10_000,
        daily_max_atomic: 10_000,
        monthly_max_atomic: 100_000,
    }
}

fn upto(status: PaymentStatus, amount: u64) -> PaymentRecord {
    PaymentRecord {
        id: "upto-1".into(),
        url: "https://twitr.sh/api/tools/x_search".into(),
        asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913".into(),
        amount_atomic: amount,
        amount_display: format_usdc(amount),
        recipient: "0xb5194A98DbDBb7028B585Db26B972e7F0F3f826A".into(),
        network: "eip155:8453".into(),
        tx_signature: None,
        status,
        timestamp: Utc::now(),
        authorization_valid_until: Some(Utc::now() + chrono::Duration::minutes(5)),
        solana_last_valid_block_height: None,
        authorization_expired_at: None,
        authorization_expiry_observed_height: None,
        session_id: "s".into(),
        thread_id: None,
        scheme: Some("upto".into()),
    }
}

#[test]
fn the_scheme_survives_a_reopen() {
    let storage = LedgerStorage::memory();
    let mut ledger = PaymentLedger::open(storage.clone(), "s", budget()).unwrap();
    ledger.try_record_payment(upto(PaymentStatus::Pending, 3600)).unwrap();
    drop(ledger);
    let reopened = PaymentLedger::open(storage, "s", budget()).unwrap();
    assert_eq!(
        reopened.payment("upto-1").unwrap().scheme.as_deref(),
        Some("upto")
    );
}

#[test]
fn settling_below_the_ceiling_releases_the_rest_of_the_budget() {
    for actual in [1200, 0] {
        let mut ledger =
            PaymentLedger::open(LedgerStorage::memory(), "s", budget()).unwrap();
        ledger.try_record_payment(upto(PaymentStatus::Pending, 3600)).unwrap();
        assert_eq!(ledger.outstanding_atomic(), 3600);
        assert_eq!(
            ledger.check_budget(10_000 - 3600 + 1).refusal().is_some(),
            true,
            "the pending ceiling is held"
        );

        ledger.try_record_payment(upto(PaymentStatus::Settled, actual)).unwrap();
        assert_eq!(ledger.outstanding_atomic(), 0);
        assert_eq!(ledger.summary().daily_total_atomic, actual);
        assert_eq!(ledger.check_budget(10_000 - actual), BudgetCheck::Allowed);
    }
}
