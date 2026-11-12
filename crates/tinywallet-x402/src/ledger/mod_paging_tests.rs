//! Tests for reading the payments stream back in windows.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use chrono::Utc;

use super::*;

fn settled(amount: u64) -> PaymentRecord {
    PaymentRecord {
        id: format!("paging-{amount}"),
        url: "https://api.example.com/data".into(),
        asset: "USDC".into(),
        amount_atomic: amount,
        amount_display: format!("{amount} atomic"),
        recipient: "Recipient".into(),
        network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp".into(),
        tx_signature: Some("sig123".into()),
        status: PaymentStatus::Settled,
        timestamp: Utc::now(),
        authorization_valid_until: None,
        solana_last_valid_block_height: None,
        authorization_expired_at: None,
        authorization_expiry_observed_height: None,
        session_id: "session-paging".into(),
        thread_id: None,
        scheme: None,
    }
}

#[test]
fn records_past_one_read_window_survive_a_restart() {
    // The payments stream is read back 512 records at a time.
    let dir = LedgerStorage::memory();
    let open =
        || PaymentLedger::open(dir.clone(), "session-paging", SpendingBudget::default()).unwrap();
    {
        let mut ledger = open();
        for amount in 1..=513 {
            ledger.record_payment(settled(amount));
        }
    }
    let recent = open().recent_payments(1_000);
    assert_eq!(recent.len(), 513);
    assert_eq!(recent[0].amount_atomic, 513, "the record past the window");
    assert_eq!(recent[512].amount_atomic, 1);
}
