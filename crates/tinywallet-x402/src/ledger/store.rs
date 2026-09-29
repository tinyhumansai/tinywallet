//! The ledger itself: an in-memory record list backed by a JSONL file.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Datelike, Utc};
use log::{debug, warn};

use super::types::{BudgetCheck, PaymentRecord, PaymentStatus, SpendingBudget, SpendingSummary};

const LOG_PREFIX: &str = "[x402::store]";

/// Append-only payment history with budget enforcement.
#[derive(Debug)]
pub struct PaymentLedger {
    records: Vec<PaymentRecord>,
    file_path: PathBuf,
    budget: SpendingBudget,
    session_id: String,
}

impl PaymentLedger {
    /// Open the ledger under `workspace_dir`, loading any existing records.
    ///
    /// The file is `<workspace_dir>/x402/payments.jsonl`; a missing file is an
    /// empty ledger.
    #[must_use]
    pub fn new(workspace_dir: &Path, session_id: &str, budget: SpendingBudget) -> Self {
        let file_path = workspace_dir.join("x402").join("payments.jsonl");
        let records = load_from_disk(&file_path);
        debug!(
            "{LOG_PREFIX} loaded {} existing payment records from {}",
            records.len(),
            file_path.display()
        );
        Self {
            records,
            file_path,
            budget,
            session_id: session_id.to_string(),
        }
    }

    /// Check `amount` against the per-request, daily and monthly limits.
    #[must_use]
    pub fn check_budget(&self, amount: u64) -> BudgetCheck {
        self.check_budget_at(Utc::now(), amount)
    }

    /// [`check_budget`](Self::check_budget) as of `now`, so the day and month
    /// windows can be tested without waiting for a boundary.
    pub(crate) fn check_budget_at(&self, now: DateTime<Utc>, amount: u64) -> BudgetCheck {
        if amount > self.budget.per_request_max_atomic {
            return BudgetCheck::ExceedsPerRequest {
                requested: amount,
                cap: self.budget.per_request_max_atomic,
            };
        }

        let today = now.date_naive();
        let this_month = (now.year(), now.month());

        let daily: u64 = self
            .records
            .iter()
            .filter(|r| r.status == PaymentStatus::Settled && r.timestamp.date_naive() == today)
            .map(|r| r.amount_atomic)
            .sum();
        if daily.saturating_add(amount) > self.budget.daily_max_atomic {
            return BudgetCheck::ExceedsDailyBudget {
                current: daily,
                cap: self.budget.daily_max_atomic,
            };
        }

        let monthly: u64 = self
            .records
            .iter()
            .filter(|r| {
                r.status == PaymentStatus::Settled
                    && (r.timestamp.year(), r.timestamp.month()) == this_month
            })
            .map(|r| r.amount_atomic)
            .sum();
        if monthly.saturating_add(amount) > self.budget.monthly_max_atomic {
            return BudgetCheck::ExceedsMonthlyBudget {
                current: monthly,
                cap: self.budget.monthly_max_atomic,
            };
        }

        BudgetCheck::Allowed
    }

    /// Append `record` to the file and to memory.
    ///
    /// A write failure is logged and the record is still kept in memory: the
    /// payment already happened, and losing the record from this session's
    /// budget would be worse than losing it from the file.
    pub fn record_payment(&mut self, record: PaymentRecord) {
        self.append_to_disk(&record);
        self.records.push(record);
    }

    /// Totals over settled payments for this session, today and this month.
    #[must_use]
    pub fn summary(&self) -> SpendingSummary {
        self.summary_at(Utc::now())
    }

    /// [`summary`](Self::summary) as of `now`.
    pub(crate) fn summary_at(&self, now: DateTime<Utc>) -> SpendingSummary {
        let today = now.date_naive();
        let this_month = (now.year(), now.month());

        let mut summary = SpendingSummary::default();
        for record in self
            .records
            .iter()
            .filter(|r| r.status == PaymentStatus::Settled)
        {
            if record.session_id == self.session_id {
                summary.session_total_atomic += record.amount_atomic;
                summary.session_count += 1;
            }
            if record.timestamp.date_naive() == today {
                summary.daily_total_atomic += record.amount_atomic;
                summary.daily_count += 1;
            }
            if (record.timestamp.year(), record.timestamp.month()) == this_month {
                summary.monthly_total_atomic += record.amount_atomic;
                summary.monthly_count += 1;
            }
        }
        summary
    }

    /// The most recent `limit` records, newest first.
    #[must_use]
    pub fn recent_payments(&self, limit: usize) -> Vec<PaymentRecord> {
        self.records.iter().rev().take(limit).cloned().collect()
    }

    /// The current limits.
    #[must_use]
    pub fn budget(&self) -> &SpendingBudget {
        &self.budget
    }

    /// Replace the limits. Not persisted; a host re-applies its own defaults at
    /// boot.
    pub fn update_budget(&mut self, budget: SpendingBudget) {
        debug!(
            "{LOG_PREFIX} budget updated per_request={} daily={} monthly={}",
            budget.per_request_max_atomic, budget.daily_max_atomic, budget.monthly_max_atomic
        );
        self.budget = budget;
    }

    fn append_to_disk(&self, record: &PaymentRecord) {
        if let Some(parent) = self.file_path.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                warn!("{LOG_PREFIX} mkdir failed: {e}");
                return;
            }
        }
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)
        {
            Ok(f) => f,
            Err(e) => {
                warn!("{LOG_PREFIX} open failed: {e}");
                return;
            }
        };
        match serde_json::to_string(record) {
            Ok(json) => {
                if let Err(e) = writeln!(file, "{json}") {
                    warn!("{LOG_PREFIX} write failed: {e}");
                }
            }
            Err(e) => warn!("{LOG_PREFIX} serialize failed: {e}"),
        }
    }
}

fn load_from_disk(path: &Path) -> Vec<PaymentRecord> {
    let Ok(file) = fs::File::open(path) else {
        return Vec::new();
    };
    let mut records = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                warn!("{LOG_PREFIX} read error: {e}");
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<PaymentRecord>(&line) {
            Ok(r) => records.push(r),
            Err(e) => warn!("{LOG_PREFIX} corrupt record: {e}"),
        }
    }
    records
}
