//! Serde types for the ledger: records, budgets, summaries.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One payment attempt, as written to the ledger file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRecord {
    /// Unique id of the attempt. A status change is a new line with the same id.
    pub id: String,
    /// The URL the payment bought access to.
    pub url: String,
    /// The asset paid in: a token mint or contract address.
    pub asset: String,
    /// The amount in atomic units of `asset`.
    pub amount_atomic: u64,
    /// The amount formatted for people, such as `0.002500 USDC`.
    pub amount_display: String,
    /// Who was paid.
    pub recipient: String,
    /// The network the payment was made on, in CAIP-2 form.
    pub network: String,
    /// The settlement transaction, once the server reported one.
    pub tx_signature: Option<String>,
    /// Where the payment stands.
    pub status: PaymentStatus,
    /// When this line was written.
    pub timestamp: DateTime<Utc>,
    /// The session that made the payment.
    pub session_id: String,
}

/// Where a payment attempt stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    /// Signed and sent, not yet settled.
    Pending,
    /// The server accepted it. The only status that counts against a budget.
    Settled,
    /// The server rejected it, or the retry failed.
    Failed,
    /// Refused before anything was signed.
    Denied,
}

/// Totals over settled payments.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendingSummary {
    /// Atomic units settled in this session.
    pub session_total_atomic: u64,
    /// Atomic units settled today (UTC).
    pub daily_total_atomic: u64,
    /// Atomic units settled this calendar month (UTC).
    pub monthly_total_atomic: u64,
    /// Settled payments in this session.
    pub session_count: usize,
    /// Settled payments today.
    pub daily_count: usize,
    /// Settled payments this month.
    pub monthly_count: usize,
}

/// Spending limits, in atomic units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpendingBudget {
    /// The most one request may cost.
    pub per_request_max_atomic: u64,
    /// The most that may settle in a day.
    pub daily_max_atomic: u64,
    /// The most that may settle in a month.
    pub monthly_max_atomic: u64,
}

impl Default for SpendingBudget {
    fn default() -> Self {
        Self {
            // 1 USDC per request.
            per_request_max_atomic: 1_000_000,
            // 10 USDC per day.
            daily_max_atomic: 10_000_000,
            // 100 USDC per month.
            monthly_max_atomic: 100_000_000,
        }
    }
}

/// The verdict of [`PaymentLedger::check_budget`](super::PaymentLedger::check_budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetCheck {
    /// Within every limit.
    Allowed,
    /// The request alone is over the per-request cap.
    ExceedsPerRequest {
        /// The amount asked for.
        requested: u64,
        /// The cap it exceeded.
        cap: u64,
    },
    /// Settled today plus this request is over the daily cap.
    ExceedsDailyBudget {
        /// Settled so far today.
        current: u64,
        /// The daily cap.
        cap: u64,
    },
    /// Settled this month plus this request is over the monthly cap.
    ExceedsMonthlyBudget {
        /// Settled so far this month.
        current: u64,
        /// The monthly cap.
        cap: u64,
    },
}

/// A hold on part of the budget, taken by
/// [`PaymentLedger::reserve`](super::PaymentLedger::reserve).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReservationId(pub(super) u64);

/// Why [`PaymentLedger::reserve`](super::PaymentLedger::reserve) refused: the
/// refusing cases of [`BudgetCheck`], for callers that have no use for
/// "allowed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRefusal {
    /// The request alone is over the per-request cap.
    PerRequest {
        /// The amount asked for.
        requested: u64,
        /// The cap it exceeded.
        cap: u64,
    },
    /// Held and settled today plus this request is over the daily cap.
    Daily {
        /// Settled and held so far today.
        current: u64,
        /// The daily cap.
        cap: u64,
    },
    /// Held and settled this month plus this request is over the monthly cap.
    Monthly {
        /// Settled and held so far this month.
        current: u64,
        /// The monthly cap.
        cap: u64,
    },
}

impl BudgetCheck {
    /// The refusal this verdict amounts to, or `None` when it is
    /// [`Allowed`](Self::Allowed).
    #[must_use]
    pub fn refusal(self) -> Option<BudgetRefusal> {
        match self {
            Self::Allowed => None,
            Self::ExceedsPerRequest { requested, cap } => {
                Some(BudgetRefusal::PerRequest { requested, cap })
            }
            Self::ExceedsDailyBudget { current, cap } => {
                Some(BudgetRefusal::Daily { current, cap })
            }
            Self::ExceedsMonthlyBudget { current, cap } => {
                Some(BudgetRefusal::Monthly { current, cap })
            }
        }
    }
}
