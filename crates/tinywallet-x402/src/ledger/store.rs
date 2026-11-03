//! The ledger itself: an in-memory record list over a payments stream, with
//! budget holds kept in one compare-and-swap document.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Datelike, Months, NaiveTime, TimeZone, Utc};
use log::{debug, warn};

use super::persist::{HOLD_TTL_MS, Hold, LedgerStorage, Persist};
use super::types::{
    BudgetCheck, BudgetRefusal, PaymentRecord, PaymentStatus, ReservationId, SpendingBudget,
    SpendingSummary,
};

const LOG_PREFIX: &str = "[x402::store]";

/// Attempts at the hold compare-and-swap before giving up. Each loss means
/// another writer made progress, so a handful is plenty.
const HOLD_CAS_ATTEMPTS: usize = 16;

/// Source of [`ReservationId`]s. Process-wide rather than per ledger, so a hold
/// taken on a ledger that was later replaced can never release a hold on its
/// successor.
static NEXT_RESERVATION: AtomicU64 = AtomicU64::new(1);

/// Identifies a particular in-memory ledger instance, even when a replacement
/// is opened from the same storage and contains the same persisted records.
static NEXT_LEDGER_GENERATION: AtomicU64 = AtomicU64::new(1);

/// A hold this ledger placed: its key in the hold document and its amount, kept
/// so the lease can be renewed (or re-placed after it lapsed).
#[derive(Debug, Clone)]
struct OwnHold {
    key: String,
    amount: u64,
}

/// Append-only payment history with budget enforcement.
#[derive(Debug)]
pub struct PaymentLedger {
    generation: u64,
    records: Vec<PaymentRecord>,
    /// Holds already represented by a durably appended payment.
    committed_holds: HashSet<String>,
    /// The next payments-stream offset to read; everything below it is in
    /// `records` (or was unparseable).
    next_offset: u64,
    persist: Persist,
    budget: SpendingBudget,
    session_id: String,
    /// Qualifies hold keys so processes sharing one storage never collide.
    owner: String,
    /// The holds this ledger placed and has not yet released.
    reservations: HashMap<ReservationId, OwnHold>,
    /// Every outstanding hold (this ledger's and other processes') as of the
    /// last read of the hold document.
    holds: BTreeMap<String, Hold>,
}

impl PaymentLedger {
    /// Open the ledger over `storage`, loading the persisted records.
    ///
    /// # Errors
    ///
    /// The storage cannot be opened or its payments stream cannot be read. A
    /// ledger that cannot see its history must not admit payments.
    pub fn open(
        storage: LedgerStorage,
        session_id: &str,
        budget: SpendingBudget,
    ) -> Result<Self, String> {
        Self::from_persist(Persist::open(storage)?, session_id, budget)
    }

    fn from_persist(
        persist: Persist,
        session_id: &str,
        budget: SpendingBudget,
    ) -> Result<Self, String> {
        let (records, next_offset) = persist.read_from(0)?;
        debug!(
            "{LOG_PREFIX} loaded {} existing payment records",
            records.len()
        );
        let committed_holds = records
            .iter()
            .filter_map(|entry| entry.committed_hold.clone())
            .collect();
        let records = records.into_iter().map(|entry| entry.record).collect();
        let generation = NEXT_LEDGER_GENERATION.fetch_add(1, Ordering::Relaxed);
        let started = Utc::now().timestamp_nanos_opt().unwrap_or_default();
        Ok(Self {
            generation,
            records,
            committed_holds,
            next_offset,
            persist,
            budget,
            session_id: session_id.to_string(),
            owner: format!("{}-{generation}-{started}", std::process::id()),
            reservations: HashMap::new(),
            holds: BTreeMap::new(),
        })
    }

    /// Pull records other writers appended since this ledger last looked.
    fn refresh_records(&mut self) -> Result<(), String> {
        let (fresh, next) = self.persist.read_from(self.next_offset)?;
        for entry in fresh {
            if let Some(key) = entry.committed_hold {
                self.committed_holds.insert(key);
            }
            self.records.push(entry.record);
        }
        self.next_offset = next;
        Ok(())
    }

    /// Append `record` to the stream and mirror it into memory.
    fn append_record(
        &mut self,
        record: PaymentRecord,
        committed_hold: Option<String>,
    ) -> Result<(), String> {
        let record = record.at_millisecond_precision();
        let offset = self.persist.append(&record, committed_hold.as_deref())?;
        if let Some(key) = committed_hold {
            self.committed_holds.insert(key);
        }
        if offset == self.next_offset {
            self.records.push(record);
            self.next_offset = offset.saturating_add(1);
        } else if self.refresh_records().is_err() {
            // Another writer interleaved and the re-read failed; keep ours.
            self.records.push(record);
        }
        Ok(())
    }

    /// The identity of this in-memory ledger instance.
    #[must_use]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    /// The session this ledger was opened for: the one
    /// [`SpendingSummary::session_total_atomic`] counts.
    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Check `amount` against the per-request, daily and monthly limits.
    ///
    /// Settled payments, unresolved signed authorizations, and outstanding
    /// [reservations](Self::reserve) count toward the daily and monthly totals.
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

        let this_month = (now.year(), now.month());
        let day_start = Utc.from_utc_datetime(&now.date_naive().and_time(NaiveTime::MIN));
        let day_end = day_start
            .checked_add_signed(chrono::Duration::days(1))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let first_of_month = now
            .date_naive()
            .with_day(1)
            .unwrap_or(now.date_naive())
            .and_time(NaiveTime::MIN);
        let month_start = Utc.from_utc_datetime(&first_of_month);
        let month_end = month_start
            .checked_add_months(Months::new(1))
            .unwrap_or(DateTime::<Utc>::MAX_UTC);
        let reserved = self.reserved_atomic();

        let daily = self
            .latest_records()
            .into_iter()
            .filter(|record| {
                (is_unresolved(record) && overlaps_authorization_window(record, day_start, day_end))
                    || (record.status == PaymentStatus::Settled
                        && record.timestamp >= day_start
                        && record.timestamp < day_end)
            })
            .fold(reserved, |total, record| {
                total.saturating_add(record.amount_atomic)
            });
        if daily
            .checked_add(amount)
            .is_none_or(|total| total > self.budget.daily_max_atomic)
        {
            return BudgetCheck::ExceedsDailyBudget {
                current: daily,
                cap: self.budget.daily_max_atomic,
            };
        }

        let monthly = self
            .latest_records()
            .into_iter()
            .filter(|record| {
                (is_unresolved(record)
                    && overlaps_authorization_window(record, month_start, month_end))
                    || (record.status == PaymentStatus::Settled
                        && (record.timestamp.year(), record.timestamp.month()) == this_month)
            })
            .fold(reserved, |total, record| {
                total.saturating_add(record.amount_atomic)
            });
        if monthly
            .checked_add(amount)
            .is_none_or(|total| total > self.budget.monthly_max_atomic)
        {
            return BudgetCheck::ExceedsMonthlyBudget {
                current: monthly,
                cap: self.budget.monthly_max_atomic,
            };
        }

        BudgetCheck::Allowed
    }

    /// Check `amount` against the limits and, if it fits, hold it.
    ///
    /// The hold is a compare-and-swap on one shared document: it re-reads every
    /// writer's records and holds, checks, and writes the new hold only if
    /// nobody else wrote the document meanwhile, retrying otherwise. Two
    /// payments that each fit alone therefore cannot both be admitted when
    /// together they exceed a cap, even across processes on one storage. The
    /// hold ends with [`release`](Self::release) or
    /// [`try_commit_reservation`](Self::try_commit_reservation), or expires on
    /// its own.
    ///
    /// # Errors
    ///
    /// The outer error is a storage failure (nothing is held, so the caller
    /// must not pay); the inner one is the [`BudgetRefusal`] that stopped
    /// `amount`.
    pub fn reserve(&mut self, amount: u64) -> Result<Result<ReservationId, BudgetRefusal>, String> {
        self.reserve_at(Utc::now(), amount)
    }

    /// [`reserve`](Self::reserve) as of `now`.
    pub(crate) fn reserve_at(
        &mut self,
        now: DateTime<Utc>,
        amount: u64,
    ) -> Result<Result<ReservationId, BudgetRefusal>, String> {
        // This cap depends only on configuration, so storage failures or
        // concurrent hold changes cannot alter the definitive refusal.
        if amount > self.budget.per_request_max_atomic {
            return Ok(Err(BudgetRefusal::PerRequest {
                requested: amount,
                cap: self.budget.per_request_max_atomic,
            }));
        }
        let now_ms = now.timestamp_millis();
        for _ in 0..HOLD_CAS_ATTEMPTS {
            let (version, mut doc) = self.persist.load_holds()?;
            // Records are read AFTER the hold document, on every attempt. A
            // writer commits by appending its record and only then dropping its
            // hold, so a reader that sees the hold gone is guaranteed to see
            // the record on this read; a reader that still sees the hold
            // counts it unless its record carries the same committed hold key.
            // That key also covers a writer paused between append and release.
            // A concurrent hold change makes the CAS below fail and retry.
            // Reading records first would leave a window in which neither is
            // counted.
            self.refresh_records()?;
            doc.holds.retain(|key, hold| {
                hold.expires_ms > now_ms && !self.committed_holds.contains(key)
            });
            self.holds.clone_from(&doc.holds);
            if let Some(refusal) = self.check_budget_at(now, amount).refusal() {
                // A legacy writer without commit metadata can still straddle
                // this snapshot and double count its record and hold. Only
                // refuse on a snapshot the hold document still matches after
                // excluding holds identified by durable commit records;
                // otherwise retry against the current one.
                let (current, _) = self.persist.load_holds()?;
                if current == version {
                    return Ok(Err(refusal));
                }
                continue;
            }
            let id = ReservationId(NEXT_RESERVATION.fetch_add(1, Ordering::Relaxed));
            let key = format!("{}:{}", self.owner, id.0);
            doc.holds.insert(
                key.clone(),
                Hold {
                    amount,
                    expires_ms: now_ms.saturating_add(HOLD_TTL_MS),
                },
            );
            if self.persist.store_holds(version, &doc)? {
                self.holds = doc.holds;
                self.reservations.insert(id, OwnHold { key, amount });
                debug!("{LOG_PREFIX} reserved {amount} atomic as {id:?}");
                return Ok(Ok(id));
            }
        }
        Err("x402 budget hold contention: gave up after repeated conflicts".to_string())
    }

    /// Drop a hold without recording a payment. Releasing a hold that is
    /// already gone does nothing. A storage failure is logged and leaves the
    /// stored hold to expire; the budget stays conservatively charged.
    pub fn release(&mut self, id: ReservationId) {
        let Some(OwnHold { key, .. }) = self.reservations.remove(&id) else {
            return;
        };
        self.holds.remove(&key);
        for _ in 0..HOLD_CAS_ATTEMPTS {
            let (version, mut doc) = match self.persist.load_holds() {
                Ok(found) => found,
                Err(error) => {
                    warn!("{LOG_PREFIX} release of {id:?} left to expire: {error}");
                    return;
                }
            };
            if version.is_none() || doc.holds.remove(&key).is_none() {
                return;
            }
            match self.persist.store_holds(version, &doc) {
                Ok(true) => {
                    debug!("{LOG_PREFIX} released {id:?}");
                    return;
                }
                Ok(false) => {}
                Err(error) => {
                    warn!("{LOG_PREFIX} release of {id:?} left to expire: {error}");
                    return;
                }
            }
        }
        warn!("{LOG_PREFIX} release of {id:?} left to expire: contention");
    }

    /// Extend the lease on every hold this ledger still owns to a fresh
    /// `HOLD_TTL_MS` from `now`, re-placing one that lapsed (and was pruned
    /// by another writer) so a payment in flight past the TTL keeps its budget
    /// charged. Returns how many holds were renewed.
    ///
    /// Callers with long-lived reservations (a signed authorization awaiting
    /// settlement) call this more often than the TTL; see `HOLD_RENEW_EVERY`.
    ///
    /// # Errors
    ///
    /// The hold document cannot be read or written, or stayed contended. The
    /// holds are unchanged and keep expiring on their own clock.
    pub fn renew_holds(&mut self) -> Result<usize, String> {
        self.renew_holds_at(Utc::now())
    }

    /// [`renew_holds`](Self::renew_holds) as of `now`.
    pub(crate) fn renew_holds_at(&mut self, now: DateTime<Utc>) -> Result<usize, String> {
        if self.reservations.is_empty() {
            return Ok(0);
        }
        let now_ms = now.timestamp_millis();
        let expires_ms = now_ms.saturating_add(HOLD_TTL_MS);
        for _ in 0..HOLD_CAS_ATTEMPTS {
            let (version, mut doc) = self.persist.load_holds()?;
            doc.holds.retain(|_, hold| hold.expires_ms > now_ms);
            for own in self.reservations.values() {
                doc.holds.insert(
                    own.key.clone(),
                    Hold {
                        amount: own.amount,
                        expires_ms,
                    },
                );
            }
            if self.persist.store_holds(version, &doc)? {
                self.holds = doc.holds;
                debug!("{LOG_PREFIX} renewed {} holds", self.reservations.len());
                return Ok(self.reservations.len());
            }
        }
        Err("x402 budget hold renewal: gave up after repeated conflicts".to_string())
    }

    /// The total currently held by reservations, in atomic units.
    #[must_use]
    pub fn reserved_atomic(&self) -> u64 {
        self.holds
            .values()
            .fold(0, |total, hold| total.saturating_add(hold.amount))
    }

    /// Attempt to append `record` to disk, then keep it in memory regardless.
    ///
    /// A write failure is logged and the record is still kept in memory: the
    /// payment already happened, and losing the record from this session's
    /// budget would be worse than losing it from the file.
    pub fn record_payment(&mut self, record: PaymentRecord) {
        if let Err(error) = self.append_record(record.clone(), None) {
            warn!("{LOG_PREFIX} record append failed: {error}");
            self.records.push(record.at_millisecond_precision());
        }
    }

    /// Append a state transition and update memory only after the durable write
    /// succeeds. Use this for transitions that must not release an authorization
    /// unless the new state is persisted.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, file creation, writing, or syncing
    /// fails. The in-memory history is left unchanged.
    pub fn try_record_payment(&mut self, record: PaymentRecord) -> Result<(), String> {
        self.append_record(record, None)
    }

    /// Persist finalized Solana block-height evidence that a pending
    /// authorization can no longer be submitted. The chain call must happen
    /// before this method, outside the ledger lock.
    ///
    /// This update is conditional on the latest record still being the same
    /// pending authorization with the expected validity bound. A receipt or
    /// replacement state that wins the race is never overwritten.
    ///
    /// # Errors
    ///
    /// Returns an error if the expiry observation cannot be durably appended.
    pub fn observe_solana_expiry(
        &mut self,
        expected_generation: u64,
        id: &str,
        expected_issued_at: DateTime<Utc>,
        expected_last_valid_height: u64,
        observed_height: u64,
        observed_at: DateTime<Utc>,
    ) -> Result<bool, String> {
        if self.generation != expected_generation || observed_height <= expected_last_valid_height {
            return Ok(false);
        }
        // Another writer may have recorded a receipt since this ledger looked.
        self.refresh_records()?;
        let Some(mut latest) = self.payment(id).cloned() else {
            return Ok(false);
        };
        if latest.status != PaymentStatus::Pending
            || latest.timestamp != expected_issued_at
            || latest.solana_last_valid_block_height != Some(expected_last_valid_height)
            || latest.authorization_expired_at.is_some()
            || observed_at < latest.timestamp
        {
            return Ok(false);
        }
        latest.authorization_expired_at = Some(observed_at);
        latest.authorization_expiry_observed_height = Some(observed_height);
        self.try_record_payment(latest)?;
        Ok(true)
    }

    /// Commit a reservation into a durable record without an interval where
    /// neither the hold nor the record counts against the budget.
    ///
    /// # Errors
    ///
    /// Returns an error if serialization, file creation, writing, or syncing
    /// fails. The record is not added to memory and the reservation stays held.
    pub fn try_commit_reservation(
        &mut self,
        id: ReservationId,
        record: PaymentRecord,
    ) -> Result<(), String> {
        let key = self.reservations.get(&id).map(|hold| hold.key.clone());
        self.append_record(record, key)?;
        self.release(id);
        Ok(())
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
            .latest_records()
            .into_iter()
            .filter(|r| r.status == PaymentStatus::Settled)
        {
            if record.session_id == self.session_id {
                summary.session_total_atomic = summary
                    .session_total_atomic
                    .saturating_add(record.amount_atomic);
                summary.session_count = summary.session_count.saturating_add(1);
            }
            if record.timestamp.date_naive() == today {
                summary.daily_total_atomic = summary
                    .daily_total_atomic
                    .saturating_add(record.amount_atomic);
                summary.daily_count = summary.daily_count.saturating_add(1);
            }
            if (record.timestamp.year(), record.timestamp.month()) == this_month {
                summary.monthly_total_atomic = summary
                    .monthly_total_atomic
                    .saturating_add(record.amount_atomic);
                summary.monthly_count = summary.monthly_count.saturating_add(1);
            }
        }
        summary
    }

    /// The most recent `limit` records, newest first.
    #[must_use]
    pub fn recent_payments(&self, limit: usize) -> Vec<PaymentRecord> {
        self.records.iter().rev().take(limit).cloned().collect()
    }

    /// Return the latest recorded state for a payment id.
    #[must_use]
    pub fn payment(&self, id: &str) -> Option<&PaymentRecord> {
        self.records.iter().rev().find(|record| record.id == id)
    }

    /// Number of authorizations whose latest state is still pending.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.latest_records()
            .into_iter()
            .filter(|record| record.status == PaymentStatus::Pending)
            .count()
    }

    /// Number of pending authorizations that can still be used to initiate a
    /// payment. Expiry can release an admission slot, but it never changes the
    /// durable budget hold: an expired authorization may already have settled
    /// without a receipt reaching this process.
    #[must_use]
    pub fn usable_pending_count(&self, now: DateTime<Utc>) -> usize {
        self.latest_records()
            .into_iter()
            .filter(|record| {
                record.status == PaymentStatus::Pending
                    && authorization_window_end(record).is_none_or(|end| end > now)
            })
            .count()
    }

    /// Latest unresolved signed authorizations.
    #[must_use]
    pub fn pending_payments(&self) -> Vec<PaymentRecord> {
        self.latest_records()
            .into_iter()
            .filter(|record| record.status == PaymentStatus::Pending)
            .cloned()
            .collect()
    }

    /// Budget still tied up in reservations and durable pending authorizations.
    #[must_use]
    pub fn outstanding_atomic(&self) -> u64 {
        let pending = self
            .latest_records()
            .into_iter()
            .filter(|record| is_unresolved(record))
            .fold(0_u64, |total, record| {
                total.saturating_add(record.amount_atomic)
            });
        pending.saturating_add(self.reserved_atomic())
    }

    fn latest_records(&self) -> Vec<&PaymentRecord> {
        let mut latest = HashMap::with_capacity(self.records.len());
        for record in &self.records {
            latest.insert(record.id.as_str(), record);
        }
        latest.into_values().collect()
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
}

fn is_unresolved(record: &PaymentRecord) -> bool {
    record.status == PaymentStatus::Pending
        // Older module versions marked an authorization Failed solely because
        // its valid-before deadline elapsed. Keep those historical rows
        // budgeted until a trusted receipt resolves them.
        || (record.status == PaymentStatus::Failed
            && record.authorization_valid_until.is_some())
}

fn overlaps_authorization_window(
    record: &PaymentRecord,
    window_start: DateTime<Utc>,
    window_end: DateTime<Utc>,
) -> bool {
    let authorization_end = authorization_window_end(record);
    record.timestamp < window_end && authorization_end.is_none_or(|end| end >= window_start)
}

fn authorization_window_end(record: &PaymentRecord) -> Option<DateTime<Utc>> {
    record.authorization_valid_until.or_else(|| {
        let (Some(last_valid), Some(observed_height), Some(observed_at)) = (
            record.solana_last_valid_block_height,
            record.authorization_expiry_observed_height,
            record.authorization_expired_at,
        ) else {
            return None;
        };
        (observed_height > last_valid && observed_at >= record.timestamp).then_some(observed_at)
    })
}
