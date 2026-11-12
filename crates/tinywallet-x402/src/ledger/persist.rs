//! The ledger's storage: the `wallet.payments` stream and one `wallet.budgets` hold document, both
//! through the runtime-neutral `tinystoragedrivers-api` ports.
//!
//! The ports are async and the ledger's API is synchronous (it runs under a
//! std mutex), so every call goes through [`Blocking`], which drives the future
//! on a dedicated runtime thread. Nothing here names a backend: the host hands
//! in the handles and picks sqlite, mongodb or memory.

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use log::debug;
use serde::{Deserialize, Serialize};
use tinystoragedrivers_api::{DocumentStore, Storage, StreamStore};
use tinystoragedrivers_types::{ErrorKind, Precondition, Version, WriteOptions};

use super::blocking::Blocking;
use super::schema::{
    self, BUDGETS_COLLECTION, BUDGETS_VERSION, HOLDS_ID, PAYMENTS_STREAM, StoredPayment,
};
use super::types::PaymentRecord;

const LOG_PREFIX: &str = "[x402::persist]";

/// How long a hold survives without being released or committed. A process that
/// dies between signing and recording must not lock budget forever.
pub(super) const HOLD_TTL_MS: i64 = 15 * 60 * 1000;
/// How often an owner of long-lived holds should call
/// [`PaymentLedger::renew_holds`](super::PaymentLedger::renew_holds): a third of
/// the TTL, so two missed beats still leave the lease alive.
pub const HOLD_RENEW_EVERY: std::time::Duration = std::time::Duration::from_secs(5 * 60);
/// Records read per stream window while loading.
const WINDOW: usize = 512;

/// The storage handles a ledger persists through.
#[derive(Debug, Clone)]
pub struct LedgerStorage {
    pub(super) documents: Arc<dyn DocumentStore>,
    pub(super) streams: Arc<dyn StreamStore>,
}

impl LedgerStorage {
    /// Persist through the given document and stream ports.
    #[must_use]
    pub fn new(documents: Arc<dyn DocumentStore>, streams: Arc<dyn StreamStore>) -> Self {
        Self { documents, streams }
    }

    /// Persist through a host-provisioned scoped handle.
    #[must_use]
    pub fn from_storage(storage: &Storage) -> Self {
        Self::new(storage.documents().clone(), storage.streams().clone())
    }

    /// Create a fresh real in-memory backend for this crate's unit tests.
    #[cfg(test)]
    #[must_use]
    #[allow(clippy::expect_used, reason = "the test scope is a fixed valid label")]
    pub(crate) fn memory() -> Self {
        let scope = tinystoragedrivers_types::Scope::new("tinywallet.test")
            .expect("the test scope is valid");
        Self::from_storage(&tinystoragedrivers_testkit::memory_storage(&scope))
    }
}

/// One budget hold as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Hold {
    pub amount: u64,
    pub expires_ms: i64,
}

/// The budget-hold document: every outstanding hold, across all processes
/// sharing the storage, keyed by owner-qualified id.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct HoldsDoc {
    #[serde(default)]
    pub holds: BTreeMap<String, Hold>,
}

fn from_ms(field: &str, ms: i64) -> Result<DateTime<Utc>, String> {
    DateTime::from_timestamp_millis(ms).ok_or_else(|| format!("{field} {ms} is out of range"))
}

/// The storage shape of `record`, with the hold its entry committed, if any.
pub(super) fn stored_payment(
    record: &PaymentRecord,
    committed_hold: Option<&str>,
) -> StoredPayment {
    StoredPayment {
        id: record.id.clone(),
        url: record.url.clone(),
        asset: record.asset.clone(),
        amount_atomic: record.amount_atomic,
        amount_display: record.amount_display.clone(),
        recipient: record.recipient.clone(),
        network: record.network.clone(),
        tx_signature: record.tx_signature.clone(),
        status: record.status.into(),
        timestamp_ms: record.timestamp.timestamp_millis(),
        authorization_valid_until_ms: record
            .authorization_valid_until
            .map(|at| at.timestamp_millis()),
        solana_last_valid_block_height: record.solana_last_valid_block_height,
        authorization_expired_at_ms: record
            .authorization_expired_at
            .map(|at| at.timestamp_millis()),
        authorization_expiry_observed_height: record.authorization_expiry_observed_height,
        session_id: record.session_id.clone(),
        thread_id: record.thread_id.clone(),
        scheme: record.scheme.clone(),
        committed_hold: committed_hold.map(str::to_owned),
    }
}

/// The public record and the hold this entry committed, if any.
pub(super) fn into_record(
    stored: StoredPayment,
) -> Result<(PaymentRecord, Option<String>), String> {
    let record = PaymentRecord {
        id: stored.id,
        url: stored.url,
        asset: stored.asset,
        amount_atomic: stored.amount_atomic,
        amount_display: stored.amount_display,
        recipient: stored.recipient,
        network: stored.network,
        tx_signature: stored.tx_signature,
        status: stored.status.into(),
        timestamp: from_ms("timestamp_ms", stored.timestamp_ms)?,
        authorization_valid_until: stored
            .authorization_valid_until_ms
            .map(|ms| from_ms("authorization_valid_until_ms", ms))
            .transpose()?,
        solana_last_valid_block_height: stored.solana_last_valid_block_height,
        authorization_expired_at: stored
            .authorization_expired_at_ms
            .map(|ms| from_ms("authorization_expired_at_ms", ms))
            .transpose()?,
        authorization_expiry_observed_height: stored.authorization_expiry_observed_height,
        session_id: stored.session_id,
        thread_id: stored.thread_id,
        scheme: stored.scheme,
    };
    Ok((record, stored.committed_hold))
}

/// A payment read back from the stream, with the hold its entry committed.
#[derive(Debug)]
pub(super) struct LoadedPayment {
    pub record: PaymentRecord,
    pub committed_hold: Option<String>,
}

/// Storage plus the sync bridge.
#[derive(Debug)]
pub(super) struct Persist {
    storage: LedgerStorage,
    bridge: Blocking,
}

impl Persist {
    /// Run one port call on the bridge, folding both layers of failure into a
    /// message that names the operation.
    fn run<T, F>(&self, what: &str, future: F) -> Result<T, String>
    where
        T: Send + 'static,
        F: Future<Output = tinystoragedrivers_types::Result<T>> + Send + 'static,
    {
        match self.bridge.run(future) {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) | Err(error) => Err(format!("{what}: {error}")),
        }
    }

    pub(super) fn open(storage: LedgerStorage) -> Result<Self, String> {
        let bridge = Blocking::new().map_err(|e| format!("start storage bridge: {e}"))?;
        let persist = Self { storage, bridge };
        let documents = Arc::clone(&persist.storage.documents);
        let streams = Arc::clone(&persist.storage.streams);
        persist.run("migrate x402 storage", async move {
            schema::migrate(documents.as_ref(), streams.as_ref()).await
        })?;
        Ok(persist)
    }

    /// Records from stream offset `from` to the end, with the next offset.
    /// Entries that no longer parse are skipped with a warning.
    pub(super) fn read_from(&self, from: u64) -> Result<(Vec<LoadedPayment>, u64), String> {
        let mut records = Vec::new();
        let mut next = from;
        loop {
            let streams = Arc::clone(&self.storage.streams);
            let window = self.run("read payments stream", async move {
                streams.read_window(PAYMENTS_STREAM, next, WINDOW).await
            })?;
            let Some(last) = window.last() else { break };
            next = last.offset.saturating_add(1);
            for entry in window {
                let parsed = serde_json::from_value::<StoredPayment>(entry.value)
                    .map_err(|error| error.to_string())
                    .and_then(into_record);
                match parsed {
                    Ok((record, committed_hold)) => records.push(LoadedPayment {
                        record,
                        committed_hold,
                    }),
                    Err(error) => log::warn!(
                        "{LOG_PREFIX} corrupt record at offset {}: {error}",
                        entry.offset
                    ),
                }
            }
        }
        Ok((records, next))
    }

    /// Append one record and return its stream offset.
    pub(super) fn append(
        &self,
        record: &PaymentRecord,
        committed_hold: Option<&str>,
    ) -> Result<u64, String> {
        let value = serde_json::to_value(stored_payment(record, committed_hold))
            .map_err(|error| error.to_string())?;
        let streams = Arc::clone(&self.storage.streams);
        self.run("append ledger record", async move {
            streams.append(PAYMENTS_STREAM, value).await
        })
    }

    /// The hold document and the version it was read at (`None` when absent).
    pub(super) fn load_holds(&self) -> Result<(Option<Version>, HoldsDoc), String> {
        let documents = Arc::clone(&self.storage.documents);
        let found = self.run("read budget holds", async move {
            documents.get(BUDGETS_COLLECTION, HOLDS_ID).await
        })?;
        match found {
            None => Ok((None, HoldsDoc::default())),
            Some(versioned) => {
                let doc = serde_json::from_value::<HoldsDoc>(versioned.doc)
                    .map_err(|e| format!("budget holds document is unreadable: {e}"))?;
                Ok((Some(versioned.version), doc))
            }
        }
    }

    /// Compare-and-swap the hold document. `Ok(false)` means someone else wrote
    /// it since `version` was read; the caller re-reads and retries.
    pub(super) fn store_holds(
        &self,
        version: Option<Version>,
        doc: &HoldsDoc,
    ) -> Result<bool, String> {
        let body = serde_json::to_value(doc).map_err(|error| error.to_string())?;
        let precondition = version.map_or(Precondition::Absent, Precondition::Version);
        let documents = Arc::clone(&self.storage.documents);
        let result = self.bridge.run(async move {
            documents
                .put_with(
                    BUDGETS_COLLECTION,
                    HOLDS_ID,
                    body,
                    precondition,
                    WriteOptions::new().schema(BUDGETS_VERSION),
                )
                .await
        });
        match result.map_err(|error| format!("write budget holds: {error}"))? {
            Ok(_) => Ok(true),
            Err(error)
                if matches!(error.kind(), ErrorKind::Conflict | ErrorKind::AlreadyExists) =>
            {
                debug!("{LOG_PREFIX} budget hold CAS lost the race");
                Ok(false)
            }
            Err(error) => Err(format!("write budget holds: {error}")),
        }
    }
}
