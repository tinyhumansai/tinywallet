//! Tests for owner-local x402 schema declarations and open-time migrations.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use tinystoragedrivers_api::{DocumentStore, StreamStore};
use tinystoragedrivers_types::{
    Capabilities, CollectionSpec, ErrorKind, Filter, Page, Precondition, Query, Scope, SealOutcome,
    Sort, StreamEntry, StreamInfo, Version, Versioned, WriteOptions,
};

use super::super::{LedgerStorage, PaymentLedger, PaymentStatus, SpendingBudget};
use crate::ledger::blocking::Blocking;

const V1_PAYMENT_MS: i64 = 1_773_576_000_000;

#[derive(Debug, Clone, Copy)]
enum RaceAction {
    CompleteMarker,
    ExistingMarker,
    MatchingBudget,
    ExistingBudget,
    WrongBudgetSchema,
    WrongBudgetExpiry,
}

#[derive(Debug)]
struct RacingDocuments {
    inner: Arc<dyn DocumentStore>,
    action: RaceAction,
}

#[async_trait]
impl DocumentStore for RacingDocuments {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn ensure_collection(
        &self,
        spec: &CollectionSpec,
    ) -> tinystoragedrivers_types::Result<()> {
        self.inner.ensure_collection(spec).await
    }

    async fn get(
        &self,
        collection: &str,
        id: &str,
    ) -> tinystoragedrivers_types::Result<Option<Versioned<Value>>> {
        self.inner.get(collection, id).await
    }

    async fn put(
        &self,
        collection: &str,
        id: &str,
        doc: Value,
        precondition: Precondition,
    ) -> tinystoragedrivers_types::Result<Version> {
        let version = self.inner.put(collection, id, doc, precondition).await?;
        if matches!(self.action, RaceAction::CompleteMarker)
            && collection == "wallet.migrations"
            && id == "x402"
        {
            return Err(tinystoragedrivers_types::StorageError::new(
                ErrorKind::Conflict,
                "simulated competing migration completion",
            ));
        }
        if matches!(self.action, RaceAction::ExistingMarker)
            && collection == "wallet.migrations"
            && id == "x402"
        {
            return Err(tinystoragedrivers_types::StorageError::new(
                ErrorKind::AlreadyExists,
                "simulated competing migration completion",
            ));
        }
        Ok(version)
    }

    async fn delete(
        &self,
        collection: &str,
        id: &str,
        precondition: Precondition,
    ) -> tinystoragedrivers_types::Result<bool> {
        self.inner.delete(collection, id, precondition).await
    }

    async fn query(
        &self,
        collection: &str,
        query: &Query,
    ) -> tinystoragedrivers_types::Result<Page<Versioned<Value>>> {
        self.inner.query(collection, query).await
    }

    async fn count(
        &self,
        collection: &str,
        filter: &Filter,
    ) -> tinystoragedrivers_types::Result<u64> {
        self.inner.count(collection, filter).await
    }

    async fn delete_where(
        &self,
        collection: &str,
        filter: &Filter,
    ) -> tinystoragedrivers_types::Result<u64> {
        self.inner.delete_where(collection, filter).await
    }

    async fn claim(
        &self,
        collection: &str,
        filter: &Filter,
        sort: &[Sort],
        patch: &Value,
    ) -> tinystoragedrivers_types::Result<Option<Versioned<Value>>> {
        self.inner.claim(collection, filter, sort, patch).await
    }

    async fn drop_collection(&self, collection: &str) -> tinystoragedrivers_types::Result<()> {
        self.inner.drop_collection(collection).await
    }

    async fn put_with(
        &self,
        collection: &str,
        id: &str,
        doc: Value,
        precondition: Precondition,
        mut options: WriteOptions,
    ) -> tinystoragedrivers_types::Result<Version> {
        let action = self.action;
        if collection == BUDGETS_COLLECTION && id == HOLDS_ID {
            match action {
                RaceAction::WrongBudgetSchema => options = options.schema(1),
                RaceAction::WrongBudgetExpiry => options = options.expires_ms(1_900_000_000_001),
                RaceAction::CompleteMarker
                | RaceAction::ExistingMarker
                | RaceAction::MatchingBudget
                | RaceAction::ExistingBudget => {}
            }
            self.inner
                .put_with(collection, id, doc.clone(), precondition, options)
                .await?;
            if !matches!(action, RaceAction::CompleteMarker) {
                let kind = if matches!(action, RaceAction::ExistingBudget) {
                    ErrorKind::AlreadyExists
                } else {
                    ErrorKind::Conflict
                };
                return Err(tinystoragedrivers_types::StorageError::new(
                    kind,
                    "simulated competing budget migration",
                ));
            }
        }
        self.inner
            .put_with(collection, id, doc, precondition, options)
            .await
    }
}

fn test_storage() -> tinystoragedrivers_api::Storage {
    tinystoragedrivers_testkit::memory_storage(&Scope::new("wallet.migration-test").unwrap())
}

fn legacy_payment() -> Value {
    json!({
        "id": "pay-1",
        "url": "https://api.example.com/data",
        "asset": "USDC",
        "amountAtomic": 2500,
        "amountDisplay": "0.002500 USDC",
        "recipient": "Recipient",
        "network": "eip155:8453",
        "txSignature": "0xabc",
        "status": "settled",
        "timestamp": "2026-03-15T12:00:00Z",
        "authorizationValidUntil": "2026-03-15T12:05:00.250Z",
        "sessionId": "session-a",
        "threadId": "thread-1",
        "committed_hold": "owner:1"
    })
}

fn legacy_payments(count: usize) -> Vec<Value> {
    (0..count)
        .map(|index| {
            let mut payment = legacy_payment();
            payment["id"] = json!(format!("pay-{index}"));
            payment
        })
        .collect()
}

fn append_values(
    storage: &tinystoragedrivers_api::Storage,
    stream: &'static str,
    values: Vec<Value>,
) {
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move {
            streams.append_batch(stream, values).await.unwrap();
        })
        .unwrap();
}

fn assert_migration_not_marked(storage: &tinystoragedrivers_api::Storage) {
    let documents = Arc::clone(storage.documents());
    assert!(
        Blocking::new()
            .unwrap()
            .run(async move { documents.get("wallet.migrations", "x402").await })
            .unwrap()
            .unwrap()
            .is_none()
    );
}

#[derive(Debug, Clone, Copy)]
enum ReadFault {
    EmptyAfterFirstPage(&'static str),
    GrowthAfterSnapshot(&'static str),
    Truncate(&'static str, usize),
    WrongOffset(&'static str),
    ReadError(&'static str),
    Overshoot(&'static str),
    AppendError(&'static str),
    AppendConflictAfterWrite(&'static str),
}

#[derive(Debug)]
struct FaultyReads {
    inner: Arc<dyn StreamStore>,
    fault: ReadFault,
    len_calls: AtomicUsize,
}

#[async_trait]
impl StreamStore for FaultyReads {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }

    async fn append(&self, stream: &str, value: Value) -> tinystoragedrivers_types::Result<u64> {
        self.inner.append(stream, value).await
    }

    async fn append_batch(
        &self,
        stream: &str,
        values: Vec<Value>,
    ) -> tinystoragedrivers_types::Result<u64> {
        self.inner.append_batch(stream, values).await
    }

    async fn append_batch_if_offset(
        &self,
        stream: &str,
        expected_next_offset: u64,
        values: Vec<Value>,
    ) -> tinystoragedrivers_types::Result<u64> {
        if matches!(self.fault, ReadFault::AppendError(name) if stream == name) {
            return Err(tinystoragedrivers_types::StorageError::backend(
                "injected stream append failure",
            ));
        }
        if matches!(self.fault, ReadFault::AppendConflictAfterWrite(name) if stream == name) {
            self.inner
                .append_batch_if_offset(stream, expected_next_offset, values)
                .await?;
            return Err(tinystoragedrivers_types::StorageError::new(
                ErrorKind::Conflict,
                "simulated competing migration append",
            ));
        }
        self.inner
            .append_batch_if_offset(stream, expected_next_offset, values)
            .await
    }

    async fn read_window(
        &self,
        stream: &str,
        from: u64,
        limit: usize,
    ) -> tinystoragedrivers_types::Result<Vec<StreamEntry>> {
        match self.fault {
            ReadFault::ReadError(name) if stream == name => Err(
                tinystoragedrivers_types::StorageError::backend("injected stream read failure"),
            ),
            ReadFault::EmptyAfterFirstPage(name) if stream == name && from > 0 => Ok(Vec::new()),
            ReadFault::Truncate(name, count) if stream == name => {
                let mut entries = self.inner.read_window(stream, from, limit).await?;
                entries.truncate(count);
                Ok(entries)
            }
            ReadFault::WrongOffset(name) if stream == name => {
                let mut entries = self.inner.read_window(stream, from, limit).await?;
                if let Some(first) = entries.first_mut() {
                    first.offset = first.offset.saturating_add(1);
                }
                Ok(entries)
            }
            ReadFault::Overshoot(name) if stream == name => {
                let mut entries = self.inner.read_window(stream, from, limit).await?;
                if let Some(last) = entries.last().cloned() {
                    entries.push(StreamEntry {
                        offset: last.offset.saturating_add(1),
                        value: last.value,
                    });
                }
                Ok(entries)
            }
            _ => self.inner.read_window(stream, from, limit).await,
        }
    }

    async fn len(&self, stream: &str) -> tinystoragedrivers_types::Result<u64> {
        let len = self.inner.len(stream).await?;
        if let ReadFault::GrowthAfterSnapshot(name) = self.fault
            && stream == name
            && self.len_calls.fetch_add(1, Ordering::Relaxed) > 0
        {
            return Ok(len.saturating_add(1));
        }
        Ok(len)
    }

    async fn truncate_before(
        &self,
        stream: &str,
        offset: u64,
    ) -> tinystoragedrivers_types::Result<u64> {
        self.inner.truncate_before(stream, offset).await
    }

    async fn delete_stream(&self, stream: &str) -> tinystoragedrivers_types::Result<bool> {
        self.inner.delete_stream(stream).await
    }

    async fn streams(&self, prefix: &str) -> tinystoragedrivers_types::Result<Vec<String>> {
        self.inner.streams(prefix).await
    }

    async fn seal(&self, stream: &str) -> tinystoragedrivers_types::Result<SealOutcome> {
        self.inner.seal(stream).await
    }

    async fn delete_sealed_stream(
        &self,
        stream: &str,
        sealed_ms: i64,
    ) -> tinystoragedrivers_types::Result<bool> {
        self.inner.delete_sealed_stream(stream, sealed_ms).await
    }

    async fn info(&self, stream: &str) -> tinystoragedrivers_types::Result<Option<StreamInfo>> {
        self.inner.info(stream).await
    }
}

#[test]
fn host_declarations_are_pure_wallet_collection_specs() {
    let declared = collections();
    assert_eq!(declared.len(), 2);
    assert!(
        declared
            .iter()
            .all(|collection| collection.name.starts_with("wallet."))
    );
    assert!(
        declared
            .iter()
            .any(|collection| collection.name == BUDGETS_COLLECTION)
    );
}

#[test]
fn ledger_and_bus_declare_the_same_collections() {
    let bus_names = tinywallet_bus::storage::collections()
        .into_iter()
        .map(|collection| collection.name)
        .collect::<Vec<_>>();
    let ledger_names = collections()
        .into_iter()
        .map(|collection| collection.name)
        .collect::<Vec<_>>();
    assert_eq!(ledger_names, bus_names);
}

#[test]
fn migration_offsets_report_overflow() {
    assert_eq!(offset_after(10, 5, "offset overflow").unwrap(), 15);
    assert!(offset_after(u64::MAX, 1, "offset overflow").is_err());
}

#[test]
fn opening_the_ledger_migrates_legacy_payments_before_reading_them() {
    let storage = test_storage();
    let streams = std::sync::Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move {
            streams
                .append("x402.payments", legacy_payment())
                .await
                .unwrap();
        })
        .unwrap();

    let ledger = PaymentLedger::open(
        LedgerStorage::from_storage(&storage),
        "session-a",
        SpendingBudget::default(),
    )
    .unwrap();
    let records = ledger.recent_payments(10);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].id, "pay-1");
    assert_eq!(records[0].status, PaymentStatus::Settled);
    assert_eq!(records[0].amount_atomic, 2500);
    assert_eq!(records[0].timestamp.timestamp_millis(), V1_PAYMENT_MS);
    assert_eq!(records[0].thread_id.as_deref(), Some("thread-1"));

    let reopened = PaymentLedger::open(
        LedgerStorage::from_storage(&storage),
        "session-a",
        SpendingBudget::default(),
    )
    .unwrap();
    assert_eq!(reopened.recent_payments(10), records);
}

#[test]
fn opening_the_ledger_migrates_legacy_holds_and_keeps_record_metadata() {
    let storage = test_storage();
    let documents = std::sync::Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put_with(
                    "x402_budget",
                    HOLDS_ID,
                    json!({
                        "holds": {
                            "old-writer:7": {
                                "amount": 321,
                                "expires_at_ms": 1_800_000_000_000_i64
                            }
                        }
                    }),
                    Precondition::Absent,
                    WriteOptions::new()
                        .schema(1)
                        .created_ms(1_700_000_000_000)
                        .expires_ms(1_900_000_000_000),
                )
                .await
                .unwrap();
        })
        .unwrap();

    let _ledger = PaymentLedger::open(
        LedgerStorage::from_storage(&storage),
        "session-a",
        SpendingBudget::default(),
    )
    .unwrap();
    let documents = std::sync::Arc::clone(storage.documents());
    let migrated = Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .get(BUDGETS_COLLECTION, HOLDS_ID)
                .await
                .unwrap()
                .unwrap()
        })
        .unwrap();
    assert_eq!(
        migrated.doc,
        json!({
            "holds": {
                "old-writer:7": { "amount": 321, "expires_ms": 1_800_000_000_000_i64 }
            }
        })
    );
    assert_eq!(migrated.meta.schema, 2);
    assert_ne!(migrated.meta.created_ms, 1_700_000_000_000);
    assert_eq!(migrated.meta.expires_ms, Some(1_900_000_000_000));
}

#[test]
fn budget_migration_rejects_matching_target_bodies_with_different_metadata() {
    for (schema, expires_ms) in [
        (1, Some(1_900_000_000_000)),
        (2, Some(1_900_000_000_001)),
        (2, None),
    ] {
        let storage = test_storage();
        let documents = Arc::clone(storage.documents());
        Blocking::new()
            .unwrap()
            .run(async move {
                let legacy = json!({ "holds": { "old": {
                    "amount": 12,
                    "expires_at_ms": 1_800_000_000_000_i64
                }}});
                documents
                    .put_with(
                        "x402_budget",
                        HOLDS_ID,
                        legacy,
                        Precondition::Absent,
                        WriteOptions::new().schema(1).expires_ms(1_900_000_000_000),
                    )
                    .await?;
                let target = json!({ "holds": { "old": {
                    "amount": 12,
                    "expires_ms": 1_800_000_000_000_i64
                }}});
                let mut options = WriteOptions::new().schema(schema);
                if let Some(expires_ms) = expires_ms {
                    options = options.expires_ms(expires_ms);
                }
                documents
                    .put_with(
                        BUDGETS_COLLECTION,
                        HOLDS_ID,
                        target,
                        Precondition::Absent,
                        options,
                    )
                    .await?;
                Ok::<_, tinystoragedrivers_types::StorageError>(())
            })
            .unwrap()
            .unwrap();

        let documents = Arc::clone(storage.documents());
        let result = Blocking::new()
            .unwrap()
            .run(async move { super::migrate_budgets(documents.as_ref()).await })
            .unwrap();
        assert!(result.is_err(), "schema={schema}, expiry={expires_ms:?}");

        let documents = Arc::clone(storage.documents());
        let (source, target) = Blocking::new()
            .unwrap()
            .run(async move {
                Ok::<_, tinystoragedrivers_types::StorageError>((
                    documents.get("x402_budget", HOLDS_ID).await?,
                    documents.get(BUDGETS_COLLECTION, HOLDS_ID).await?,
                ))
            })
            .unwrap()
            .unwrap();
        assert!(source.is_some(), "legacy source must remain intact");
        let target = target.expect("conflicting target must remain intact");
        assert_eq!(target.meta.schema, schema);
        assert_eq!(target.meta.expires_ms, expires_ms);
        assert_migration_not_marked(&storage);
    }
}

#[test]
fn budget_migration_does_not_mark_complete_after_an_absent_write_conflict() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put(
                    "x402_budget",
                    HOLDS_ID,
                    json!({ "holds": { "old": { "amount": 12, "expires_at_ms": 1_800_000_000_000_i64 }}}),
                    Precondition::Absent,
                )
                .await
        })
        .unwrap()
        .unwrap();

    let documents = Arc::clone(storage.documents());
    let racing = tinystoragedrivers_testkit::ConflictOnce::new(documents);
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate_budgets(&racing).await })
        .unwrap();
    assert!(result.is_err());

    let documents = Arc::clone(storage.documents());
    let (source, target) = Blocking::new()
        .unwrap()
        .run(async move {
            Ok::<_, tinystoragedrivers_types::StorageError>((
                documents.get("x402_budget", HOLDS_ID).await?,
                documents.get(BUDGETS_COLLECTION, HOLDS_ID).await?,
            ))
        })
        .unwrap()
        .unwrap();
    assert!(source.is_some());
    assert!(target.is_none());
    assert_migration_not_marked(&storage);
}

#[test]
fn budget_migration_accepts_a_matching_target_with_matching_metadata() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            let body = json!({ "holds": { "old": {
                "amount": 12,
                "expires_at_ms": 1_800_000_000_000_i64
            }}});
            documents
                .put_with(
                    "x402_budget",
                    HOLDS_ID,
                    body,
                    Precondition::Absent,
                    WriteOptions::new().schema(1).expires_ms(1_900_000_000_000),
                )
                .await?;
            documents
                .put_with(
                    BUDGETS_COLLECTION,
                    HOLDS_ID,
                    json!({ "holds": { "old": {
                        "amount": 12,
                        "expires_ms": 1_800_000_000_000_i64
                    }}}),
                    Precondition::Absent,
                    WriteOptions::new()
                        .schema(BUDGETS_VERSION)
                        .expires_ms(1_900_000_000_000),
                )
                .await?;
            Ok::<_, tinystoragedrivers_types::StorageError>(())
        })
        .unwrap()
        .unwrap();

    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate_budgets(documents.as_ref()).await })
        .unwrap()
        .unwrap();
}

#[test]
fn stored_and_runtime_payment_statuses_round_trip_without_changing_the_variant() {
    use super::super::types::PaymentStatus;

    for (runtime, stored) in [
        (PaymentStatus::Pending, StoredPaymentStatus::Pending),
        (PaymentStatus::Settled, StoredPaymentStatus::Settled),
        (PaymentStatus::Failed, StoredPaymentStatus::Failed),
        (PaymentStatus::Denied, StoredPaymentStatus::Denied),
    ] {
        assert_eq!(StoredPaymentStatus::from(runtime), stored);
        assert_eq!(PaymentStatus::from(stored), runtime);
    }
}

#[test]
fn owner_migration_marks_empty_sources_complete_and_is_idempotent() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap()
        .unwrap();

    let documents = Arc::clone(storage.documents());
    let marker = Blocking::new()
        .unwrap()
        .run(async move { documents.get("wallet.migrations", "x402").await })
        .unwrap()
        .unwrap()
        .expect("successful migration writes its completion marker");
    assert_eq!(marker.doc, json!({ "version": 2 }));

    let documents = Arc::clone(storage.documents());
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap()
        .unwrap();
}

#[test]
fn owner_migration_conflict_does_not_claim_a_missing_marker_was_written() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    let streams = Arc::clone(storage.streams());
    let racing = tinystoragedrivers_testkit::ConflictOnce::new(documents);
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(&racing, streams.as_ref()).await })
        .unwrap();
    assert!(result.is_err());
    assert_migration_not_marked(&storage);
}

#[test]
fn owner_migration_propagates_a_non_conflict_marker_write_failure() {
    let storage = test_storage();
    let plan = tinystoragedrivers_testkit::FaultPlan::new();
    plan.fail_operation_nth("documents.put", 1, ErrorKind::Unavailable);
    let documents =
        tinystoragedrivers_testkit::Failing::with_plan(Arc::clone(storage.documents()), plan);
    let streams = Arc::clone(storage.streams());
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(&documents, streams.as_ref()).await })
        .unwrap();
    assert!(result.is_err());
    assert_migration_not_marked(&storage);
}

#[test]
fn budget_migration_propagates_a_non_conflict_target_write_failure() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put(
                    "x402_budget",
                    HOLDS_ID,
                    json!({ "holds": { "old": {
                        "amount": 12,
                        "expires_at_ms": 1_800_000_000_000_i64
                    }}}),
                    Precondition::Absent,
                )
                .await
        })
        .unwrap()
        .unwrap();

    let plan = tinystoragedrivers_testkit::FaultPlan::new();
    plan.fail_operation_nth("documents.put_with", 1, ErrorKind::Unavailable);
    let documents =
        tinystoragedrivers_testkit::Failing::with_plan(Arc::clone(storage.documents()), plan);
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate_budgets(&documents).await })
        .unwrap();
    assert!(result.is_err());
    let documents = Arc::clone(storage.documents());
    let (source, target) = Blocking::new()
        .unwrap()
        .run(async move {
            Ok::<_, tinystoragedrivers_types::StorageError>((
                documents.get("x402_budget", HOLDS_ID).await?,
                documents.get(BUDGETS_COLLECTION, HOLDS_ID).await?,
            ))
        })
        .unwrap()
        .unwrap();
    assert!(source.is_some());
    assert!(target.is_none());
}

#[test]
fn invalid_legacy_payment_rows_are_skipped_without_changing_the_stream_name_contract() {
    assert_eq!(
        super::migrate_payments_stream("x402.payments", vec![json!({ "bad": true })]).unwrap(),
        Some(("wallet.payments".into(), vec![]))
    );
    assert_eq!(
        super::renamed_holds(&json!({})).unwrap(),
        serde_json::Map::new()
    );
    assert!(super::renamed_holds(&json!({ "holds": [] })).is_none());
}

#[test]
fn malformed_legacy_budget_holds_abort_migration_without_marking_it_complete() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put(
                    "x402_budget",
                    HOLDS_ID,
                    json!({ "holds": { "reserved": { "amount": "12", "expires_at_ms": 1_800_000_000_000_i64 } } }),
                    Precondition::Absent,
                )
                .await
        })
        .unwrap()
        .unwrap();

    let documents = Arc::clone(storage.documents());
    let streams = Arc::clone(storage.streams());
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap();

    assert!(result.is_err(), "malformed holds must stop migration");
    let documents = Arc::clone(storage.documents());
    let (target, marker) = Blocking::new()
        .unwrap()
        .run(async move {
            Ok::<_, tinystoragedrivers_types::StorageError>((
                documents.get(BUDGETS_COLLECTION, HOLDS_ID).await?,
                documents.get("wallet.migrations", "x402").await?,
            ))
        })
        .unwrap()
        .unwrap();
    assert!(target.is_none(), "invalid reservations must not be dropped");
    assert!(marker.is_none(), "a failed migration must remain retryable");
}

#[test]
fn owner_migration_advances_a_versioned_marker_and_skips_current_versions() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put(
                    "wallet.migrations",
                    "x402",
                    json!({ "version": 1 }),
                    Precondition::Absent,
                )
                .await
        })
        .unwrap()
        .unwrap();
    let documents = Arc::clone(storage.documents());
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap()
        .unwrap();

    let documents = Arc::clone(storage.documents());
    let marker = Blocking::new()
        .unwrap()
        .run(async move { documents.get("wallet.migrations", "x402").await })
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(marker.doc, json!({ "version": 2 }));

    let documents = Arc::clone(storage.documents());
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap()
        .unwrap();
}

#[test]
fn owner_migration_accepts_a_competing_completed_marker() {
    let storage = test_storage();
    let documents = RacingDocuments {
        inner: Arc::clone(storage.documents()),
        action: RaceAction::CompleteMarker,
    };
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate(&documents, streams.as_ref()).await })
        .unwrap()
        .unwrap();
    let documents = Arc::clone(storage.documents());
    let marker = Blocking::new()
        .unwrap()
        .run(async move { documents.get("wallet.migrations", "x402").await })
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(marker.doc, json!({ "version": 2 }));
}

#[test]
fn owner_migration_accepts_an_already_existing_matching_marker() {
    let storage = test_storage();
    let documents = RacingDocuments {
        inner: Arc::clone(storage.documents()),
        action: RaceAction::ExistingMarker,
    };
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate(&documents, streams.as_ref()).await })
        .unwrap()
        .unwrap();
}

#[test]
fn budget_migration_conflict_retry_rejects_matching_bodies_with_wrong_metadata() {
    for action in [RaceAction::WrongBudgetSchema, RaceAction::WrongBudgetExpiry] {
        let storage = test_storage();
        let documents = Arc::clone(storage.documents());
        Blocking::new()
            .unwrap()
            .run(async move {
                documents
                    .put_with(
                        "x402_budget",
                        HOLDS_ID,
                        json!({ "holds": { "old": {
                            "amount": 12,
                            "expires_at_ms": 1_800_000_000_000_i64
                        }}}),
                        Precondition::Absent,
                        WriteOptions::new().schema(1).expires_ms(1_900_000_000_000),
                    )
                    .await
            })
            .unwrap()
            .unwrap();
        let documents = RacingDocuments {
            inner: Arc::clone(storage.documents()),
            action,
        };
        let result = Blocking::new()
            .unwrap()
            .run(async move { super::migrate_budgets(&documents).await })
            .unwrap();
        assert!(result.is_err(), "{action:?}");

        let documents = Arc::clone(storage.documents());
        let (source, target) = Blocking::new()
            .unwrap()
            .run(async move {
                Ok::<_, tinystoragedrivers_types::StorageError>((
                    documents.get("x402_budget", HOLDS_ID).await?,
                    documents.get(BUDGETS_COLLECTION, HOLDS_ID).await?,
                ))
            })
            .unwrap()
            .unwrap();
        assert!(source.is_some(), "legacy row must be preserved");
        let target = target.expect("competing target row must be preserved");
        assert_eq!(
            target.doc,
            json!({ "holds": { "old": {
                "amount": 12,
                "expires_ms": 1_800_000_000_000_i64
            }}})
        );
        match action {
            RaceAction::WrongBudgetSchema => assert_eq!(target.meta.schema, 1),
            RaceAction::WrongBudgetExpiry => {
                assert_eq!(target.meta.expires_ms, Some(1_900_000_000_001));
            }
            RaceAction::CompleteMarker
            | RaceAction::ExistingMarker
            | RaceAction::MatchingBudget
            | RaceAction::ExistingBudget => unreachable!(),
        }
        assert_migration_not_marked(&storage);
    }
}

#[test]
fn budget_migration_accepts_a_matching_concurrent_write_after_conflict() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put_with(
                    "x402_budget",
                    HOLDS_ID,
                    json!({ "holds": { "old": {
                        "amount": 12,
                        "expires_at_ms": 1_800_000_000_000_i64
                    }}}),
                    Precondition::Absent,
                    WriteOptions::new().schema(1).expires_ms(1_900_000_000_000),
                )
                .await
        })
        .unwrap()
        .unwrap();
    let documents = RacingDocuments {
        inner: Arc::clone(storage.documents()),
        action: RaceAction::MatchingBudget,
    };
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate_budgets(&documents).await })
        .unwrap();
    assert!(result.is_ok());
}

#[test]
fn budget_migration_accepts_an_already_existing_matching_document() {
    let storage = test_storage();
    let documents = Arc::clone(storage.documents());
    Blocking::new()
        .unwrap()
        .run(async move {
            documents
                .put_with(
                    "x402_budget",
                    HOLDS_ID,
                    json!({ "holds": { "old": {
                        "amount": 12,
                        "expires_at_ms": 1_800_000_000_000_i64
                    }}}),
                    Precondition::Absent,
                    WriteOptions::new().schema(1),
                )
                .await
        })
        .unwrap()
        .unwrap();
    let documents = RacingDocuments {
        inner: Arc::clone(storage.documents()),
        action: RaceAction::ExistingBudget,
    };

    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate_budgets(&documents).await })
        .unwrap();

    assert!(result.is_ok());
}

#[test]
fn payment_migration_refuses_a_longer_or_different_existing_target() {
    for target in [vec![json!({}), json!({})], vec![json!({ "wrong": true })]] {
        let storage = test_storage();
        append_values(&storage, "x402.payments", legacy_payments(1));
        append_values(&storage, "wallet.payments", target);
        let streams = Arc::clone(storage.streams());
        let result = Blocking::new()
            .unwrap()
            .run(async move { super::migrate_payments(streams.as_ref()).await })
            .unwrap();
        assert!(result.is_err());
        assert_migration_not_marked(&storage);
    }
}

#[test]
fn unrelated_stream_names_are_not_migrated() {
    assert_eq!(
        super::migrate_payments_stream("other.stream", vec![]).unwrap(),
        None
    );
}

#[test]
fn incomplete_legacy_payment_window_does_not_mark_migration_complete() {
    let storage = test_storage();
    append_values(&storage, "x402.payments", legacy_payments(513));
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::EmptyAfterFirstPage("x402.payments"),
        len_calls: AtomicUsize::new(0),
    });

    let documents = Arc::clone(storage.documents());
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await });

    assert!(matches!(result, Ok(Err(_))));
    assert_migration_not_marked(&storage);
}

#[test]
fn payment_migration_copies_a_large_legacy_stream_across_bounded_batches() {
    let storage = test_storage();
    let count = 1_025;
    append_values(&storage, "x402.payments", legacy_payments(count));
    let streams = Arc::clone(storage.streams());

    Blocking::new()
        .unwrap()
        .run(async move { super::migrate_payments(streams.as_ref()).await })
        .unwrap()
        .unwrap();

    let streams = Arc::clone(storage.streams());
    assert_eq!(
        Blocking::new()
            .unwrap()
            .run(async move { streams.len("wallet.payments").await })
            .unwrap()
            .unwrap(),
        count as u64
    );
}

#[test]
fn incomplete_existing_payment_prefix_does_not_mark_migration_complete() {
    let storage = test_storage();
    let source = legacy_payments(2);
    append_values(&storage, "x402.payments", source.clone());
    let migrated = super::migrate_payments_stream("x402.payments", source)
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(migrated.len(), 2);
    append_values(&storage, "wallet.payments", migrated);
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::Truncate("wallet.payments", 1),
        len_calls: AtomicUsize::new(0),
    });

    let documents = Arc::clone(storage.documents());
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await });

    assert!(matches!(result, Ok(Err(_))));
    assert_migration_not_marked(&storage);
}

#[test]
fn changed_legacy_payment_source_does_not_mark_migration_complete() {
    let storage = test_storage();
    append_values(&storage, "x402.payments", legacy_payments(1));
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::GrowthAfterSnapshot("x402.payments"),
        len_calls: AtomicUsize::new(0),
    });
    let documents = Arc::clone(storage.documents());

    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await });

    assert!(matches!(result, Ok(Err(_))));
    assert_migration_not_marked(&storage);
}

#[test]
fn malformed_legacy_payment_offsets_do_not_mark_migration_complete() {
    let storage = test_storage();
    append_values(&storage, "x402.payments", legacy_payments(1));
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::WrongOffset("x402.payments"),
        len_calls: AtomicUsize::new(0),
    });
    let documents = Arc::clone(storage.documents());
    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap();
    assert!(result.is_err());
    assert_migration_not_marked(&storage);
}

#[test]
fn payment_migration_rejects_stream_read_errors_and_oversized_windows() {
    for fault in [
        ReadFault::ReadError("x402.payments"),
        ReadFault::Overshoot("x402.payments"),
    ] {
        let storage = test_storage();
        append_values(&storage, "x402.payments", legacy_payments(1));
        let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
            inner: Arc::clone(storage.streams()),
            fault,
            len_calls: AtomicUsize::new(0),
        });
        let documents = Arc::clone(storage.documents());
        let result = Blocking::new()
            .unwrap()
            .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
            .unwrap();
        assert!(result.is_err());
        assert_migration_not_marked(&storage);
    }
}

#[test]
fn payment_migration_propagates_errors_reading_an_existing_target_prefix() {
    let storage = test_storage();
    append_values(&storage, "x402.payments", legacy_payments(1));
    append_values(&storage, "wallet.payments", vec![json!({ "wrong": true })]);
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::ReadError("wallet.payments"),
        len_calls: AtomicUsize::new(0),
    });
    let documents = Arc::clone(storage.documents());

    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap();

    assert!(result.is_err());
    assert_migration_not_marked(&storage);
}

#[test]
fn payment_migration_propagates_target_append_failure_without_marking_complete() {
    let storage = test_storage();
    append_values(&storage, "x402.payments", legacy_payments(1));
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::AppendError("wallet.payments"),
        len_calls: AtomicUsize::new(0),
    });
    let documents = Arc::clone(storage.documents());

    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await });

    assert!(matches!(result, Ok(Err(_))));
    assert_migration_not_marked(&storage);
}

#[test]
fn payment_migration_accepts_a_matching_concurrent_append() {
    let storage = test_storage();
    append_values(&storage, "x402.payments", legacy_payments(1));
    let streams: Arc<dyn StreamStore> = Arc::new(FaultyReads {
        inner: Arc::clone(storage.streams()),
        fault: ReadFault::AppendConflictAfterWrite("wallet.payments"),
        len_calls: AtomicUsize::new(0),
    });
    let documents = Arc::clone(storage.documents());

    let result = Blocking::new()
        .unwrap()
        .run(async move { super::migrate(documents.as_ref(), streams.as_ref()).await })
        .unwrap();

    assert!(result.is_ok());
    let streams = Arc::clone(storage.streams());
    assert_eq!(
        Blocking::new()
            .unwrap()
            .run(async move { streams.len("wallet.payments").await })
            .unwrap()
            .unwrap(),
        1
    );
}

#[test]
fn payment_migration_completes_a_matching_prefix_and_appends_only_its_suffix() {
    let storage = test_storage();
    let source = legacy_payments(2);
    append_values(&storage, "x402.payments", source.clone());
    let migrated = super::migrate_payments_stream("x402.payments", source)
        .unwrap()
        .unwrap()
        .1;
    assert_eq!(migrated.len(), 2);
    append_values(&storage, "wallet.payments", vec![migrated[0].clone()]);
    let streams = Arc::clone(storage.streams());
    assert_eq!(
        Blocking::new()
            .unwrap()
            .run(async move { streams.len("wallet.payments").await })
            .unwrap()
            .unwrap(),
        1
    );
    let streams = Arc::clone(storage.streams());
    Blocking::new()
        .unwrap()
        .run(async move { super::migrate_payments(streams.as_ref()).await })
        .unwrap()
        .unwrap();
    let streams = Arc::clone(storage.streams());
    let entries = Blocking::new()
        .unwrap()
        .run(async move { streams.read_window("wallet.payments", 0, 10).await })
        .unwrap()
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].offset, 0);
    assert_eq!(entries[1].offset, 1);
}

#[test]
fn payment_migration_accepts_an_already_complete_matching_target() {
    let storage = test_storage();
    let source = legacy_payments(2);
    append_values(&storage, "x402.payments", source.clone());
    let migrated = super::migrate_payments_stream("x402.payments", source)
        .unwrap()
        .unwrap()
        .1;
    append_values(&storage, "wallet.payments", migrated.clone());
    let streams = Arc::clone(storage.streams());

    Blocking::new()
        .unwrap()
        .run(async move { super::migrate_payments(streams.as_ref()).await })
        .unwrap()
        .unwrap();

    let streams = Arc::clone(storage.streams());
    let entries = Blocking::new()
        .unwrap()
        .run(async move { streams.read_window("wallet.payments", 0, 10).await })
        .unwrap()
        .unwrap();
    assert_eq!(entries.len(), migrated.len());
    assert_eq!(
        entries
            .into_iter()
            .map(|entry| entry.value)
            .collect::<Vec<_>>(),
        migrated
    );
}
