//! Tests for confidential routing decisions in the typed wallet client.

use super::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tinybus::module::{
    AccessFuture, FailureReporter, FailureSink, ModuleAccess, ModuleCallError, ProxyFailure,
    ReleaseAsset, ReleaseRecord,
};

struct Quiet;

impl FailureSink for Quiet {
    fn capture(&self, _: &tinybus::module::FailureReport<'_>) {}
}

struct NoModules {
    reporter: FailureReporter,
}

static RECORD: ReleaseRecord = ReleaseRecord {
    id: "tinywallet",
    bus_name: tinywallet_bus::BUS_NAME,
    object_path: tinywallet_bus::OBJECT_PATH,
    version: "0.25.1",
    release_url: "https://example.invalid/tinywallet",
    assets: &[],
};

impl ModuleAccess for NoModules {
    fn find(&self, id: &str) -> Option<&'static ReleaseRecord> {
        (id == RECORD.id).then_some(&RECORD)
    }

    fn enabled(&self) -> bool {
        true
    }

    fn reporter(&self) -> &FailureReporter {
        &self.reporter
    }

    fn ensure_loaded<'a>(&'a self, _: &'a str) -> AccessFuture<'a, Result<(), String>> {
        Box::pin(async { Err("not loaded".to_string()) })
    }

    fn proxy<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> AccessFuture<'a, Result<tinybus::Proxy, ProxyFailure>> {
        Box::pin(async { Err(ProxyFailure::Transport) })
    }
}

fn client() -> WalletClient {
    WalletClient::new(ModuleClient::new(NoModules {
        reporter: FailureReporter::new(Arc::new(Quiet)),
    }))
}

struct MustNotSerialize(Arc<AtomicBool>);

impl serde::Serialize for MustNotSerialize {
    fn serialize<S>(&self, _: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.store(true, Ordering::SeqCst);
        Err(<S::Error as serde::ser::Error>::custom(
            "request serialization was not expected",
        ))
    }
}

struct CallerOwnedSecretRequest {
    secret: String,
    serialized: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}

impl serde::Serialize for CallerOwnedSecretRequest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.serialized.store(true, Ordering::SeqCst);
        serializer.serialize_str(&self.secret)
    }
}

impl Drop for CallerOwnedSecretRequest {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.dropped.store(true, Ordering::SeqCst);
    }
}

#[test]
fn every_bus_confidential_member_is_classified_as_confidential() {
    for member in CONFIDENTIAL_METHODS {
        assert!(is_confidential(member), "{member}");
    }
}

#[test]
fn wallet_signing_members_are_declared_confidential() {
    for member in [
        methods::DERIVE_ACCOUNT,
        methods::DERIVE_MNEMONIC_SEED,
        methods::EXPORT_KEY,
        methods::GENERATE_MNEMONIC,
        methods::SIGN_MESSAGE,
        methods::SIGN_TRANSACTION,
    ] {
        assert!(is_confidential(member), "{member}");
    }
}

#[test]
fn calls_use_the_tinywallet_contract_identity_and_declared_members() {
    assert_eq!(tinywallet_bus::BUS_NAME, "ai.tinyhumans.tinywallet.Wallet");
    assert_eq!(
        tinywallet_bus::OBJECT_PATH,
        "/ai/tinyhumans/tinywallet/Wallet"
    );
    for member in [
        methods::DERIVE_ACCOUNT,
        methods::DERIVE_MNEMONIC_SEED,
        methods::ENCODE_ERC20_TRANSFER,
        methods::EXPORT_KEY,
        methods::GENERATE_MNEMONIC,
        methods::SIGN_MESSAGE,
        methods::SIGN_TRANSACTION,
    ] {
        assert!(
            tinywallet_bus::METHODS.contains(&member),
            "{member} is not in the contract"
        );
    }
}

#[test]
fn public_wallet_members_remain_ordinary_calls() {
    for member in [
        methods::ENCODE_ERC20_TRANSFER,
        methods::VALIDATE_ADDRESS,
        methods::WEB3_ROUTES,
        methods::X402_CLOSE,
    ] {
        assert!(!is_confidential(member), "{member}");
    }
}

#[test]
fn confidential_wire_requests_keep_their_distinct_wrapper_shapes() {
    let secret = SecretMaterial {
        mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
        derivation_path: "m/44'/60'/0'/0/0".to_string(),
        chain: tinywallet_bus::Chain::Evm,
    };
    let bare = serde_json::to_value(&secret);
    assert!(bare.is_ok(), "the secret wire type must serialize");
    let bare = bare.unwrap_or(serde_json::Value::Null);
    assert!(serde_json::from_value::<ExportRequest>(bare).is_err());

    let signing = serde_json::to_value(SignRequest {
        secret: secret.clone(),
        transaction: TransactionSpec::Evm {
            to: format!("0x{}", "11".repeat(20)),
            value_wei: "1".to_string(),
            data_hex: "0x".to_string(),
            nonce: 0,
            gas_limit: 21_000,
            gas_price_wei: "1".to_string(),
            chain_id: 1,
        },
    });
    assert!(signing.is_ok(), "the sign request wire type must serialize");
    let signing = signing.unwrap_or(serde_json::Value::Null);
    assert!(serde_json::from_value::<SignMessageRequest>(signing).is_err());
}

#[test]
fn remote_peer_details_are_absent_from_error_renderings() {
    let error = ClientError::Remote(ModuleCallFailure {
        kind: ModuleCallError::ModuleFault,
        wire_name: "private-peer-detail".to_string(),
        message: "sensitive request content".to_string(),
    });
    assert!(!format!("{error:?}").contains("private-peer-detail"));
    assert!(!format!("{error:?}").contains("sensitive request content"));
    assert!(!error.to_string().contains("private-peer-detail"));
    assert!(!error.to_string().contains("sensitive request content"));
}

#[test]
fn mnemonic_request_types_wipe_their_phrase_fields() {
    let mut secret = SecretMaterial {
        mnemonic: "sensitive phrase".to_string(),
        derivation_path: "m/44'/60'/0'/0/0".to_string(),
        chain: tinywallet_bus::Chain::Evm,
    };
    secret.zeroize_mnemonic();
    let secret_mnemonic_is_empty = secret.mnemonic.is_empty();
    assert!(secret_mnemonic_is_empty);

    let mut request = DeriveMnemonicSeedRequest {
        mnemonic: "sensitive phrase".to_string(),
    };
    request.zeroize_mnemonic();
    let request_mnemonic_is_empty = request.mnemonic.is_empty();
    assert!(request_mnemonic_is_empty);
}

static OBSERVER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static OBSERVED_MNEMONIC_WIPES: std::sync::Mutex<Vec<(&'static str, bool)>> =
    std::sync::Mutex::new(Vec::new());

pub(super) fn observe_mnemonic_wipe(wrapper: &'static str, mnemonic_is_empty: bool) {
    OBSERVED_MNEMONIC_WIPES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push((wrapper, mnemonic_is_empty));
}

fn take_observed_mnemonic_wipes() -> Vec<(&'static str, bool)> {
    std::mem::take(
        &mut *OBSERVED_MNEMONIC_WIPES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    )
}

struct WipeObserved(Arc<AtomicBool>);

impl ZeroizeMnemonic for WipeObserved {
    fn zeroize_mnemonic(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn complete_with_guard(result: Result<(), ()>, wiped: Arc<AtomicBool>) -> Result<(), ()> {
    let _request = MnemonicRequestGuard(WipeObserved(wiped));
    result
}

#[test]
fn mnemonic_request_guard_wipes_after_success_and_error() {
    for result in [Ok(()), Err(())] {
        let wiped = Arc::new(AtomicBool::new(false));
        let outcome = complete_with_guard(result, wiped.clone());
        assert_eq!(outcome, result);
        assert!(wiped.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn mnemonic_request_guard_wipes_when_the_waiting_call_is_cancelled() {
    let wiped = Arc::new(AtomicBool::new(false));
    let task_wiped = wiped.clone();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let _request = MnemonicRequestGuard(WipeObserved(task_wiped));
        let _ = started_tx.send(());
        std::future::pending::<()>().await;
    });
    assert!(started_rx.await.is_ok());
    task.abort();
    let _ = task.await;
    assert!(wiped.load(Ordering::SeqCst));
}

fn secret_material() -> SecretMaterial {
    SecretMaterial {
        mnemonic: "sensitive phrase".to_string(),
        derivation_path: "m/44'/60'/0'/0/0".to_string(),
        chain: Chain::Evm,
    }
}

fn transaction() -> TransactionSpec {
    TransactionSpec::Evm {
        to: format!("0x{}", "11".repeat(20)),
        value_wei: "1".to_string(),
        data_hex: "0x".to_string(),
        nonce: 0,
        gas_limit: 21_000,
        gas_price_wei: "1".to_string(),
        chain_id: 1,
    }
}

fn assert_remote_unavailable(result: Result<impl Sized, ClientError>) {
    assert!(matches!(
        result,
        Err(ClientError::Remote(failure)) if failure.kind == ModuleCallError::Unavailable
    ));
}

#[tokio::test]
async fn signing_and_export_wrappers_wipe_mnemonics_after_errors() {
    let _observer_lock = OBSERVER_TEST_LOCK.lock().await;
    let _ = take_observed_mnemonic_wipes();

    let result = client()
        .sign_transaction(secret_material(), transaction())
        .await;
    assert_remote_unavailable(result);
    let result = client()
        .sign_message(secret_material(), &[0x42; 32], Scheme::Secp256k1Prehash)
        .await;
    assert_remote_unavailable(result);
    let result = client().export_key(secret_material()).await;
    assert_remote_unavailable(result);

    assert_eq!(
        take_observed_mnemonic_wipes(),
        vec![
            ("sign_transaction", true),
            ("sign_message", true),
            ("export_key", true),
        ]
    );
}

static STRICT_RECORD: std::sync::OnceLock<Option<ReleaseRecord>> = std::sync::OnceLock::new();

// The dummy pin lets the strict call reach preparation. The fake access never
// reports readiness or supplies a proxy, so no attestation succeeds and no
// request can be serialized or delivered.
fn strict_record() -> Option<&'static ReleaseRecord> {
    STRICT_RECORD
        .get_or_init(|| {
            let host_key = tinybus::module::platform::host_candidates()
                .into_iter()
                .next()?
                .into_boxed_str();
            let host_key = Box::leak(host_key);
            let archive_sha256 = Box::leak("a".repeat(64).into_boxed_str());
            let library_sha256 = Box::leak("b".repeat(64).into_boxed_str());
            let assets = Box::leak(
                vec![ReleaseAsset {
                    host_key,
                    archive: "fixture.tar.gz",
                    sha256: archive_sha256,
                    library_sha256: Some(library_sha256),
                }]
                .into_boxed_slice(),
            );
            Some(ReleaseRecord {
                id: "tinywallet",
                bus_name: tinywallet_bus::BUS_NAME,
                object_path: tinywallet_bus::OBJECT_PATH,
                version: "0.25.1",
                release_url: "https://example.invalid/tinywallet",
                assets,
            })
        })
        .as_ref()
}

struct PendingModules {
    reporter: FailureReporter,
    started: Arc<tokio::sync::Notify>,
}

impl ModuleAccess for PendingModules {
    fn find(&self, id: &str) -> Option<&'static ReleaseRecord> {
        if id == "tinywallet" {
            strict_record()
        } else {
            None
        }
    }

    fn enabled(&self) -> bool {
        true
    }

    fn reporter(&self) -> &FailureReporter {
        &self.reporter
    }

    fn ensure_loaded<'a>(&'a self, _: &'a str) -> AccessFuture<'a, Result<(), String>> {
        Box::pin(async { Err("unexpected ordinary load".to_string()) })
    }

    fn prepare_attested<'a>(&'a self, _: &'a str) -> AccessFuture<'a, Result<(), String>> {
        let started = Arc::clone(&self.started);
        Box::pin(async move {
            started.notify_one();
            std::future::pending().await
        })
    }

    fn proxy<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
    ) -> AccessFuture<'a, Result<tinybus::Proxy, ProxyFailure>> {
        Box::pin(async { Err(ProxyFailure::Transport) })
    }
}

fn pending_client(started: Arc<tokio::sync::Notify>) -> WalletClient {
    WalletClient::new(ModuleClient::new(PendingModules {
        reporter: FailureReporter::new(Arc::new(Quiet)),
        started,
    }))
}

#[tokio::test]
async fn signing_and_export_wrappers_wipe_mnemonics_when_cancelled() {
    // Unsupported hosts have no published module platform candidate to pin.
    if strict_record().is_none() {
        return;
    }
    let _observer_lock = OBSERVER_TEST_LOCK.lock().await;
    let _ = take_observed_mnemonic_wipes();

    let started = Arc::new(tokio::sync::Notify::new());
    let wallet = pending_client(Arc::clone(&started));
    let transaction_task = tokio::spawn(async move {
        let _ = wallet
            .sign_transaction(secret_material(), transaction())
            .await;
    });
    started.notified().await;
    transaction_task.abort();
    let _ = transaction_task.await;

    let started = Arc::new(tokio::sync::Notify::new());
    let wallet = pending_client(Arc::clone(&started));
    let message_task = tokio::spawn(async move {
        let _ = wallet
            .sign_message(secret_material(), &[0x42; 32], Scheme::Secp256k1Prehash)
            .await;
    });
    started.notified().await;
    message_task.abort();
    let _ = message_task.await;

    let started = Arc::new(tokio::sync::Notify::new());
    let wallet = pending_client(Arc::clone(&started));
    let export_task = tokio::spawn(async move {
        let _ = wallet.export_key(secret_material()).await;
    });
    started.notified().await;
    export_task.abort();
    let _ = export_task.await;

    assert_eq!(
        take_observed_mnemonic_wipes(),
        vec![
            ("sign_transaction", true),
            ("sign_message", true),
            ("export_key", true),
        ]
    );
}

#[tokio::test]
async fn ordinary_call_refuses_confidential_member_before_serializing_request() {
    for member in CONFIDENTIAL_METHODS {
        let serialized = Arc::new(AtomicBool::new(false));
        let request = MustNotSerialize(serialized.clone());
        let result = client()
            .call::<_, serde_json::Value>(member, &request)
            .await;
        assert!(
            matches!(result, Err(ClientError::ConfidentialRequired)),
            "{member}"
        );
        assert!(!serialized.load(Ordering::SeqCst), "{member}");
    }
}

#[tokio::test]
async fn ordinary_refusal_leaves_secret_request_with_caller_to_wipe() {
    let serialized = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let request = CallerOwnedSecretRequest {
        secret: "content-free-test-secret".to_owned(),
        serialized: Arc::clone(&serialized),
        dropped: Arc::clone(&dropped),
    };
    let result = client()
        .call::<_, serde_json::Value>(methods::DERIVE_ACCOUNT, &request)
        .await;

    assert!(matches!(result, Err(ClientError::ConfidentialRequired)));
    assert!(!serialized.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));
    drop(request);
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn attested_call_refuses_public_member_before_module_access() {
    let serialized = Arc::new(AtomicBool::new(false));
    let request = MustNotSerialize(serialized.clone());
    let result = client()
        .call_attested::<_, serde_json::Value>(methods::ENCODE_ERC20_TRANSFER, &request)
        .await;
    assert!(matches!(result, Err(ClientError::NotConfidential)));
    assert!(!serialized.load(Ordering::SeqCst));
}

#[tokio::test]
async fn attested_call_with_no_release_library_pins_never_serializes_request() {
    let serialized = Arc::new(AtomicBool::new(false));
    let request = MustNotSerialize(serialized.clone());
    let result = client()
        .call_attested::<_, serde_json::Value>(methods::SIGN_MESSAGE, &request)
        .await;
    assert!(matches!(
        result,
        Err(ClientError::Remote(failure)) if failure.kind == ModuleCallError::Unavailable
    ));
    assert!(!serialized.load(Ordering::SeqCst));
}

#[tokio::test]
async fn attested_failure_leaves_secret_request_with_caller_to_wipe() {
    let serialized = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let request = CallerOwnedSecretRequest {
        secret: "content-free-test-secret".to_owned(),
        serialized: Arc::clone(&serialized),
        dropped: Arc::clone(&dropped),
    };
    let result = client()
        .call_attested::<_, serde_json::Value>(methods::SIGN_MESSAGE, &request)
        .await;

    assert!(
        matches!(result, Err(ClientError::Remote(failure)) if failure.kind == ModuleCallError::Unavailable)
    );
    assert!(!serialized.load(Ordering::SeqCst));
    assert!(!dropped.load(Ordering::SeqCst));
    drop(request);
    assert!(dropped.load(Ordering::SeqCst));
}

#[tokio::test]
async fn cancelling_attested_call_leaves_secret_request_with_caller_task_to_wipe() {
    let serialized = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let started = Arc::new(tokio::sync::Notify::new());
    let wallet = pending_client(Arc::clone(&started));
    let task_serialized = Arc::clone(&serialized);
    let task_dropped = Arc::clone(&dropped);
    let task = tokio::spawn(async move {
        let request = CallerOwnedSecretRequest {
            secret: "content-free-test-secret".to_owned(),
            serialized: task_serialized,
            dropped: task_dropped,
        };
        let _ = wallet
            .call_attested::<_, serde_json::Value>(methods::SIGN_MESSAGE, &request)
            .await;
    });
    started.notified().await;
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(!serialized.load(Ordering::SeqCst));
    task.abort();
    let _ = task.await;
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!serialized.load(Ordering::SeqCst));
}
