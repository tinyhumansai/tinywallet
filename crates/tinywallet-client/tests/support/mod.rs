//! Local native-module fixtures shared by the explicit client E2E targets.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;

use tinybus::broker::Broker;
use tinybus::module::{
    AccessFuture, CachedRelease, FailureReporter, FailureSink, ModuleAccess, ModuleCallError,
    ModuleHost, ProxyFailure, ReleaseAsset, ReleaseRecord,
};
use tinybus::transport::memory::{MemoryBus, MemoryTransport};
use tinybus::{Connection, Proxy};
use tinywallet_client::WalletClient;
use tokio::sync::OnceCell;

pub(crate) const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";
const RELEASE_URL: &str = "https://github.com/tinyhumansai/tinywallet/releases/tag/v0.25.1";

static RECORD: OnceLock<ReleaseRecord> = OnceLock::new();
static WRONG_LIBRARY_RECORD: OnceLock<ReleaseRecord> = OnceLock::new();

struct QuietSink;

impl FailureSink for QuietSink {
    fn capture(&self, _: &tinybus::module::FailureReport<'_>) {}
}

pub(crate) struct Fixture {
    pub(crate) access: Arc<Access>,
    pub(crate) wallet: WalletClient,
    pub(crate) wrong_pin_wallet: WalletClient,
    _controller: Connection,
    broker_task: tokio::task::JoinHandle<tinybus::Result<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.broker_task.abort();
    }
}

pub(crate) struct Access {
    host: Arc<ModuleHost>,
    connection: Connection,
    reporter: FailureReporter,
    loaded: Arc<OnceCell<()>>,
    record: &'static ReleaseRecord,
    release: CachedRelease<'static>,
    unattested_module: Option<PathBuf>,
}

pub(crate) struct SharedAccess(Arc<Access>);

impl Access {
    fn new(
        host: Arc<ModuleHost>,
        connection: Connection,
        loaded: Arc<OnceCell<()>>,
        record: &'static ReleaseRecord,
        release: CachedRelease<'static>,
        unattested_module: Option<PathBuf>,
    ) -> Self {
        Self {
            host,
            connection,
            reporter: FailureReporter::new(Arc::new(QuietSink)),
            loaded,
            record,
            release,
            unattested_module,
        }
    }

    pub(crate) async fn unique_peer(&self) -> tinybus::BusName {
        self.connection
            .name_owner(self.record.bus_name)
            .await
            .expect("module owner lookup")
            .expect("ready module has a unique owner")
    }

    pub(crate) async fn attestation(&self) -> tinybus::Attestation {
        self.observed_attestation()
            .await
            .expect("cached release was attested")
    }

    pub(crate) async fn observed_attestation(&self) -> Option<tinybus::Attestation> {
        self.connection
            .attestation(
                tinybus::BusName::new(self.record.bus_name).expect("valid wallet bus name"),
            )
            .await
            .expect("module attestation lookup")
    }
}

impl ModuleAccess for Access {
    fn find(&self, id: &str) -> Option<&'static ReleaseRecord> {
        (id == self.record.id).then_some(self.record)
    }

    fn enabled(&self) -> bool {
        true
    }

    fn reporter(&self) -> &FailureReporter {
        &self.reporter
    }

    fn ensure_loaded<'a>(&'a self, _: &'a str) -> AccessFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.loaded
                .get_or_try_init(|| async {
                    let loaded = if let Some(path) = &self.unattested_module {
                        self.host.load_file(path)
                    } else {
                        self.host
                            .load_github_release_cached(&self.release, serde_json::json!({}))
                    };
                    loaded.map(drop).map_err(|error| {
                        format!("the local test module could not be admitted: {error}")
                    })
                })
                .await
                .map(drop)
        })
    }

    fn prepare_attested<'a>(&'a self, id: &'a str) -> AccessFuture<'a, Result<(), String>> {
        Box::pin(async move {
            self.ensure_loaded(id).await?;
            self.host
                .ensure_ready(self.record.bus_name)
                .await
                .map_err(|_| "the test module did not reach ready".to_string())
        })
    }

    fn proxy<'a>(
        &'a self,
        bus_name: &'a str,
        object_path: &'a str,
    ) -> AccessFuture<'a, Result<Proxy, ProxyFailure>> {
        Box::pin(async move {
            self.connection
                .proxy(bus_name, object_path, bus_name)
                .map_err(|_| ProxyFailure::Contract)
        })
    }
}

impl ModuleAccess for SharedAccess {
    fn find(&self, id: &str) -> Option<&'static ReleaseRecord> {
        self.0.find(id)
    }

    fn enabled(&self) -> bool {
        self.0.enabled()
    }

    fn reporter(&self) -> &FailureReporter {
        self.0.reporter()
    }

    fn ensure_loaded<'a>(&'a self, id: &'a str) -> AccessFuture<'a, Result<(), String>> {
        self.0.ensure_loaded(id)
    }

    fn prepare_attested<'a>(&'a self, id: &'a str) -> AccessFuture<'a, Result<(), String>> {
        self.0.prepare_attested(id)
    }

    fn proxy<'a>(
        &'a self,
        bus_name: &'a str,
        object_path: &'a str,
    ) -> AccessFuture<'a, Result<Proxy, ProxyFailure>> {
        self.0.proxy(bus_name, object_path)
    }
}

pub(crate) async fn fixture() -> Fixture {
    let admitted_record = record(false);
    let release = cached_release();
    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let broker_task = broker.clone().spawn(bus.clone());
    let controller = attach_module_controller(&broker).await;
    let host = Arc::new(ModuleHost::new(broker));
    let connection = Connection::connect(bus.connect().await.expect("memory bus"))
        .await
        .expect("client connection");
    let loaded = Arc::new(OnceCell::new());
    let access = Arc::new(Access::new(
        Arc::clone(&host),
        connection.clone(),
        Arc::clone(&loaded),
        admitted_record,
        release.clone(),
        None,
    ));
    access
        .ensure_loaded(admitted_record.id)
        .await
        .expect("the pinned cached test artifact should load without network access");
    host.ensure_ready(admitted_record.bus_name)
        .await
        .expect("the pinned module should become ready");
    let wrong_access = Access::new(host, connection, loaded, record(true), release, None);
    Fixture {
        wallet: WalletClient::new(tinybus::module::ModuleClient::new(SharedAccess(
            Arc::clone(&access),
        ))),
        wrong_pin_wallet: WalletClient::new(tinybus::module::ModuleClient::new(wrong_access)),
        access,
        _controller: controller,
        broker_task,
    }
}

pub(crate) async fn unattested_fixture() -> Fixture {
    let admitted_record = record(false);
    let release = cached_release();
    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let broker_task = broker.clone().spawn(bus.clone());
    let controller = attach_module_controller(&broker).await;
    let host = Arc::new(ModuleHost::new(broker));
    let connection = Connection::connect(bus.connect().await.expect("memory bus"))
        .await
        .expect("client connection");
    let loaded = Arc::new(OnceCell::new());
    let module_path = unattested_module_path();
    let access = Arc::new(Access::new(
        Arc::clone(&host),
        connection.clone(),
        Arc::clone(&loaded),
        admitted_record,
        release.clone(),
        Some(module_path),
    ));
    access
        .ensure_loaded(admitted_record.id)
        .await
        .expect("the local unattested module should load without network access");
    host.ensure_ready(admitted_record.bus_name)
        .await
        .expect("the local module should become ready");
    let wrong_access = Access::new(host, connection, loaded, record(true), release, None);
    Fixture {
        wallet: WalletClient::new(tinybus::module::ModuleClient::new(SharedAccess(
            Arc::clone(&access),
        ))),
        wrong_pin_wallet: WalletClient::new(tinybus::module::ModuleClient::new(wrong_access)),
        access,
        _controller: controller,
        broker_task,
    }
}

async fn attach_module_controller(broker: &Broker) -> Connection {
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker
        .attach_module_controller(Arc::new(broker_transport))
        .expect("the fixture controller should be selected once");
    Connection::connect(Box::new(controller_transport))
        .await
        .expect("fixture controller should connect")
}

pub(crate) fn record(wrong_library_pin: bool) -> &'static ReleaseRecord {
    let slot = if wrong_library_pin {
        &WRONG_LIBRARY_RECORD
    } else {
        &RECORD
    };
    slot.get_or_init(|| {
        let host_key = Box::leak(
            tinybus::module::platform::host_candidates()
                .into_iter()
                .next()
                .expect("the native test host has a module platform key")
                .into_boxed_str(),
        );
        let archive = leak_env("TINYWALLET_CLIENT_TEST_ARCHIVE_NAME");
        let archive_sha256 = leak_env("TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256");
        let library_sha256 = if wrong_library_pin {
            Box::leak("f".repeat(64).into_boxed_str())
        } else {
            leak_env("TINYWALLET_CLIENT_TEST_LIBRARY_SHA256")
        };
        let assets = Box::leak(
            vec![ReleaseAsset {
                host_key,
                archive,
                sha256: archive_sha256,
                library_sha256: Some(library_sha256),
            }]
            .into_boxed_slice(),
        );
        ReleaseRecord {
            id: "tinywallet",
            bus_name: tinywallet_bus::BUS_NAME,
            object_path: tinywallet_bus::OBJECT_PATH,
            version: "0.25.1",
            release_url: RELEASE_URL,
            assets,
        }
    })
}

fn cached_release() -> CachedRelease<'static> {
    CachedRelease {
        release_url: RELEASE_URL,
        asset_name: leak_env("TINYWALLET_CLIENT_TEST_ARCHIVE_NAME"),
        expected_sha256: Some(leak_env("TINYWALLET_CLIENT_TEST_ARCHIVE_SHA256")),
        expected_library_sha256: Some(leak_env("TINYWALLET_CLIENT_TEST_LIBRARY_SHA256")),
        cache_dir: leak_path("TINYWALLET_CLIENT_TEST_CACHE"),
        allow_download: false,
    }
}

fn leak_env(name: &str) -> &'static str {
    Box::leak(
        std::env::var(name)
            .unwrap_or_else(|_| {
                panic!("{name} must point at the staged local wallet test artifact")
            })
            .into_boxed_str(),
    )
}

fn leak_path(name: &str) -> &'static Path {
    Box::leak(
        PathBuf::from(
            std::env::var(name)
                .unwrap_or_else(|_| panic!("{name} must point at the staged local wallet cache")),
        )
        .into_boxed_path(),
    )
}

pub(crate) fn unattested_module_path() -> PathBuf {
    PathBuf::from(leak_env("TINYWALLET_CLIENT_UNATTESTED_MODULE"))
}

pub(crate) fn expected_module_unavailable(error: tinywallet_client::ClientError) -> bool {
    matches!(
        error,
        tinywallet_client::ClientError::Remote(failure)
            if failure.kind == ModuleCallError::Unavailable
    )
}
