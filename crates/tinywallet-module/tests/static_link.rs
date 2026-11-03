//! The `static-link` build exports `linked_module()` and the host admits it
//! in-process, attesting it as host code (the executable's digest).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use sha2::{Digest, Sha256};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, ModuleState};
use tinybus::transport::memory::{MemoryBus, MemoryTransport};
use tinywallet_module::{BUS_NAME, linked_module};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn linked_module_is_admitted_and_attested_as_the_host_executable() {
    let bus = MemoryBus::new();
    let broker = Broker::new_restricted_module_control();
    let broker_task = broker.spawn(bus.clone());
    let (broker_transport, controller_transport) = MemoryTransport::pair();
    broker
        .attach_module_controller(std::sync::Arc::new(broker_transport))
        .unwrap();
    let _controller = Connection::connect(Box::new(controller_transport))
        .await
        .unwrap();
    let host = ModuleHost::new(broker);

    let module = linked_module().expect("linked manifest is valid");
    let info = host
        .attach_linked_with_config(module, serde_json::json!({}))
        .expect("linked tinywallet is admitted");
    assert_eq!(info.manifest.bus_name.as_ref() as &str, BUS_NAME);
    assert!(matches!(
        info.state,
        ModuleState::Initializing | ModuleState::Resolved
    ));

    let client = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let attestation = client
        .attestation(info.manifest.bus_name.clone())
        .await
        .unwrap()
        .expect("linked module is attested, so confidential members are deliverable");
    let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let hex = Sha256::digest(exe)
        .iter()
        .fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        });
    assert_eq!(attestation.sha256, hex);

    // The point of attestation: a secret-bearing confidential member is
    // delivered to the linked module, which an unattested one would refuse.
    let proxy = client
        .proxy(BUS_NAME, tinywallet_module::OBJECT_PATH, BUS_NAME)
        .unwrap();
    let request = serde_json::json!({
        "secret": {
            "mnemonic": "abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon about",
            "derivation_path": "m/44'/60'/0'/0/0",
            "chain": "evm",
        },
        "transaction": {
            "kind": "evm",
            "to": "0x3535353535353535353535353535353535353535",
            "value_wei": "1000000000000000000",
            "data_hex": "0x",
            "nonce": 9,
            "gas_limit": 21_000,
            "gas_price_wei": "20000000000",
            "chain_id": 1,
        },
    });
    let mut last = None;
    for _ in 0..50 {
        match proxy
            .call_confidential::<serde_json::Value>("SignTransaction", (request.clone(),))
            .await
        {
            Ok(signed) => {
                last = Some(signed);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }
    assert!(
        last.is_some(),
        "linked module must accept confidential delivery"
    );
    broker_task.abort();
}
