//! Contract decoding and missing-host behavior for module callbacks.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

#[test]
fn each_callback_response_kind_decodes_as_its_contract_type() {
    let backend: WalletBackendResponse = extract_response(
        "WalletBackend",
        HostResponse::WalletBackend(WalletBackendResponse {
            data: serde_json::json!({"routes": []}),
        }),
    )
    .unwrap();
    assert_eq!(backend.data, serde_json::json!({"routes": []}));

    let accounts: WalletAccountsResponse = extract_response(
        "WalletAccounts",
        HostResponse::WalletAccounts(WalletAccountsResponse {
            configured: true,
            accounts: Vec::new(),
        }),
    )
    .unwrap();
    assert!(accounts.configured);

    let transport: ChainTransportResult = extract_response(
        "ChainTransport",
        HostResponse::ChainTransport(ChainTransportResult::Ok {
            body: serde_json::json!("body"),
        }),
    )
    .unwrap();
    assert!(matches!(transport, ChainTransportResult::Ok { .. }));

    for expected in ["AuthorizeWeb3Execution", "AuthorizeX402Payment"] {
        let authorization: AuthorizationResult = extract_response(
            expected,
            HostResponse::Authorization(AuthorizationResult {
                approved: true,
                reason: None,
            }),
        )
        .unwrap();
        assert!(authorization.approved);
    }
}

#[test]
fn wrong_or_malformed_callback_responses_are_reported() {
    let wrong_kind = extract_response::<WalletBackendResponse>(
        "WalletBackend",
        HostResponse::Authorization(AuthorizationResult {
            approved: false,
            reason: Some("denied".to_string()),
        }),
    )
    .unwrap_err();
    assert!(wrong_kind.contains("wrong response kind"));

    let decode_error = extract_response::<String>(
        "WalletBackend",
        HostResponse::WalletBackend(WalletBackendResponse {
            data: serde_json::Value::Null,
        }),
    )
    .unwrap_err();
    assert!(decode_error.contains("decoding host callback response"));
}

#[tokio::test]
async fn missing_host_is_reported_without_fallback() {
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker = tinybus::broker::Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let callbacks = HostCallbacks::new(&connection).unwrap();
    assert!(format!("{callbacks:?}").contains("HostCallbacks"));
    let error = callbacks.wallet_accounts().await.unwrap_err();
    assert_ne!(error, "");
    broker_task.abort();
}

#[tokio::test]
async fn missing_storage_host_fails_closed_for_the_payment_ledger() {
    let bus = tinybus::transport::memory::MemoryBus::new();
    let broker = tinybus::broker::Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let connection = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let callbacks = HostCallbacks::new(&connection).unwrap();

    let error = callbacks.ledger_storage().await.unwrap_err();

    assert!(error.contains("x402 ledger storage is unavailable"));
    broker_task.abort();
}
