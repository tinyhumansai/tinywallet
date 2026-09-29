//! Unit tests for the transport seam.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use serde_json::{Value, json};

use super::{NetworkId, Transport, TransportError, TransportResult, decode};
use crate::chain::Chain;

/// A transport that records what it was asked for and replays canned answers.
/// Stands in for a host implementation so the seam can be exercised without a
/// network.
struct FakeTransport {
    answer: TransportResult<Value>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl FakeTransport {
    fn ok(value: Value) -> Self {
        Self {
            answer: Ok(value),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn err(error: TransportError) -> Self {
        Self {
            answer: Err(error),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn json_rpc(
        &self,
        _network: NetworkId,
        method: &str,
        params: Value,
    ) -> TransportResult<Value> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("json_rpc {method} {params}"));
        self.answer.clone()
    }

    async fn rest_get(&self, _network: NetworkId, path: &str) -> TransportResult<String> {
        self.calls.lock().unwrap().push(format!("rest_get {path}"));
        self.answer.clone().map(|v| v.to_string())
    }

    async fn rest_post(
        &self,
        _network: NetworkId,
        path: &str,
        body: String,
        content_type: &str,
    ) -> TransportResult<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("rest_post {path} {content_type} {body}"));
        self.answer.clone().map(|v| v.to_string())
    }
}

#[test]
fn network_id_names_a_non_evm_chain_by_chain_alone() {
    let id = NetworkId::chain(Chain::Solana);
    assert_eq!(id.chain, Chain::Solana);
    assert_eq!(id.evm_chain_id, None);
    assert_eq!(id.to_string(), "solana");
}

#[test]
fn network_id_distinguishes_evm_networks_by_chain_id() {
    // Ethereum and Base share an address format and an RPC dialect, so the
    // chain alone cannot say which endpoint should answer.
    let mainnet = NetworkId::evm(1);
    let base = NetworkId::evm(8453);
    assert_ne!(mainnet, base);
    assert_eq!(mainnet.chain, base.chain);
    assert_eq!(mainnet.to_string(), "evm:1");
    assert_eq!(base.to_string(), "evm:8453");
}

#[test]
fn unreachable_is_retryable_and_rpc_is_not() {
    // The whole reason these are separate variants: a failover loop advances
    // on the first and must stop dead on the second.
    let network = NetworkId::chain(Chain::Btc);
    let unreachable = TransportError::Unreachable {
        network,
        message: "connection refused".to_string(),
    };
    let authoritative = TransportError::Rpc {
        network,
        message: "insufficient funds".to_string(),
    };
    assert!(unreachable.is_retryable());
    assert!(!authoritative.is_retryable());
}

#[test]
fn errors_report_the_network_they_relate_to() {
    let network = NetworkId::evm(8453);
    let err = TransportError::Rpc {
        network,
        message: "nonce too low".to_string(),
    };
    assert_eq!(err.network(), network);
    assert!(err.to_string().contains("evm:8453"));
    assert!(err.to_string().contains("nonce too low"));
}

#[tokio::test]
async fn json_rpc_passes_the_method_and_params_through() {
    let transport = FakeTransport::ok(json!("0x1"));
    let out = transport
        .json_rpc(
            NetworkId::evm(1),
            "eth_getTransactionCount",
            json!(["0xabc", "latest"]),
        )
        .await
        .unwrap();
    assert_eq!(out, json!("0x1"));
    assert_eq!(
        transport.calls(),
        vec![r#"json_rpc eth_getTransactionCount ["0xabc","latest"]"#.to_string()]
    );
}

#[tokio::test]
async fn rest_post_carries_the_content_type() {
    // Esplora wants text/plain for a raw transaction and TronGrid wants JSON,
    // so the content type cannot be assumed by the caller.
    let transport = FakeTransport::ok(json!("txid"));
    transport
        .rest_post(
            NetworkId::chain(Chain::Btc),
            "tx",
            "0200000001".to_string(),
            "text/plain",
        )
        .await
        .unwrap();
    assert_eq!(
        transport.calls(),
        vec!["rest_post tx text/plain 0200000001".to_string()]
    );
}

#[tokio::test]
async fn a_transport_error_surfaces_to_the_caller_unchanged() {
    let network = NetworkId::chain(Chain::Solana);
    let transport = FakeTransport::err(TransportError::Rpc {
        network,
        message: "blockhash not found".to_string(),
    });
    let err = transport
        .json_rpc(network, "sendTransaction", json!([]))
        .await
        .unwrap_err();
    assert!(!err.is_retryable());
    assert!(err.to_string().contains("blockhash not found"));
}

#[test]
fn decode_turns_a_matching_result_into_a_typed_value() {
    #[derive(serde::Deserialize, PartialEq, Debug)]
    struct Balance {
        value: u64,
    }
    let out: Balance = decode(
        NetworkId::chain(Chain::Solana),
        "getBalance",
        json!({"value": 42}),
    )
    .unwrap();
    assert_eq!(out, Balance { value: 42 });
}

#[test]
fn decode_reports_a_shape_mismatch_as_authoritative_not_retryable() {
    // The endpoint answered; it just did not answer what was asked. Retrying
    // elsewhere cannot fix a schema mismatch, so this must not be Unreachable.
    #[derive(serde::Deserialize, Debug)]
    struct Balance {
        #[allow(dead_code)]
        value: u64,
    }
    let err = decode::<Balance>(
        NetworkId::chain(Chain::Solana),
        "getBalance",
        json!({"nope": true}),
    )
    .unwrap_err();
    assert!(!err.is_retryable(), "a shape mismatch is not retryable");
    assert!(err.to_string().contains("getBalance"));
}
