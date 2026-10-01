//! Unit tests for chain queries.
//!
//! Driven through a scripted [`Transport`], so every chain's request shape and
//! response parsing is exercised with no network. The four chains each read a
//! different field out of a differently-shaped answer, which is exactly the
//! kind of translation that rots silently.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use async_trait::async_trait;
use serde_json::{Value, json};

use super::{Error, balance};
use crate::asset::{EvmNetwork, Network, SolanaCluster};
use crate::rpc::{NetworkId, Transport, TransportError, TransportResult};

/// Records every request and replays one canned answer.
struct Scripted {
    answer: TransportResult<String>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl Scripted {
    fn json(value: &Value) -> Self {
        Self {
            answer: Ok(value.to_string()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn raw(body: &str) -> Self {
        Self {
            answer: Ok(body.to_string()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn failing(error: TransportError) -> Self {
        Self {
            answer: Err(error),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn value(&self) -> TransportResult<Value> {
        match &self.answer {
            Ok(body) => Ok(serde_json::from_str(body).unwrap_or(Value::Null)),
            Err(e) => Err(e.clone()),
        }
    }
}

#[async_trait]
impl Transport for Scripted {
    async fn json_rpc(
        &self,
        network: NetworkId,
        method: &str,
        params: Value,
    ) -> TransportResult<Value> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{network} json_rpc {method} {params}"));
        self.value()
    }

    async fn rest_get(&self, network: NetworkId, path: &str) -> TransportResult<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{network} GET {path}"));
        self.answer.clone()
    }

    async fn rest_post(
        &self,
        network: NetworkId,
        path: &str,
        body: String,
        content_type: &str,
    ) -> TransportResult<String> {
        self.calls
            .lock()
            .unwrap()
            .push(format!("{network} POST {path} [{content_type}] {body}"));
        self.answer.clone()
    }
}

const EVM_ADDR: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
const BTC_ADDR: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
const SOL_ADDR: &str = "11111111111111111111111111111111";
const TRON_ADDR: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

#[tokio::test]
async fn evm_reads_a_hex_wei_balance_at_the_latest_block() {
    let transport = Scripted::json(&json!("0xde0b6b3a7640000")); // 1e18
    let wei = balance(&transport, Network::Evm(EvmNetwork::Base), EVM_ADDR)
        .await
        .unwrap();

    assert_eq!(wei, 1_000_000_000_000_000_000);
    let call = &transport.calls()[0];
    assert!(call.contains("eth_getBalance"), "{call}");
    // `latest`, not `pending`: a pending balance can go backwards without
    // anything having failed.
    assert!(call.contains("latest"), "{call}");
    // Routed by chain id, so the host can tell Base from Ethereum.
    assert!(call.starts_with("evm:8453"), "{call}");
}

#[tokio::test]
async fn evm_accepts_a_zero_balance() {
    let transport = Scripted::json(&json!("0x0"));
    assert_eq!(
        balance(&transport, Network::Evm(EvmNetwork::Ethereum), EVM_ADDR)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn evm_rejects_a_non_hex_balance_as_malformed() {
    let transport = Scripted::json(&json!("not-hex"));
    match balance(&transport, Network::Evm(EvmNetwork::Base), EVM_ADDR)
        .await
        .unwrap_err()
    {
        Error::MalformedResponse { operation, .. } => assert_eq!(operation, "eth_getBalance"),
        other => panic!("expected MalformedResponse, got {other:?}"),
    }
}

#[tokio::test]
async fn evm_rejects_a_non_string_balance_as_malformed() {
    let transport = Scripted::json(&json!({ "wei": 1 }));
    assert!(matches!(
        balance(&transport, Network::Evm(EvmNetwork::Base), EVM_ADDR)
            .await
            .unwrap_err(),
        Error::MalformedResponse {
            operation: "eth_getBalance",
            ..
        }
    ));
}

#[tokio::test]
async fn solana_unwraps_the_context_envelope() {
    // Solana wraps results in {context, value}; reading the envelope instead
    // of `value` would yield nonsense.
    let transport = Scripted::json(&json!({ "context": { "slot": 1 }, "value": 2_500_000_000u64 }));
    let lamports = balance(
        &transport,
        Network::Solana(SolanaCluster::Mainnet),
        SOL_ADDR,
    )
    .await
    .unwrap();
    assert_eq!(lamports, 2_500_000_000);
    assert!(transport.calls()[0].contains("getBalance"));
}

#[tokio::test]
async fn btc_sums_confirmed_and_mempool_activity() {
    // Esplora reports funded/spent totals separately for chain and mempool.
    // The balance is (funded - spent) across both.
    let transport = Scripted::json(&json!({
        "chain_stats":   { "funded_txo_sum": 100_000u64, "spent_txo_sum": 40_000u64 },
        "mempool_stats": { "funded_txo_sum":  10_000u64, "spent_txo_sum":  1_000u64 },
    }));
    let sats = balance(&transport, Network::Btc, BTC_ADDR).await.unwrap();

    assert_eq!(sats, 60_000 + 9_000);
    assert_eq!(
        transport.calls(),
        vec![format!("btc GET address/{BTC_ADDR}")]
    );
}

#[tokio::test]
async fn btc_clamps_rather_than_underflowing_on_a_nonsensical_response() {
    // spent > funded should be impossible. If a broken or hostile endpoint
    // says otherwise, clamping to zero is far better than underflowing into a
    // balance near u64::MAX and showing the user a fortune.
    let transport = Scripted::json(&json!({
        "chain_stats":   { "funded_txo_sum": 1u64, "spent_txo_sum": 999u64 },
        "mempool_stats": { "funded_txo_sum": 0u64, "spent_txo_sum": 0u64 },
    }));
    assert_eq!(
        balance(&transport, Network::Btc, BTC_ADDR).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn btc_rejects_a_response_that_is_not_esplora() {
    let transport = Scripted::raw("<html>captive portal</html>");
    assert!(matches!(
        balance(&transport, Network::Btc, BTC_ADDR)
            .await
            .unwrap_err(),
        Error::MalformedResponse { .. }
    ));
}

#[tokio::test]
async fn tron_posts_the_hex_address_not_the_base58_one() {
    // TronGrid wants the 41-prefixed hex form; sending base58check silently
    // returns an empty account, which reads as a zero balance.
    let transport = Scripted::json(&json!({ "balance": 12_345_678u64 }));
    let sun = balance(&transport, Network::Tron, TRON_ADDR).await.unwrap();

    assert_eq!(sun, 12_345_678);
    let call = &transport.calls()[0];
    assert!(call.contains("wallet/getaccount"), "{call}");
    assert!(call.contains("application/json"), "{call}");
    assert!(
        call.contains(&crate::address::tron::to_hex(TRON_ADDR).unwrap()),
        "must send the hex form: {call}"
    );
    assert!(!call.contains(TRON_ADDR), "must not send base58: {call}");
}

#[tokio::test]
async fn tron_treats_an_empty_account_as_zero() {
    // Unlike the other chains, TronGrid returns `{}` for an account that has
    // never been funded rather than a balance of 0. That is not malformed.
    let transport = Scripted::json(&json!({}));
    assert_eq!(
        balance(&transport, Network::Tron, TRON_ADDR).await.unwrap(),
        0
    );
}

#[tokio::test]
async fn a_bad_address_is_rejected_before_any_request_is_made() {
    // "You typed a bad address" beats a node's inconsistent answer, and beats
    // spending a round trip to find out.
    let transport = Scripted::json(&json!("0x0"));
    let err = balance(&transport, Network::Evm(EvmNetwork::Base), "nope")
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Address(_)), "got {err:?}");
    assert!(
        transport.calls().is_empty(),
        "no request should have been sent: {:?}",
        transport.calls()
    );
}

#[tokio::test]
async fn an_address_from_the_wrong_chain_is_rejected() {
    let transport = Scripted::json(&json!("0x0"));
    for (network, wrong) in [
        (Network::Evm(EvmNetwork::Base), SOL_ADDR),
        (Network::Btc, EVM_ADDR),
        (Network::Tron, BTC_ADDR),
    ] {
        let err = balance(&transport, network, wrong).await.unwrap_err();
        assert!(matches!(err, Error::Address(_)), "{network}: {err:?}");
    }
    assert!(transport.calls().is_empty());
}

#[tokio::test]
async fn a_transport_failure_surfaces_with_its_retryability_intact() {
    // The client must not flatten the distinction the seam draws — a host's
    // failover logic depends on it.
    let network = NetworkId::evm(8453);
    let transport = Scripted::failing(TransportError::Unreachable {
        network,
        message: "connection refused".to_string(),
    });
    match balance(&transport, Network::Evm(EvmNetwork::Base), EVM_ADDR)
        .await
        .unwrap_err()
    {
        Error::Transport(e) => assert!(e.is_retryable()),
        other => panic!("expected Transport, got {other:?}"),
    }

    let transport = Scripted::failing(TransportError::Rpc {
        network,
        message: "method not found".to_string(),
    });
    match balance(&transport, Network::Evm(EvmNetwork::Base), EVM_ADDR)
        .await
        .unwrap_err()
    {
        Error::Transport(e) => assert!(!e.is_retryable()),
        other => panic!("expected Transport, got {other:?}"),
    }
}

#[tokio::test]
async fn every_chain_issues_exactly_one_request_for_a_balance() {
    for (network, address, body) in [
        (Network::Evm(EvmNetwork::Ethereum), EVM_ADDR, json!("0x1")),
        (
            Network::Solana(SolanaCluster::Devnet),
            SOL_ADDR,
            json!({"value": 1u64}),
        ),
        (Network::Tron, TRON_ADDR, json!({"balance": 1u64})),
        (
            Network::Btc,
            BTC_ADDR,
            json!({
                "chain_stats":   {"funded_txo_sum": 1u64, "spent_txo_sum": 0u64},
                "mempool_stats": {"funded_txo_sum": 0u64, "spent_txo_sum": 0u64},
            }),
        ),
    ] {
        let transport = Scripted::json(&body);
        let out = balance(&transport, network, address).await.unwrap();
        assert_eq!(out, 1, "{network} balance");
        assert_eq!(transport.calls().len(), 1, "{network} request count");
    }
}

/// Answers each JSON-RPC method from a table, so the multi-call send path can
/// be driven end to end.
struct Sequenced {
    answers: std::collections::HashMap<String, Value>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl Sequenced {
    fn new(pairs: &[(&str, Value)]) -> Self {
        Self {
            answers: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn methods(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
}

#[async_trait]
impl Transport for Sequenced {
    async fn json_rpc(
        &self,
        network: NetworkId,
        method: &str,
        _params: Value,
    ) -> TransportResult<Value> {
        self.calls.lock().unwrap().push(method.to_string());
        self.answers
            .get(method)
            .cloned()
            .ok_or_else(|| TransportError::Rpc {
                network,
                message: format!("unscripted method {method}"),
            })
    }

    async fn rest_get(&self, network: NetworkId, _path: &str) -> TransportResult<String> {
        Err(TransportError::Rpc {
            network,
            message: "unused".to_string(),
        })
    }

    async fn rest_post(
        &self,
        network: NetworkId,
        _path: &str,
        _body: String,
        _content_type: &str,
    ) -> TransportResult<String> {
        Err(TransportError::Rpc {
            network,
            message: "unused".to_string(),
        })
    }
}

const SEND_KEY: [u8; 32] = [0x46; 32];
const TX_HASH: &str = "0xabc123";

fn base_send_script() -> Vec<(&'static str, Value)> {
    vec![
        ("eth_chainId", json!("0x2105")), // 8453 = Base
        ("eth_getTransactionCount", json!("0x9")),
        ("eth_gasPrice", json!("0x4a817c800")),
        ("eth_estimateGas", json!("0x5208")),
        ("eth_sendRawTransaction", json!(TX_HASH)),
    ]
}

#[tokio::test]
async fn send_evm_broadcasts_and_returns_the_hash() {
    let transport = Sequenced::new(&base_send_script());
    let hash = super::send_evm(
        &transport,
        EvmNetwork::Base,
        EVM_ADDR,
        EVM_ADDR,
        1_000,
        Vec::new(),
        &SEND_KEY,
    )
    .await
    .unwrap();

    assert_eq!(hash, TX_HASH);
    assert!(
        transport
            .methods()
            .contains(&"eth_sendRawTransaction".to_string())
    );
}

#[tokio::test]
async fn send_evm_verifies_the_chain_id_before_signing_anything() {
    // The dangerous case: an endpoint config pointing at the wrong network
    // would otherwise yield a perfectly valid transaction for a chain the user
    // never chose. It must fail, and it must fail before broadcasting.
    let mut script = base_send_script();
    script[0] = ("eth_chainId", json!("0x1")); // Ethereum, not Base
    let transport = Sequenced::new(&script);

    let err = super::send_evm(
        &transport,
        EvmNetwork::Base,
        EVM_ADDR,
        EVM_ADDR,
        1_000,
        Vec::new(),
        &SEND_KEY,
    )
    .await
    .unwrap_err();

    match err {
        Error::ChainIdMismatch {
            expected, reported, ..
        } => {
            assert_eq!(expected, 8453);
            assert_eq!(reported, 1);
        }
        other => panic!("expected ChainIdMismatch, got {other:?}"),
    }
    assert!(
        !transport
            .methods()
            .contains(&"eth_sendRawTransaction".to_string()),
        "must not broadcast after a chain id mismatch"
    );
}

#[tokio::test]
async fn send_evm_reads_the_nonce_at_pending_not_latest() {
    // A balance is read at `latest` because pending transactions can be
    // dropped. A nonce is the opposite: at `latest`, two transfers in quick
    // succession share a nonce and the second replaces the first.
    struct Capturing(std::sync::Mutex<Vec<String>>);

    #[async_trait]
    impl Transport for Capturing {
        async fn json_rpc(
            &self,
            _network: NetworkId,
            method: &str,
            params: Value,
        ) -> TransportResult<Value> {
            self.0.lock().unwrap().push(format!("{method} {params}"));
            Ok(match method {
                "eth_chainId" => json!("0x2105"),
                "eth_getTransactionCount" => json!("0x9"),
                "eth_gasPrice" => json!("0x4a817c800"),
                "eth_estimateGas" => json!("0x5208"),
                _ => json!(TX_HASH),
            })
        }
        async fn rest_get(&self, _n: NetworkId, _p: &str) -> TransportResult<String> {
            unreachable!()
        }
        async fn rest_post(
            &self,
            _n: NetworkId,
            _p: &str,
            _b: String,
            _c: &str,
        ) -> TransportResult<String> {
            unreachable!()
        }
    }

    let transport = Capturing(std::sync::Mutex::new(Vec::new()));
    super::send_evm(
        &transport,
        EvmNetwork::Base,
        EVM_ADDR,
        EVM_ADDR,
        1,
        Vec::new(),
        &SEND_KEY,
    )
    .await
    .unwrap();

    let nonce_call = transport
        .0
        .lock()
        .unwrap()
        .iter()
        .find(|c| c.starts_with("eth_getTransactionCount"))
        .cloned()
        .expect("nonce was fetched");
    assert!(nonce_call.contains("pending"), "{nonce_call}");
}

#[tokio::test]
async fn send_evm_rejects_a_bad_address_before_any_request() {
    let transport = Sequenced::new(&base_send_script());
    assert!(matches!(
        super::send_evm(
            &transport,
            EvmNetwork::Base,
            "nope",
            EVM_ADDR,
            1,
            Vec::new(),
            &SEND_KEY
        )
        .await
        .unwrap_err(),
        Error::Address(_)
    ));
    assert!(transport.methods().is_empty());
}

#[tokio::test]
async fn send_evm_surfaces_a_broadcast_rejection_as_non_retryable() {
    // "nonce too low" is the node's real answer. Retrying it elsewhere would
    // get the same answer — and risk a double broadcast.
    let mut script = base_send_script();
    script.pop();
    let transport = Sequenced::new(&script);

    match super::send_evm(
        &transport,
        EvmNetwork::Base,
        EVM_ADDR,
        EVM_ADDR,
        1,
        Vec::new(),
        &SEND_KEY,
    )
    .await
    .unwrap_err()
    {
        Error::Transport(e) => assert!(!e.is_retryable()),
        other => panic!("expected Transport, got {other:?}"),
    }
}

#[tokio::test]
async fn send_evm_includes_calldata_and_rejects_a_non_string_hash() {
    struct Capturing(std::sync::Mutex<Vec<(String, Value)>>);

    #[async_trait]
    impl Transport for Capturing {
        async fn json_rpc(
            &self,
            _network: NetworkId,
            method: &str,
            params: Value,
        ) -> TransportResult<Value> {
            self.0.lock().unwrap().push((method.to_string(), params));
            Ok(match method {
                "eth_chainId" => json!("0x2105"),
                "eth_getTransactionCount" => json!("0x9"),
                "eth_gasPrice" => json!("0x1"),
                "eth_estimateGas" => json!("0x5208"),
                "eth_sendRawTransaction" => json!(42),
                _ => unreachable!(),
            })
        }
        async fn rest_get(&self, _n: NetworkId, _p: &str) -> TransportResult<String> {
            unreachable!()
        }
        async fn rest_post(
            &self,
            _n: NetworkId,
            _p: &str,
            _b: String,
            _c: &str,
        ) -> TransportResult<String> {
            unreachable!()
        }
    }

    let transport = Capturing(std::sync::Mutex::new(Vec::new()));
    assert!(matches!(
        super::send_evm(
            &transport,
            EvmNetwork::Base,
            EVM_ADDR,
            EVM_ADDR,
            1,
            vec![0xde, 0xad],
            &SEND_KEY,
        )
        .await
        .unwrap_err(),
        Error::MalformedResponse {
            operation: "eth_sendRawTransaction",
            ..
        }
    ));
    let calls = transport.0.lock().unwrap();
    let (_, estimate) = calls
        .iter()
        .find(|(method, _)| method == "eth_estimateGas")
        .expect("gas estimate was requested");
    assert_eq!(estimate[0]["data"], "0xdead");
}

#[tokio::test]
async fn send_solana_fetches_a_blockhash_then_broadcasts_base64() {
    let transport = Sequenced::new(&[
        (
            "getLatestBlockhash",
            json!({ "value": { "blockhash": "11111111111111111111111111111111" } }),
        ),
        ("sendTransaction", json!("5xSig")),
    ]);

    let key = crate::key::derive(
        crate::Chain::Solana,
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about",
        "m/44'/501'/0'/0'",
    )
    .unwrap();

    let sig = super::send_solana(
        &transport,
        SolanaCluster::Mainnet,
        key.address(),
        SOL_ADDR,
        1_000,
        key.secret_bytes(),
    )
    .await
    .unwrap();

    assert_eq!(sig, "5xSig");
    let methods = transport.methods();
    assert_eq!(
        methods,
        vec![
            "getLatestBlockhash".to_string(),
            "sendTransaction".to_string()
        ],
        "the blockhash must be fetched immediately before signing"
    );
}

#[tokio::test]
async fn send_solana_rejects_a_key_that_does_not_control_the_sender() {
    let transport = Sequenced::new(&[(
        "getLatestBlockhash",
        json!({ "value": { "blockhash": "11111111111111111111111111111111" } }),
    )]);

    let err = super::send_solana(
        &transport,
        SolanaCluster::Mainnet,
        SOL_ADDR,
        SOL_ADDR,
        1,
        &[7u8; 32],
    )
    .await
    .unwrap_err();

    assert!(matches!(err, Error::Tx(_)), "got {err:?}");
    assert!(
        !transport.methods().contains(&"sendTransaction".to_string()),
        "must not broadcast a transaction it could not sign correctly"
    );
}

#[tokio::test]
async fn send_solana_rejects_malformed_blockhash_and_signature_responses() {
    let missing_blockhash = Sequenced::new(&[("getLatestBlockhash", json!({}))]);
    assert!(matches!(
        super::send_solana(
            &missing_blockhash,
            SolanaCluster::Mainnet,
            SOL_ADDR,
            SOL_ADDR,
            1,
            &[7u8; 32],
        )
        .await
        .unwrap_err(),
        Error::MalformedResponse {
            operation: "getLatestBlockhash",
            ..
        }
    ));

    let key = crate::key::derive(
        crate::Chain::Solana,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "m/44'/501'/0'/0'",
    )
    .unwrap();
    let invalid_signature = Sequenced::new(&[
        (
            "getLatestBlockhash",
            json!({ "value": { "blockhash": "11111111111111111111111111111111" } }),
        ),
        ("sendTransaction", json!({ "signature": "not-a-string" })),
    ]);
    assert!(matches!(
        super::send_solana(
            &invalid_signature,
            SolanaCluster::Mainnet,
            key.address(),
            SOL_ADDR,
            1,
            key.secret_bytes(),
        )
        .await
        .unwrap_err(),
        Error::MalformedResponse {
            operation: "sendTransaction",
            ..
        }
    ));
}

/// Answers REST calls from a path-keyed table.
struct RestScript {
    answers: std::collections::HashMap<String, String>,
    calls: std::sync::Mutex<Vec<String>>,
}

impl RestScript {
    fn new(pairs: &[(&str, String)]) -> Self {
        Self {
            answers: pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn paths(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }
    fn answer(&self, network: NetworkId, path: &str) -> TransportResult<String> {
        self.calls.lock().unwrap().push(path.to_string());
        self.answers
            .get(path)
            .cloned()
            .ok_or_else(|| TransportError::Rpc {
                network,
                message: format!("unscripted path {path}"),
            })
    }
}

#[async_trait]
impl Transport for RestScript {
    async fn json_rpc(
        &self,
        network: NetworkId,
        method: &str,
        _p: Value,
    ) -> TransportResult<Value> {
        Err(TransportError::Rpc {
            network,
            message: format!("unexpected json_rpc {method}"),
        })
    }
    async fn rest_get(&self, network: NetworkId, path: &str) -> TransportResult<String> {
        self.answer(network, path)
    }
    async fn rest_post(
        &self,
        network: NetworkId,
        path: &str,
        _b: String,
        _c: &str,
    ) -> TransportResult<String> {
        self.answer(network, path)
    }
}

fn btc_key() -> crate::key::DerivedKey {
    crate::key::derive(
        crate::Chain::Btc,
        "abandon abandon abandon abandon abandon abandon \
         abandon abandon abandon abandon abandon about",
        "m/84'/0'/0'/0/0",
    )
    .unwrap()
}

#[tokio::test]
async fn send_btc_fetches_utxos_then_broadcasts_raw_hex() {
    let key = btc_key();
    let utxo_body = json!([{
        "txid": "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605",
        "vout": 0,
        "value": 100_000u64,
    }])
    .to_string();
    let transport = RestScript::new(&[
        (&format!("address/{}/utxo", key.address()), utxo_body),
        ("tx", "thetxid\n".to_string()),
    ]);

    let txid = super::send_btc(
        &transport,
        key.address(),
        BTC_ADDR,
        50_000,
        1_000,
        key.secret_bytes(),
    )
    .await
    .unwrap();

    assert_eq!(txid, "thetxid", "the txid is trimmed");
    let paths = transport.paths();
    assert!(paths[0].ends_with("/utxo"), "UTXOs first: {paths:?}");
    assert_eq!(paths[1], "tx", "then broadcast");
}

#[tokio::test]
async fn send_btc_surfaces_insufficient_funds_without_broadcasting() {
    let key = btc_key();
    let transport = RestScript::new(&[(
        &format!("address/{}/utxo", key.address()),
        json!([{
            "txid": "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605",
            "vout": 0,
            "value": 100u64,
        }])
        .to_string(),
    )]);

    let err = super::send_btc(
        &transport,
        key.address(),
        BTC_ADDR,
        50_000,
        1_000,
        key.secret_bytes(),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, Error::Tx(_)), "got {err:?}");
    assert!(
        !transport.paths().contains(&"tx".to_string()),
        "must not broadcast an unfundable transfer"
    );
}

#[tokio::test]
async fn send_tron_verifies_the_node_built_transaction_before_signing() {
    // A node that returns a transaction paying someone else must not get a
    // signature — the whole reason Tron verifies before signing.
    let to_hex = crate::address::tron::to_hex(TRON_ADDR).unwrap();
    let raw = format!("0a02b1f42208{to_hex}5a01");
    let txid = crate::tx::tron::recompute_txid(&raw).unwrap();

    let elsewhere = "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH";
    let transport = RestScript::new(&[(
        "wallet/createtransaction",
        json!({ "raw_data_hex": raw, "txID": txid }).to_string(),
    )]);

    let err = super::send_tron(&transport, TRON_ADDR, elsewhere, 1, &[0x46; 32])
        .await
        .unwrap_err();

    assert!(matches!(err, Error::Tx(_)), "got {err:?}");
    assert!(
        !transport
            .paths()
            .contains(&"wallet/broadcasttransaction".to_string()),
        "must not broadcast a transaction it could not verify"
    );
}

#[tokio::test]
async fn send_tron_treats_a_result_false_body_as_a_rejection() {
    // TronGrid answers HTTP 200 with {"result": false} on a rejection, so a
    // successful status is not a successful broadcast.
    let to_hex = crate::address::tron::to_hex(TRON_ADDR).unwrap();
    let raw = format!("0a02b1f42208{to_hex}5a01");
    let txid = crate::tx::tron::recompute_txid(&raw).unwrap();

    let transport = RestScript::new(&[
        (
            "wallet/createtransaction",
            json!({ "raw_data_hex": raw, "txID": txid }).to_string(),
        ),
        (
            "wallet/broadcasttransaction",
            json!({ "result": false, "message": "SIGERROR" }).to_string(),
        ),
    ]);

    let err = super::send_tron(&transport, TRON_ADDR, TRON_ADDR, 1, &[0x46; 32])
        .await
        .unwrap_err();
    match err {
        Error::Transport(e) => assert!(e.to_string().contains("rejected")),
        other => panic!("expected Transport, got {other:?}"),
    }
}

#[tokio::test]
async fn tron_rejects_malformed_account_and_transaction_responses() {
    let malformed_account = Scripted::raw("not json");
    assert!(matches!(
        balance(&malformed_account, Network::Tron, TRON_ADDR)
            .await
            .unwrap_err(),
        Error::MalformedResponse {
            operation: "wallet/getaccount",
            ..
        }
    ));

    let missing_transaction = RestScript::new(&[(
        "wallet/createtransaction",
        json!({ "txID": "abc" }).to_string(),
    )]);
    assert!(matches!(
        super::send_tron(&missing_transaction, TRON_ADDR, TRON_ADDR, 1, &SEND_KEY)
            .await
            .unwrap_err(),
        Error::MalformedResponse {
            operation: "wallet/createtransaction",
            ..
        }
    ));
}

#[tokio::test]
async fn send_tron_returns_the_txid_after_a_successful_broadcast() {
    let to_hex = crate::address::tron::to_hex(TRON_ADDR).unwrap();
    let raw = format!("0a02b1f42208{to_hex}5a01");
    let txid = crate::tx::tron::recompute_txid(&raw).unwrap();
    let transport = RestScript::new(&[
        (
            "wallet/createtransaction",
            json!({ "raw_data_hex": raw, "txID": txid }).to_string(),
        ),
        (
            "wallet/broadcasttransaction",
            json!({ "result": true }).to_string(),
        ),
    ]);

    assert_eq!(
        super::send_tron(&transport, TRON_ADDR, TRON_ADDR, 1, &SEND_KEY)
            .await
            .unwrap(),
        txid
    );
}

#[tokio::test]
async fn send_tron_rejects_missing_txid_and_a_malformed_broadcast_body() {
    let to_hex = crate::address::tron::to_hex(TRON_ADDR).unwrap();
    let raw = format!("0a02b1f42208{to_hex}5a01");
    let txid = crate::tx::tron::recompute_txid(&raw).unwrap();

    let missing_txid = RestScript::new(&[(
        "wallet/createtransaction",
        json!({ "raw_data_hex": raw }).to_string(),
    )]);
    assert!(matches!(
        super::send_tron(&missing_txid, TRON_ADDR, TRON_ADDR, 1, &SEND_KEY)
            .await
            .unwrap_err(),
        Error::MalformedResponse {
            operation: "wallet/createtransaction",
            ..
        }
    ));

    let malformed_broadcast = RestScript::new(&[
        (
            "wallet/createtransaction",
            json!({ "raw_data_hex": raw, "txID": txid }).to_string(),
        ),
        ("wallet/broadcasttransaction", "not json".to_string()),
    ]);
    assert!(matches!(
        super::send_tron(&malformed_broadcast, TRON_ADDR, TRON_ADDR, 1, &SEND_KEY)
            .await
            .unwrap_err(),
        Error::MalformedResponse {
            operation: "wallet/broadcasttransaction",
            ..
        }
    ));
}

#[tokio::test]
async fn evm_status_maps_receipt_status_to_confirmed_or_failed() {
    // A reverted transaction still has a receipt and still spent its fee, so
    // it is a terminal state rather than an error.
    for (status, expected) in [
        (json!("0x1"), super::TxState::Confirmed),
        (json!("0x0"), super::TxState::Failed),
    ] {
        let transport = Sequenced::new(&[(
            "eth_getTransactionReceipt",
            json!({ "status": status, "blockNumber": "0x10" }),
        )]);
        let out = super::status(&transport, Network::Evm(EvmNetwork::Base), "0xabc")
            .await
            .unwrap();
        assert_eq!(out.state, expected);
        assert_eq!(out.block, Some(16));
    }
}

#[tokio::test]
async fn a_transaction_the_network_has_not_seen_is_pending_everywhere() {
    // No chain here can distinguish "never broadcast" from "not yet mined",
    // so absence must report Pending rather than an error or a failure.
    let evm = Sequenced::new(&[("eth_getTransactionReceipt", Value::Null)]);
    assert_eq!(
        super::status(&evm, Network::Evm(EvmNetwork::Base), "0xabc")
            .await
            .unwrap()
            .state,
        super::TxState::Pending
    );

    let sol = Sequenced::new(&[("getSignatureStatuses", json!({ "value": [null] }))]);
    assert_eq!(
        super::status(&sol, Network::Solana(SolanaCluster::Mainnet), "sig")
            .await
            .unwrap()
            .state,
        super::TxState::Pending
    );

    let btc = RestScript::new(&[("tx/abc/status", json!({ "confirmed": false }).to_string())]);
    assert_eq!(
        super::status(&btc, Network::Btc, "abc")
            .await
            .unwrap()
            .state,
        super::TxState::Pending
    );

    // TronGrid returns `{}` for an unknown transaction, not an error.
    let tron = RestScript::new(&[("wallet/gettransactioninfobyid", "{}".to_string())]);
    assert_eq!(
        super::status(&tron, Network::Tron, "abc")
            .await
            .unwrap()
            .state,
        super::TxState::Pending
    );
}

#[tokio::test]
async fn solana_status_reads_err_presence_not_its_shape() {
    let ok = Sequenced::new(&[(
        "getSignatureStatuses",
        json!({ "value": [{ "err": null, "slot": 99u64, "confirmations": 3u64 }] }),
    )]);
    let out = super::status(&ok, Network::Solana(SolanaCluster::Mainnet), "sig")
        .await
        .unwrap();
    assert_eq!(out.state, super::TxState::Confirmed);
    assert_eq!(out.confirmations, Some(3));
    assert_eq!(out.block, Some(99));

    let failed = Sequenced::new(&[(
        "getSignatureStatuses",
        json!({ "value": [{ "err": { "InstructionError": [0, "Custom"] }, "slot": 99u64 }] }),
    )]);
    assert_eq!(
        super::status(&failed, Network::Solana(SolanaCluster::Mainnet), "sig")
            .await
            .unwrap()
            .state,
        super::TxState::Failed
    );
}

#[tokio::test]
async fn btc_status_has_no_failed_state() {
    // Bitcoin transactions are in a block or not; there is nothing to map
    // onto Failed.
    let transport = RestScript::new(&[(
        "tx/abc/status",
        json!({ "confirmed": true, "block_height": 800_000u64 }).to_string(),
    )]);
    let out = super::status(&transport, Network::Btc, "abc")
        .await
        .unwrap();
    assert_eq!(out.state, super::TxState::Confirmed);
    assert_eq!(out.block, Some(800_000));
}

#[tokio::test]
async fn tron_status_treats_a_missing_receipt_result_as_success() {
    // TronGrid only populates `receipt.result` for contract calls, so a mined
    // native transfer has none — reading that as a failure would report every
    // successful TRX transfer as failed.
    let transport = RestScript::new(&[(
        "wallet/gettransactioninfobyid",
        json!({ "blockNumber": 55u64 }).to_string(),
    )]);
    let out = super::status(&transport, Network::Tron, "abc")
        .await
        .unwrap();
    assert_eq!(out.state, super::TxState::Confirmed);
    assert_eq!(out.block, Some(55));

    let reverted = RestScript::new(&[(
        "wallet/gettransactioninfobyid",
        json!({ "blockNumber": 55u64, "receipt": { "result": "REVERT" } }).to_string(),
    )]);
    assert_eq!(
        super::status(&reverted, Network::Tron, "abc")
            .await
            .unwrap()
            .state,
        super::TxState::Failed
    );
}
