//! End-to-end test for loading the built `TinyWallet` module into `TinyBus`.
//!
//! One of the native tests that exercises the real thing: the built `cdylib`,
//! the ABI descriptor, manifest admission, the dynamic loader, and a broker
//! routing actual frames. The signing round-trip is in `module_e2e.rs`.
//!
//! What it proves that a unit test cannot: a transaction signed *through the
//! loaded module* is byte-for-byte the transaction the library produces signing
//! in one step. That is the whole claim of moving signing out of a host — if it
//! were false, the host would broadcast something other than what it built.
//!
//! It also demonstrates the intended custody boundary: key material crosses
//! only on `TinyBus` confidential members into an attested module. Ordinary
//! account, quote, approval, and transport callbacks never carry secrets.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use std::{
    fs,
    path::{Path, PathBuf},
};

use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tinybus::Connection;
use tinybus::broker::Broker;
use tinybus::module::{ModuleHost, ModuleState};
use tinybus::transport::memory::MemoryBus;
use tinywallet::wire::{
    AttachRequest, PublicKey, Scheme, Signature, SignedTransaction, SigningRequest,
    TransactionSpec, UnsignedTransaction,
};
use tinywallet::{Chain, tx};
use tinywallet_bus::wire::{
    AuthorizationResult, AuthorizeNativeWalletExecutionRequest, AuthorizeX402PaymentRequest,
    ChainTransportRequest, ChainTransportResult, DerivedAccount, HostResponse,
    NativeWalletConfigRequest, NativeWalletConfigResponse, NativeWalletExecuteRequest,
    NativeWalletPrepareTransferRequest, NativeWalletServiceHandle, NetworkRequest,
    PrepareTransferParams, RpcEndpointKey, SecretMaterial, SolanaCluster, WalletAccountsResponse,
    WalletBackendRequest, WalletBackendResponse, WalletChain, Web3CloseRequest, Web3ServiceHandle,
    X402ConfigResponse, X402ConfigureRequest, X402ServiceHandle,
};
use tinywallet_module::{BUS_NAME, HOST_INTERFACE, HOST_OBJECT_PATH, OBJECT_PATH};

// Public Solana mint-shaped address used only by the mocked token fixture; not a credential.
const SOLANA_FIXTURE_MINT: &str = "EPjFWdd5AufqSSqeM2qWw89b7aQf1nZ5V9u7vG3Gf6D";

/// Every method the manifest must declare, in order.
///
/// The manifest's own list is hand-written in `module_export!`, so this is a
/// second hand-written list checked against it. That catches a manifest edited
/// without the interface, which is the failure that actually happens — a method
/// absent from the manifest is not advertised to a host at all.
const EXPECTED_METHODS: &[&str] = &[
    "BuildUnsigned",
    "AttachSignature",
    "DeriveAccount",
    "DeriveMnemonicSeed",
    "EncodeErc20Transfer",
    "GenerateMnemonic",
    "SignTransaction",
    "ExportKey",
    "SignMessage",
    "ValidateAddress",
    "ConstructEvmTransaction",
    "Web3Routes",
    "Web3SwapQuote",
    "Web3BridgeQuote",
    "Web3DappQuote",
    "Web3Execute",
    "Web3Configure",
    "Web3ConfigureWithEndpoints",
    "Web3Close",
    "NativeWalletConfigure",
    "NativeWalletClose",
    "NativeWalletNetworkDefaults",
    "NativeWalletSupportedAssets",
    "NativeWalletChainStatus",
    "NativeWalletBalances",
    "NativeWalletPrepareTransfer",
    "NativeWalletExecutePrepared",
    "NativeWalletTxStatus",
    "NativeWalletTxReceipt",
    "NativeWalletLookupTx",
    "X402PreparePayment",
    "X402RecordPayment",
    "X402SpendingSummary",
    "X402SpendingSummaryDetailed",
    "X402ListPayments",
    "X402UpdateBudget",
    "X402Configure",
    "X402Close",
];

/// The BIP-39 test vector mnemonic. Never use it for real funds.
const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                      abandon abandon abandon abandon abandon about";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires TINYWALLET_TEST_MODULE to point at the built cdylib"]
#[expect(
    clippy::too_many_lines,
    reason = "one artifact load is required because TinyBus does not unload modules"
)]
async fn the_built_module_signs_every_chain_over_a_real_broker() {
    // One test rather than four: TinyBus never unloads a module, and a second
    // load of the same artifact would collide on the well-known name, so every
    // chain is exercised against the one admitted instance.
    let (
        client,
        _host,
        host_bad_response,
        approved_web3,
        approved_native,
        native_transport_networks,
        submitted_tx,
        _,
        _,
        _,
        modules,
        broker_task,
        staged,
    ) = admit_module().await;
    wait_until_serving(&client).await;

    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME).unwrap();
    let x402_configured = proxy
        .call::<X402ServiceHandle>(
            "X402Configure",
            (X402ConfigureRequest {
                config: X402ConfigResponse {
                    workspace_dir: staged.path().join("workspace").display().to_string(),
                    session_id: "module-e2e".to_string(),
                    per_request_max_atomic: 1_000_000,
                    daily_max_atomic: 10_000_000,
                    monthly_max_atomic: 100_000_000,
                },
            },),
        )
        .await;
    // This fixture has no storage host, so x402 must fail closed instead of
    // silently switching to process-local state.
    let error = x402_configured.expect_err("unprovisioned storage must fail x402 closed");
    assert!(
        error.to_string().contains("X402OperationFailed"),
        "an unprovisioned artifact must fail x402 closed: {error}"
    );
    let mut web3_service: Web3ServiceHandle = proxy.call("Web3Configure", ((),)).await.unwrap();

    // The new native engine crosses the compiled module ABI, not a copied host
    // implementation: endpoint metadata stays opaque and signing approval
    // receives the exact transaction built inside the loaded artifact.
    let native: NativeWalletConfigResponse = proxy
        .call(
            "NativeWalletConfigure",
            (NativeWalletConfigRequest {
                solana_cluster: SolanaCluster::Mainnet,
                overridden_endpoints: vec![RpcEndpointKey::Btc],
            },),
        )
        .await
        .unwrap();
    let btc_defaults: Vec<tinywallet_bus::wire::WalletNetworkDefaults> = proxy
        .call(
            "NativeWalletNetworkDefaults",
            (tinywallet_bus::wire::NativeWalletServiceRequest {
                service: native.service.clone(),
            },),
        )
        .await
        .unwrap();
    let btc_default = btc_defaults
        .iter()
        .find(|row| row.chain == WalletChain::Btc)
        .unwrap();
    assert_eq!(btc_default.rpc_url, native.endpoint_references[0].reference);
    assert!(!btc_default.rpc_url.starts_with("http"));
    let _ = proxy
        .call::<serde_json::Value>(
            "NativeWalletTxStatus",
            (tinywallet_bus::wire::NativeWalletTransactionRequest {
                service: native.service.clone(),
                chain: WalletChain::Btc,
                evm_network: None,
                hash: "fixture-tx".to_string(),
            },),
        )
        .await;
    assert!(
        native_transport_networks
            .lock()
            .unwrap()
            .iter()
            .any(|network| {
                network.chain == Chain::Btc
                    && network.endpoint_ref.as_deref() == Some(btc_default.rpc_url.as_str())
            })
    );
    let _ = proxy
        .call::<serde_json::Value>(
            "NativeWalletTxStatus",
            (tinywallet_bus::wire::NativeWalletTransactionRequest {
                service: native.service.clone(),
                chain: WalletChain::Evm,
                evm_network: Some(tinywallet_bus::wire::EvmNetwork::EthereumMainnet),
                hash: "0xfixture-default-endpoint".to_string(),
            },),
        )
        .await;
    assert!(
        native_transport_networks
            .lock()
            .unwrap()
            .iter()
            .any(|network| {
                network.chain == Chain::Evm
                    && network.evm_chain_id == Some(1)
                    && network.endpoint_ref.is_none()
                    && network.endpoint_url.as_deref()
                        == Some("https://ethereum-rpc.publicnode.com")
            }),
        "default endpoint choice must cross the compiled module ABI"
    );
    let native_quote: tinywallet_bus::wire::PreparedTransaction = proxy
        .call(
            "NativeWalletPrepareTransfer",
            (NativeWalletPrepareTransferRequest {
                service: native.service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "native-artifact-thread".to_string(),
                    client_id: "native-artifact-client".to_string(),
                }),
                params: PrepareTransferParams {
                    chain: WalletChain::Evm,
                    to_address: "0x3535353535353535353535353535353535353535".to_string(),
                    amount_raw: "1000".to_string(),
                    asset_symbol: None,
                    evm_network: None,
                },
            },),
        )
        .await
        .unwrap();
    let native_execution: tinywallet_bus::wire::ExecutionResult = proxy
        .call_confidential(
            "NativeWalletExecutePrepared",
            (NativeWalletExecuteRequest {
                service: native.service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "native-artifact-thread".to_string(),
                    client_id: "native-artifact-client".to_string(),
                }),
                quote_id: native_quote.quote_id.clone(),
                confirmed: true,
                secret: SecretMaterial {
                    mnemonic: VECTOR.to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                    chain: Chain::Evm,
                },
            },),
        )
        .await
        .unwrap();
    assert_eq!(native_execution.transaction_hash, "0xfeedface");
    {
        let native_approval = approved_native.lock().unwrap();
        assert_eq!(native_approval.as_ref().unwrap().quote, native_quote);
        assert!(matches!(
            &native_approval.as_ref().unwrap().intent,
            tinywallet_bus::wire::NativeWalletExecutionIntent::Transaction {
                transaction: TransactionSpec::Evm { chain_id: 1, .. }
            }
        ));
    }
    proxy
        .call::<()>(
            "NativeWalletClose",
            (tinywallet_bus::wire::NativeWalletCloseRequest {
                service: NativeWalletServiceHandle {
                    handle: native.service.handle,
                },
            },),
        )
        .await
        .unwrap();

    let routes: serde_json::Value = proxy.call("Web3Routes", ((),)).await.unwrap();
    assert_eq!(routes, serde_json::json!({"routes": ["evm", "solana"]}));
    let quote: serde_json::Value = proxy
        .call(
            "Web3SwapQuote",
            (tinywallet_bus::wire::Web3QuoteRequest {
                service: web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "thread-1".to_string(),
                    client_id: "client-1".to_string(),
                }),
                params: serde_json::json!({
                    "chainId": 1,
                    "tokenIn": "0x0000000000000000000000000000000000000000",
                    "tokenInAmount": "100",
                    "tokenOut": "0x0000000000000000000000000000000000000001"
                }),
            },),
        )
        .await
        .unwrap();
    assert_eq!(quote["kind"], "swap");
    assert!(quote["quoteId"].as_str().unwrap().starts_with("w3_"));
    assert_eq!(
        quote["quote"]["request"]["senderAddress"],
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
    );
    let bridge_quote: serde_json::Value = proxy
        .call(
            "Web3BridgeQuote",
            (tinywallet_bus::wire::Web3QuoteRequest {
                service: web3_service.clone(),
                owner: None,
                params: serde_json::json!({
                    "srcChainId": 1,
                    "srcChainTokenIn": "0x0",
                    "srcChainTokenInAmount": "100",
                    "dstChainId": 10,
                    "dstChainTokenOut": "0x1"
                }),
            },),
        )
        .await
        .unwrap();
    assert_eq!(bridge_quote["kind"], "bridge");
    let dapp_quote: serde_json::Value = proxy
        .call(
            "Web3DappQuote",
            (tinywallet_bus::wire::Web3QuoteRequest {
                service: web3_service.clone(),
                owner: None,
                params: serde_json::json!({
                    "contractAddress": "0x1111111111111111111111111111111111111111",
                    "calldata": "0xabcd",
                    "valueRaw": "0"
                }),
            },),
        )
        .await
        .unwrap();
    assert_eq!(dapp_quote["kind"], "dapp_call");
    let unconfirmed = proxy
        .call_confidential::<serde_json::Value>(
            "Web3Execute",
            (tinywallet_bus::wire::Web3ExecuteRequest {
                service: web3_service.clone(),
                owner: None,
                quote_id: dapp_quote["quoteId"].as_str().unwrap().to_string(),
                confirmed: false,
                secret: SecretMaterial {
                    mnemonic: VECTOR.to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                    chain: Chain::Evm,
                },
            },),
        )
        .await
        .unwrap_err();
    assert!(unconfirmed.to_string().contains("InvalidInput"));
    let solana_quote: serde_json::Value = proxy
        .call(
            "Web3SwapQuote",
            (tinywallet_bus::wire::Web3QuoteRequest {
                service: web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "solana-owner".to_string(),
                    client_id: "client-1".to_string(),
                }),
                params: serde_json::json!({
                    "chainId": tinywallet_web3::crypto::service::DEBRIDGE_SOLANA_CHAIN_ID,
                    "tokenIn": "So11111111111111111111111111111111111111112",
                    "tokenInAmount": "100",
                    "tokenOut": SOLANA_FIXTURE_MINT
                }),
            },),
        )
        .await
        .unwrap();
    let wrong_solana_owner = proxy
        .call_confidential::<serde_json::Value>(
            "Web3Execute",
            (tinywallet_bus::wire::Web3ExecuteRequest {
                service: web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "other-signer".to_string(),
                    client_id: "client-1".to_string(),
                }),
                quote_id: solana_quote["quoteId"].as_str().unwrap().to_string(),
                confirmed: true,
                secret: SecretMaterial {
                    mnemonic: VECTOR.to_string(),
                    derivation_path: "m/44'/501'/0'/0'".to_string(),
                    chain: Chain::Solana,
                },
            },),
        )
        .await
        .unwrap_err();
    assert!(
        wrong_solana_owner
            .to_string()
            .contains("Web3OperationFailed")
    );
    assert!(
        approved_web3.lock().unwrap().is_none(),
        "a foreign Solana quote must be rejected before the host approval callback"
    );
    let wrong_owner = proxy
        .call_confidential::<serde_json::Value>(
            "Web3Execute",
            (tinywallet_bus::wire::Web3ExecuteRequest {
                service: web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "other-thread".to_string(),
                    client_id: "client-1".to_string(),
                }),
                quote_id: quote["quoteId"].as_str().unwrap().to_string(),
                confirmed: true,
                secret: SecretMaterial {
                    mnemonic: VECTOR.to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                    chain: Chain::Evm,
                },
            },),
        )
        .await
        .unwrap_err();
    assert!(wrong_owner.to_string().contains("Web3OperationFailed"));
    assert!(
        approved_web3.lock().unwrap().is_none(),
        "wrong quote owner must not reach approval"
    );

    let execution: serde_json::Value = proxy
        .call_confidential(
            "Web3Execute",
            (tinywallet_bus::wire::Web3ExecuteRequest {
                service: web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "thread-1".to_string(),
                    client_id: "client-1".to_string(),
                }),
                quote_id: quote["quoteId"].as_str().unwrap().to_string(),
                confirmed: true,
                secret: SecretMaterial {
                    mnemonic: VECTOR.to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                    chain: Chain::Evm,
                },
            },),
        )
        .await
        .unwrap();
    assert_eq!(execution["transactionHash"], "0xfeedface");
    let approved = approved_web3.lock().unwrap().clone().unwrap();
    assert_eq!(approved.quote_id, quote["quoteId"].as_str().unwrap());
    assert_eq!(approved.operation, "swap");
    match approved.transaction {
        tinywallet_bus::wire::Web3ExecutionIntent::Evm {
            network,
            to,
            data,
            value,
            nonce,
            gas_limit,
            gas_price_wei,
            chain_id,
        } => {
            assert_eq!(network, "eip155:1");
            assert_eq!(to, "0x0000000000000000000000000000000000000002");
            assert_eq!(data.as_deref(), Some("0x1234"));
            assert_eq!(value, "0");
            assert_eq!(nonce, 0);
            assert_eq!(gas_limit, 21_000);
            assert_eq!(gas_price_wei, "1");
            assert_eq!(chain_id, 1);
        }
        intent @ tinywallet_bus::wire::Web3ExecutionIntent::Solana { .. } => {
            panic!("expected exact EVM signing facts, got {intent:?}")
        }
    }
    let submitted = submitted_tx.lock().unwrap().clone().unwrap();
    assert!(submitted.starts_with("0x"));
    assert!(
        submitted.len() > 100,
        "module should submit a signed EVM transaction"
    );

    let quote_to_invalidate: serde_json::Value = proxy
        .call(
            "Web3SwapQuote",
            (tinywallet_bus::wire::Web3QuoteRequest {
                service: web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "thread-1".to_string(),
                    client_id: "client-1".to_string(),
                }),
                params: serde_json::json!({
                    "chainId": 1,
                    "tokenIn": "0x0000000000000000000000000000000000000000",
                    "tokenInAmount": "100",
                    "tokenOut": "0x0000000000000000000000000000000000000001"
                }),
            },),
        )
        .await
        .unwrap();
    let closed_web3_service = web3_service.clone();
    web3_service = proxy.call("Web3Configure", ((),)).await.unwrap();
    assert_ne!(web3_service, closed_web3_service);
    let stale_quote = proxy
        .call_confidential::<serde_json::Value>(
            "Web3Execute",
            (tinywallet_bus::wire::Web3ExecuteRequest {
                service: closed_web3_service.clone(),
                owner: Some(tinywallet_bus::wire::QuoteOwner {
                    thread_id: "thread-1".to_string(),
                    client_id: "client-1".to_string(),
                }),
                quote_id: quote_to_invalidate["quoteId"].as_str().unwrap().to_string(),
                confirmed: true,
                secret: SecretMaterial {
                    mnemonic: VECTOR.to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                    chain: Chain::Evm,
                },
            },),
        )
        .await
        .unwrap_err();
    assert!(stale_quote.to_string().contains("Web3OperationFailed"));

    host_bad_response.store(true, Ordering::SeqCst);
    let error = proxy
        .call::<serde_json::Value>("Web3Routes", ((),))
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            tinybus::Error::MethodFailed { name, .. }
                if name == "ai.tinyhumans.tinywallet.Error.HostCallFailed"
        ),
        "incompatible callback replies must fail closed without a local fallback"
    );
    host_bad_response.store(false, Ordering::SeqCst);
    proxy
        .call::<()>(
            "Web3Close",
            (Web3CloseRequest {
                service: web3_service,
            },),
        )
        .await
        .unwrap();
    let web3_closed = proxy
        .call::<serde_json::Value>("Web3Routes", ((),))
        .await
        .unwrap_err();
    assert!(web3_closed.to_string().contains("HostUnavailable"));

    validates_addresses_inside_the_artifact(&proxy).await;
    generates_mnemonics_inside_the_artifact(&proxy).await;
    constructs_evm_transactions_inside_the_artifact(&proxy).await;
    signs_an_evm_transfer_identically_to_the_library(&proxy).await;
    signs_a_multi_input_bitcoin_spend(&proxy).await;
    signs_a_solana_transfer(&proxy).await;
    refuses_a_request_the_module_cannot_build(&proxy).await;
    refuses_confidential_secret_delivery_to_an_unattested_artifact().await;

    assert!(matches!(modules.list()[0].state, ModuleState::Ready));
    broker_task.abort();
}

/// Load the built artifact and check its manifest against the interface.
fn module_manifest(artifact: &Path, digest: &str) -> String {
    let key = serde_json::to_string(&artifact.file_name().unwrap().to_string_lossy()).unwrap();
    let value = serde_json::to_string(digest).unwrap();
    format!("{key} = {value}\n")
}

async fn admit_module() -> (
    Connection,
    Connection,
    Arc<AtomicBool>,
    Arc<Mutex<Option<tinywallet_bus::wire::AuthorizeWeb3ExecutionRequest>>>,
    Arc<Mutex<Option<AuthorizeNativeWalletExecutionRequest>>>,
    Arc<Mutex<Vec<NetworkRequest>>>,
    Arc<Mutex<Option<String>>>,
    Arc<Mutex<Option<AuthorizeX402PaymentRequest>>>,
    Arc<AtomicBool>,
    Arc<X402TestGate>,
    ModuleHost,
    tokio::task::JoinHandle<tinybus::Result<()>>,
    tempfile::TempDir,
) {
    let artifact =
        std::env::var_os("TINYWALLET_TEST_MODULE").expect("TINYWALLET_TEST_MODULE must be set");
    let artifact = PathBuf::from(artifact);
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);

    let staged = tempfile::Builder::new()
        .prefix("tinywallet-attested-")
        .tempdir_in(artifact.parent().unwrap())
        .unwrap();
    let staged_artifact = staged.path().join(artifact.file_name().unwrap());
    fs::copy(&artifact, &staged_artifact).unwrap();
    let digest = hex(&Sha256::digest(fs::read(&staged_artifact).unwrap()));
    fs::write(
        staged.path().join("modules.toml"),
        module_manifest(&artifact, &digest),
    )
    .unwrap();

    let host = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    let host_bad_response = Arc::new(AtomicBool::new(false));
    let approved_web3 = Arc::new(Mutex::new(None));
    let approved_native = Arc::new(Mutex::new(None));
    let native_transport_networks = Arc::new(Mutex::new(Vec::new()));
    let submitted_tx = Arc::new(Mutex::new(None));
    let approved_x402 = Arc::new(Mutex::new(None));
    let x402_approved = Arc::new(AtomicBool::new(true));
    let x402_gate = Arc::new(X402TestGate::default());
    host.serve_at(
        HOST_OBJECT_PATH.try_into().unwrap(),
        TestHost {
            bad_response: host_bad_response.clone(),
            approved_web3: approved_web3.clone(),
            approved_native: approved_native.clone(),
            native_transport_networks: native_transport_networks.clone(),
            submitted_tx: submitted_tx.clone(),
            approved_x402: approved_x402.clone(),
            x402_approved: x402_approved.clone(),
            x402_gate: x402_gate.clone(),
        },
    )
    .await
    .unwrap();
    host.request_name(HOST_INTERFACE).await.unwrap();

    let loaded = modules
        .load_file(&staged_artifact)
        .expect("module should load");
    assert_eq!(loaded.name, "tinywallet-module");
    assert_eq!(loaded.manifest.bus_name.as_str(), BUS_NAME);
    assert_eq!(loaded.manifest.object_path.as_str(), OBJECT_PATH);
    assert_eq!(loaded.manifest.requires.len(), 1);
    assert_eq!(
        loaded.manifest.requires[0].interface.interface.as_str(),
        HOST_INTERFACE,
        "the compiled manifest must require the typed host callback contract"
    );
    assert!(loaded.manifest.requires[0].optional);
    assert_eq!(tinywallet_bus::HOST_METHODS.len(), 6);

    let declared: Vec<&str> = loaded
        .manifest
        .provides
        .iter()
        .flat_map(|interface| interface.methods.iter())
        .map(tinybus::MemberName::as_str)
        .collect();
    assert_eq!(
        declared, EXPECTED_METHODS,
        "manifest methods drifted from the interface"
    );

    // And that the manifest is the contract a host compiles against. The three
    // lists — the `#[tinybus::interface]` block, the `module_export!` manifest,
    // and `tinywallet_bus::METHODS` — are independent, and only a host reading
    // the third would notice the first two agreeing on a name it does not know.
    let mut sorted = declared.clone();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        tinywallet_bus::METHODS,
        "the manifest and the published contract name different members"
    );

    let client = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    (
        client,
        host,
        host_bad_response,
        approved_web3,
        approved_native,
        native_transport_networks,
        submitted_tx,
        approved_x402,
        x402_approved,
        x402_gate,
        modules,
        broker_task,
        staged,
    )
}

struct TestHost {
    bad_response: Arc<AtomicBool>,
    approved_web3: Arc<Mutex<Option<tinywallet_bus::wire::AuthorizeWeb3ExecutionRequest>>>,
    approved_native: Arc<Mutex<Option<AuthorizeNativeWalletExecutionRequest>>>,
    native_transport_networks: Arc<Mutex<Vec<NetworkRequest>>>,
    submitted_tx: Arc<Mutex<Option<String>>>,
    approved_x402: Arc<Mutex<Option<AuthorizeX402PaymentRequest>>>,
    x402_approved: Arc<AtomicBool>,
    x402_gate: Arc<X402TestGate>,
}

#[derive(Default)]
struct X402TestGate {
    blocked: AtomicBool,
    started: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

#[expect(
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    reason = "the generated TinyBus host interface requires async methods"
)]
#[tinybus::interface(name = "ai.tinyhumans.tinywallet.Host")]
impl TestHost {
    async fn authorize_x402_payment(
        &self,
        request: AuthorizeX402PaymentRequest,
    ) -> tinybus::Result<HostResponse> {
        *self.approved_x402.lock().unwrap() = Some(request);
        if self.x402_gate.blocked.load(Ordering::SeqCst) {
            self.x402_gate.started.notify_one();
            self.x402_gate.resume.notified().await;
        }
        Ok(HostResponse::Authorization(AuthorizationResult {
            approved: self.x402_approved.load(Ordering::SeqCst),
            reason: Some("fixture approval policy".to_string()),
        }))
    }

    async fn wallet_accounts(&self) -> tinybus::Result<HostResponse> {
        Ok(HostResponse::WalletAccounts(WalletAccountsResponse {
            configured: true,
            accounts: vec![
                tinywallet_bus::wire::WalletAccountInfo {
                    chain: Chain::Evm,
                    address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94".to_string(),
                    derivation_path: "m/44'/60'/0'/0/0".to_string(),
                },
                tinywallet_bus::wire::WalletAccountInfo {
                    chain: Chain::Solana,
                    address: "11111111111111111111111111111111".to_string(),
                    derivation_path: "m/44'/501'/0'/0'".to_string(),
                },
            ],
        }))
    }

    async fn authorize_web3_execution(
        &self,
        request: tinywallet_bus::wire::AuthorizeWeb3ExecutionRequest,
    ) -> tinybus::Result<HostResponse> {
        *self.approved_web3.lock().unwrap() = Some(request);
        Ok(HostResponse::Authorization(AuthorizationResult {
            approved: true,
            reason: None,
        }))
    }

    async fn authorize_native_wallet_execution(
        &self,
        request: AuthorizeNativeWalletExecutionRequest,
    ) -> tinybus::Result<HostResponse> {
        *self.approved_native.lock().unwrap() = Some(request);
        Ok(HostResponse::Authorization(AuthorizationResult {
            approved: true,
            reason: None,
        }))
    }

    async fn chain_transport(
        &self,
        request: ChainTransportRequest,
    ) -> tinybus::Result<HostResponse> {
        let network = match &request {
            ChainTransportRequest::JsonRpc { network, .. }
            | ChainTransportRequest::RestGet { network, .. }
            | ChainTransportRequest::RestPost { network, .. } => network.clone(),
        };
        self.native_transport_networks.lock().unwrap().push(network);
        let result = match request {
            ChainTransportRequest::JsonRpc { method, params, .. } => {
                let value = match method.as_str() {
                    "getLatestBlockhash" => serde_json::json!({
                        "value": {
                            "blockhash": "11111111111111111111111111111111",
                            "lastValidBlockHeight": 100
                        }
                    }),
                    "eth_chainId" | "eth_gasPrice" => serde_json::json!("0x1"),
                    "eth_getTransactionCount" => serde_json::json!("0x0"),
                    "eth_estimateGas" => serde_json::json!("0x5208"),
                    "eth_sendRawTransaction" => {
                        *self.submitted_tx.lock().unwrap() = params[0].as_str().map(str::to_string);
                        serde_json::json!("0xfeedface")
                    }
                    _ => serde_json::Value::Null,
                };
                ChainTransportResult::Ok { body: value }
            }
            _ => ChainTransportResult::Unreachable {
                message: "fixture transport does not implement REST".to_string(),
            },
        };
        Ok(HostResponse::ChainTransport(result))
    }

    async fn wallet_backend(&self, request: WalletBackendRequest) -> tinybus::Result<HostResponse> {
        if self.bad_response.load(Ordering::SeqCst) {
            return Ok(HostResponse::Authorization(AuthorizationResult {
                approved: true,
                reason: None,
            }));
        }
        let data = match request {
            WalletBackendRequest::Routes => serde_json::json!({"routes": ["evm", "solana"]}),
            WalletBackendRequest::SwapTransaction { body }
            | WalletBackendRequest::BridgeTransaction { body } => {
                let tx = if body["chainId"]
                    == tinywallet_web3::crypto::service::DEBRIDGE_SOLANA_CHAIN_ID
                {
                    serde_json::json!({"data":"deadbeef"})
                } else {
                    serde_json::json!({
                        "to": "0x0000000000000000000000000000000000000002",
                        "data": "0x1234",
                        "value": "0"
                    })
                };
                serde_json::json!({"request": body, "tx": tx})
            }
        };
        Ok(HostResponse::WalletBackend(WalletBackendResponse { data }))
    }
}

/// Wait for the module to claim its well-known name.
async fn wait_until_serving(client: &Connection) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if client
                .list_names()
                .await
                .unwrap()
                .iter()
                .any(|name| name.as_str() == BUS_NAME)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("module should become ready");
}

/// The load-bearing case: through the bus must equal in-process.
async fn signs_an_evm_transfer_identically_to_the_library(proxy: &tinybus::Proxy) {
    let secret = derive(Chain::Evm, "m/44'/60'/0'/0/0");
    let spec = TransactionSpec::Evm {
        to: "0x3535353535353535353535353535353535353535".to_string(),
        value_wei: "1000000000000000000".to_string(),
        data_hex: "0x".to_string(),
        nonce: 9,
        gas_limit: 21_000,
        gas_price_wei: "20000000000".to_string(),
        chain_id: 1,
    };

    let signed = round_trip(proxy, &spec, &secret).await;

    let expected = tx::evm::LegacyTransaction {
        nonce: 9,
        gas_price: 20_000_000_000,
        gas_limit: 21_000,
        to: Some("0x3535353535353535353535353535353535353535".to_string()),
        value: 1_000_000_000_000_000_000,
        data: Vec::new(),
        chain_id: 1,
    }
    .sign(&secret)
    .unwrap();

    assert_eq!(
        signed.raw,
        format!("0x{}", hex(&expected)),
        "a transaction signed through the module diverged from the library"
    );
    assert_eq!(
        signed.txid,
        Some(tx::evm::LegacyTransaction::hash_of(&expected))
    );
}

/// Several inputs, so the multi-signature ordering crosses the bus for real.
async fn signs_a_multi_input_bitcoin_spend(proxy: &tinybus::Proxy) {
    let derived = tinywallet::key::derive(Chain::Btc, VECTOR, "m/84'/0'/0'/0/0").unwrap();
    let secret = derived.secret_bytes().to_vec();
    let txid = "7f3b662ea8b6ff2e0e1a1f9bd0f1c39a6b8ba51e1b0f0e0d0c0b0a0908070605";
    let spec = TransactionSpec::Btc {
        from: derived.address().to_string(),
        to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        amount_sat: 150_000,
        fee_sat: 2_000,
        utxos: (0..3)
            .map(|vout| tinywallet::wire::Utxo {
                txid: txid.to_string(),
                vout,
                value: 60_000 + u64::from(vout) * 10_000,
            })
            .collect(),
    };

    let signed = round_trip(proxy, &spec, &secret).await;

    let expected = tx::btc::Transfer {
        from: derived.address().to_string(),
        to: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".to_string(),
        amount: 150_000,
        fee: 2_000,
    }
    .sign(
        &(0..3)
            .map(|vout| tx::btc::Utxo {
                txid: txid.to_string(),
                vout,
                value: 60_000 + u64::from(vout) * 10_000,
            })
            .collect::<Vec<_>>(),
        &secret,
    )
    .unwrap();

    assert_eq!(signed.raw, expected);
}

/// ed25519 rather than a prehashed digest, so the other signing scheme is covered.
async fn signs_a_solana_transfer(proxy: &tinybus::Proxy) {
    use ed25519_dalek::{Signer as _, SigningKey};

    let derived = tinywallet::key::derive(Chain::Solana, VECTOR, "m/44'/501'/0'/0'").unwrap();
    let spec = TransactionSpec::Solana {
        from: derived.address().to_string(),
        to: "11111111111111111111111111111111".to_string(),
        lamports: 1_000_000_000,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
    };
    let public = PublicKey {
        key_hex: hex(derived.secret_bytes()),
    };

    let unsigned: UnsignedTransaction = proxy
        .call(
            "BuildUnsigned",
            (SigningRequest {
                transaction: spec.clone(),
                public_key: public.clone(),
            },),
        )
        .await
        .unwrap();
    assert_eq!(unsigned.payloads[0].scheme, Scheme::Ed25519);

    // Signed here, in this process. The module is never given the key.
    let key: [u8; 32] = derived.secret_bytes().try_into().unwrap();
    let signature = SigningKey::from_bytes(&key)
        .sign(&unhex(&unsigned.payloads[0].bytes_hex))
        .to_bytes();

    let signed: SignedTransaction = proxy
        .call(
            "AttachSignature",
            (AttachRequest {
                transaction: spec.clone(),
                public_key: public,
                signatures: vec![Signature::Ed25519 {
                    signature_hex: hex(&signature),
                }],
            },),
        )
        .await
        .unwrap();

    let expected = tx::solana::NativeTransfer {
        from: derived.address().to_string(),
        to: "11111111111111111111111111111111".to_string(),
        lamports: 1_000_000_000,
        recent_blockhash: "11111111111111111111111111111111".to_string(),
    }
    .sign(derived.secret_bytes())
    .unwrap();

    assert_eq!(signed.raw, base64(&expected));
}

/// A malformed request must come back as a named error, not a signature.
///
/// This used to send a request whose `chain` tag contradicted its transaction.
/// That is no longer expressible — the requests carry no `chain` and the spec
/// names its own — so the case is now a transaction the module can parse but
/// cannot build: a Tron payload whose recomputed `txID` disagrees with the one
/// claimed, which is the defence against a compromised node.
async fn refuses_a_request_the_module_cannot_build(proxy: &tinybus::Proxy) {
    let result: tinybus::Result<UnsignedTransaction> = proxy
        .call(
            "BuildUnsigned",
            (SigningRequest {
                transaction: TransactionSpec::Tron {
                    raw_data_hex: "0a02b1f12208".to_string() + &"ab".repeat(64),
                    expected_to: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t".to_string(),
                    expected_txid: "00".repeat(32),
                    transfer: tinywallet::wire::TronTransfer::Native { amount_sun: 0 },
                },
                public_key: PublicKey {
                    key_hex: "02".repeat(33),
                },
            },),
        )
        .await;

    let error = result.expect_err("a tampered transaction must not produce a signature");
    assert_eq!(
        error.wire_name(),
        "ai.tinyhumans.tinywallet.Error.InvalidInput",
        "the wire error name is the contract a host matches on"
    );
}

/// Drive both calls for a secp256k1 chain, signing locally in between.
async fn round_trip(
    proxy: &tinybus::Proxy,
    spec: &TransactionSpec,
    secret: &[u8],
) -> SignedTransaction {
    let public_key = PublicKey {
        key_hex: hex(&compressed_public(secret)),
    };

    let unsigned: UnsignedTransaction = proxy
        .call(
            "BuildUnsigned",
            (SigningRequest {
                transaction: spec.clone(),
                public_key: public_key.clone(),
            },),
        )
        .await
        .unwrap();

    // Every payload signed here, with a key the module has never seen.
    let signatures = unsigned
        .payloads
        .iter()
        .map(|payload| {
            assert_eq!(payload.scheme, Scheme::Secp256k1Prehash);
            let digest: [u8; 32] = unhex(&payload.bytes_hex).try_into().unwrap();
            let secret = SecretKey::from_slice(secret).unwrap();
            let recoverable = Secp256k1::signing_only()
                .sign_ecdsa_recoverable(&Message::from_digest(digest), &secret);
            let (recovery_id, compact) = recoverable.serialize_compact();
            Signature::Secp256k1 {
                rs_hex: hex(&compact),
                recovery_id: u8::try_from(recovery_id.to_i32()).unwrap(),
            }
        })
        .collect();

    proxy
        .call(
            "AttachSignature",
            (AttachRequest {
                transaction: spec.clone(),
                public_key,
                signatures,
            },),
        )
        .await
        .unwrap()
}

fn derive(chain: Chain, path: &str) -> Vec<u8> {
    tinywallet::key::derive(chain, VECTOR, path)
        .unwrap()
        .secret_bytes()
        .to_vec()
}

fn compressed_public(secret: &[u8]) -> [u8; 33] {
    use bitcoin::secp256k1::PublicKey as SecpPublic;
    let secret = SecretKey::from_slice(secret).unwrap();
    SecpPublic::from_secret_key(&Secp256k1::new(), &secret).serialize()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

fn unhex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}

/// Standard base64, matching what the module emits for Solana.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(TABLE[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

/// The guard, proven against the real loader.
///
/// This module is loaded from a bare path with no `modules.toml` beside it, so
/// nobody vouched for its bytes and the broker must refuse to carry a secret to
/// it — even though the artifact is genuine, the name resolves, and the very
/// same method would succeed if it were attested.
///
/// It is the negative half that makes the confidential flow worth anything. A
/// positive result alone would be equally consistent with a broker that carried
/// every confidential message to anyone who asked.
async fn refuses_confidential_secret_delivery_to_an_unattested_artifact() {
    let artifact =
        std::env::var_os("TINYWALLET_TEST_MODULE").expect("TINYWALLET_TEST_MODULE must be set");
    let artifact = PathBuf::from(artifact);
    // The admitted fixture lives beside a digest manifest. Load a separate
    // copy without that trust file so this path really tests an unattested
    // artifact rather than accidentally reusing the approved directory.
    let untrusted_dir = tempfile::tempdir().expect("create untrusted fixture directory");
    let physical_dir = untrusted_dir.path().join("module");
    fs::create_dir(&physical_dir).expect("create untrusted module directory");
    // macOS temporary roots can include symlink components. Exercise that
    // fixture shape on every Unix runner, without weakening loader admission.
    #[cfg(unix)]
    let fixture_dir = {
        let alias = untrusted_dir.path().join("module-alias");
        std::os::unix::fs::symlink(&physical_dir, &alias).expect("link fixture directory");
        alias
    };
    #[cfg(not(unix))]
    let fixture_dir = physical_dir;
    let fixture_dir = fs::canonicalize(fixture_dir).expect("resolve fixture directory aliases");
    let untrusted_artifact =
        fixture_dir.join(artifact.file_name().expect("test artifact has a filename"));
    fs::copy(&artifact, &untrusted_artifact).expect("copy untrusted test module");
    let bus = MemoryBus::new();
    let broker = Broker::new();
    let broker_task = broker.spawn(bus.clone());
    let modules = ModuleHost::new(broker);
    modules
        .load_file(&untrusted_artifact)
        .expect("unattested module should load");
    let client = Connection::connect(bus.connect().await.unwrap())
        .await
        .unwrap();
    wait_until_serving(&client).await;
    let proxy = client.proxy(BUS_NAME, OBJECT_PATH, BUS_NAME).unwrap();
    let request = serde_json::json!({
        "secret": {
            "mnemonic": VECTOR,
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

    let error = proxy
        .call_confidential::<SignedTransaction>("SignTransaction", (request.clone(),))
        .await
        .expect_err("an unattested module must not receive a recovery phrase");

    // The specific error matters: "not attested" and "no such name" send an
    // operator to fix different things, and the module *is* installed here.
    let rendered = error.to_string();
    assert!(
        rendered.contains("NotAttested") || rendered.to_lowercase().contains("attest"),
        "expected an attestation refusal, got: {rendered}"
    );
    let error = proxy
        .call::<SignedTransaction>("SignTransaction", (request,))
        .await
        .expect_err("secret-bearing calls must reject ordinary delivery");
    assert!(
        error.to_string().to_lowercase().contains("confidential"),
        "expected confidential-call refusal, got: {error}"
    );
    broker_task.abort();
}

async fn generates_mnemonics_inside_the_artifact(proxy: &tinybus::Proxy) {
    use tinywallet_bus::wire::{
        DeriveMnemonicSeedRequest, DeriveMnemonicSeedResponse, GenerateMnemonicRequest,
        GenerateMnemonicResponse,
    };

    let error = proxy
        .call::<GenerateMnemonicResponse>(
            tinywallet_bus::names::methods::GENERATE_MNEMONIC,
            (GenerateMnemonicRequest { word_count: 12 },),
        )
        .await
        .expect_err("mnemonic generation must require confidential delivery");
    assert_eq!(
        error.wire_name(),
        tinybus::Error::CONFIDENTIALITY_REQUIRED,
        "the compiled manifest must keep mnemonic generation confidential"
    );

    let generated: GenerateMnemonicResponse = proxy
        .call_confidential(
            tinywallet_bus::names::methods::GENERATE_MNEMONIC,
            (GenerateMnemonicRequest { word_count: 12 },),
        )
        .await
        .unwrap();
    assert_eq!(generated.word_count, 12);
    assert_eq!(generated.phrase.split_whitespace().count(), 12);

    let seed_request = DeriveMnemonicSeedRequest {
        mnemonic: VECTOR.to_string(),
    };
    let error = proxy
        .call::<DeriveMnemonicSeedResponse>(
            tinywallet_bus::names::methods::DERIVE_MNEMONIC_SEED,
            (seed_request.clone(),),
        )
        .await
        .expect_err("BIP-39 phrases must reject ordinary delivery");
    assert_eq!(
        error.wire_name(),
        tinybus::Error::CONFIDENTIALITY_REQUIRED,
        "the compiled manifest must keep mnemonic seed derivation confidential"
    );

    let seed: DeriveMnemonicSeedResponse = proxy
        .call_confidential(
            tinywallet_bus::names::methods::DERIVE_MNEMONIC_SEED,
            (seed_request,),
        )
        .await
        .unwrap();
    let seed_hex = hex::encode(seed.seed);
    assert_eq!(
        seed_hex,
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
    );

    let derived: DerivedAccount = proxy
        .call_confidential(
            tinywallet_bus::names::methods::DERIVE_ACCOUNT,
            (SecretMaterial {
                mnemonic: generated.phrase,
                derivation_path: "m/44'/60'/0'/0/0".into(),
                chain: Chain::Evm,
            },),
        )
        .await
        .unwrap();
    assert_ne!(derived.address, "");
}

async fn validates_addresses_inside_the_artifact(proxy: &tinybus::Proxy) {
    use tinywallet_bus::wire::{ValidateAddressRequest, ValidateAddressResponse};
    for (chain, address) in [
        (Chain::Evm, "0x3535353535353535353535353535353535353535"),
        (Chain::Solana, "11111111111111111111111111111111"),
        (Chain::Tron, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
    ] {
        let response: ValidateAddressResponse = proxy
            .call(
                "ValidateAddress",
                (ValidateAddressRequest {
                    chain,
                    address: address.into(),
                    sender: false,
                },),
            )
            .await
            .unwrap();
        assert_eq!(response.result.unwrap(), address);
    }
    let response: ValidateAddressResponse = proxy
        .call(
            "ValidateAddress",
            (ValidateAddressRequest {
                chain: Chain::Evm,
                address: "invalid".into(),
                sender: false,
            },),
        )
        .await
        .unwrap();
    assert!(matches!(
        response.result,
        Err(tinywallet_bus::Error::InvalidAddress { .. })
    ));
    let response: ValidateAddressResponse = proxy
        .call(
            "ValidateAddress",
            (ValidateAddressRequest {
                chain: Chain::Btc,
                address: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into(),
                sender: true,
            },),
        )
        .await
        .unwrap();
    assert!(matches!(
        response.result,
        Err(tinywallet_bus::Error::UnsupportedAddressType {
            chain: Chain::Btc,
            ..
        })
    ));
}

/// Verify native/token/call construction and signature-ready bytes through the loaded ABI.
async fn constructs_evm_transactions_inside_the_artifact(proxy: &tinybus::Proxy) {
    use tinywallet_bus::wire::{ConstructedEvmTransaction, EvmConstructionRequest, EvmIntent};
    let secret = derive(Chain::Evm, "m/44'/60'/0'/0/0");
    let mut request = EvmConstructionRequest {
        public_key: PublicKey {
            key_hex: hex(&compressed_public(&secret)),
        },
        chain_id: 1,
        nonce: 7,
        gas_limit: 21000,
        gas_price_wei: "30000000000".into(),
        intent: EvmIntent::NativeTransfer {
            to: "0x3535353535353535353535353535353535353535".into(),
            amount_wei: "5".into(),
        },
    };
    for intent in [
        request.intent.clone(),
        EvmIntent::Erc20Transfer {
            token: "0x1111111111111111111111111111111111111111".into(),
            to: "0x3535353535353535353535353535353535353535".into(),
            amount_raw: "340282366920938463463374607431768211456".into(),
        },
        EvmIntent::ContractCall {
            to: "0x1111111111111111111111111111111111111111".into(),
            value_wei: "0".into(),
            data_hex: "0xAaBb".into(),
        },
    ] {
        request.intent = intent;
        let response: ConstructedEvmTransaction = proxy
            .call(
                tinywallet_bus::names::methods::CONSTRUCT_EVM_TRANSACTION,
                (&request,),
            )
            .await
            .unwrap();
        let unsigned: UnsignedTransaction = proxy
            .call(
                "BuildUnsigned",
                (SigningRequest {
                    transaction: response.transaction.clone(),
                    public_key: request.public_key.clone(),
                },),
            )
            .await
            .unwrap();
        assert_eq!(response.unsigned, unsigned);
        assert_eq!(
            response.approval.sender,
            "0x9858EfFD232B4033E47d90003D41EC34EcaEda94"
        );
        assert_eq!(response.approval.max_fee_wei, "630000000000000");
        let signed = round_trip(proxy, &response.transaction, &secret).await;
        assert!(signed.raw.starts_with("0x"));
    }
    request.public_key.key_hex = "00".repeat(33);
    let refusal: tinybus::Result<ConstructedEvmTransaction> =
        proxy.call("ConstructEvmTransaction", (request,)).await;
    assert!(
        matches!(refusal,Err(tinybus::Error::MethodFailed{name,..}) if name=="ai.tinyhumans.tinywallet.Error.InvalidInput")
    );
}
