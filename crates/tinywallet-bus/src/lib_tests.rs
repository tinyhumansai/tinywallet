//! Tests that pin the shared `TinyWallet` vocabulary and compatibility rule.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    BUS_NAME, CONFIDENTIAL_METHODS, CONTRACT_VERSION, HOST_INTERFACE, HOST_METHODS,
    HOST_OBJECT_PATH, METHODS, OBJECT_PATH, is_compatible, names,
};

#[cfg(feature = "wire")]
#[test]
fn shipped_tool_declarations_match_the_recorded_pre_move_contract() {
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "../tests/fixtures/tool-declarations-pre-native-v0.9.0.json"
    ))
    .unwrap();
    let actual = serde_json::Value::Array(
        super::tools::shipped_tool_declarations()
            .into_iter()
            .map(|declaration| {
                serde_json::json!({
                    "name": declaration.name,
                    "description": declaration.description,
                    "parameters": declaration.parameters,
                })
            })
            .collect(),
    );
    assert_eq!(actual, recorded);
}

#[cfg(feature = "wire")]
#[test]
fn named_tool_declaration_lookup_reports_unknown_names_without_fallback() {
    assert_eq!(
        super::tools::find_tool_declaration("web3_swap_execute").map(|tool| tool.name),
        Some("web3_swap_execute")
    );
    assert_eq!(
        super::tools::find_tool_declaration("wallet_tool_that_does_not_exist"),
        None
    );
    assert_eq!(
        super::tools::find_web3_tool_declaration("web3_unknown"),
        None
    );
    assert_eq!(
        super::tools::find_wallet_tool_declaration("wallet_unknown"),
        None
    );
}

#[cfg(feature = "wire")]
#[test]
fn network_identifiers_keep_their_wire_names_and_chain_ids() {
    use super::wire::{EvmNetwork, SolanaCluster};

    assert_eq!(EvmNetwork::BaseMainnet.as_str(), "base_mainnet");
    assert_eq!(EvmNetwork::BaseMainnet.chain_id(), 8453);
    assert_eq!(
        serde_json::to_value(SolanaCluster::Devnet).unwrap(),
        "devnet"
    );
}

#[cfg(feature = "wire")]
#[test]
fn web3_endpoint_configuration_contains_keys_but_no_endpoint_urls() {
    let request = super::wire::Web3ConfigureRequest {
        solana_cluster: super::wire::SolanaCluster::Devnet,
        overridden_endpoints: vec![super::wire::RpcEndpointKey::Evm {
            network: super::wire::EvmNetwork::BaseMainnet,
        }],
    };
    let encoded = serde_json::to_value(&request).expect("configuration serializes");
    assert_eq!(encoded["solanaCluster"], "devnet");
    assert!(encoded.get("url").is_none());
    assert_eq!(
        serde_json::from_value::<super::wire::Web3ConfigureRequest>(encoded).unwrap(),
        request
    );
}

#[cfg(feature = "wire")]
#[test]
fn network_request_keeps_legacy_json_and_omits_unset_endpoint_url() {
    use super::Chain;
    use super::wire::NetworkRequest;

    let legacy = serde_json::json!({
        "chain": "evm",
        "evm_chain_id": 1,
        "endpoint_ref": "configured-endpoint"
    });
    let decoded: NetworkRequest = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(decoded.endpoint_url, None);
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);

    let default = NetworkRequest {
        chain: Chain::Evm,
        evm_chain_id: Some(1),
        endpoint_ref: None,
        endpoint_url: Some("https://rpc.example".to_string()),
    };
    assert_eq!(
        serde_json::to_value(default).unwrap()["endpoint_url"],
        "https://rpc.example"
    );
}

#[test]
fn the_contract_accepts_its_own_version_and_newer_minors() {
    assert_eq!(CONTRACT_VERSION, (1, 14));
    assert!(is_compatible(CONTRACT_VERSION));
    assert!(is_compatible((CONTRACT_VERSION.0, CONTRACT_VERSION.1 + 1)));
    assert!(!is_compatible((CONTRACT_VERSION.0 + 1, 0)));
    // A module older than the host cannot serve every member the host may call.
    assert!(!is_compatible((1, 5)));
}

#[test]
fn storage_declarations_are_available_from_the_bus_contract() {
    let names = super::storage_collections()
        .into_iter()
        .map(|collection| collection.name)
        .collect::<Vec<_>>();

    assert_eq!(names, ["wallet.budgets", "wallet.migrations"]);
}

#[test]
fn the_identity_matches_the_path_the_module_serves() {
    // Both spellings appear in the module's `serve_at` / `request_name` pair,
    // and a host that guesses one of them gets `NameHasNoOwner` at call time.
    assert_eq!(BUS_NAME, "ai.tinyhumans.tinywallet.Wallet");
    assert_eq!(OBJECT_PATH, "/ai/tinyhumans/tinywallet/Wallet");
}

#[test]
fn the_method_list_is_sorted_complete_and_free_of_duplicates() {
    let mut sorted = METHODS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.as_slice(),
        METHODS,
        "sorted dispatch order, no repeats"
    );
    assert_eq!(METHODS.len(), 38);
    for member in [
        names::methods::ATTACH_SIGNATURE,
        names::methods::BUILD_UNSIGNED,
        names::methods::CONSTRUCT_EVM_TRANSACTION,
        names::methods::DERIVE_ACCOUNT,
        names::methods::DERIVE_MNEMONIC_SEED,
        names::methods::ENCODE_ERC20_TRANSFER,
        names::methods::EXPORT_KEY,
        names::methods::GENERATE_MNEMONIC,
        names::methods::SIGN_MESSAGE,
        names::methods::SIGN_TRANSACTION,
        names::methods::VALIDATE_ADDRESS,
        names::methods::WEB3_ROUTES,
        names::methods::WEB3_SWAP_QUOTE,
        names::methods::WEB3_BRIDGE_QUOTE,
        names::methods::WEB3_DAPP_QUOTE,
        names::methods::WEB3_EXECUTE,
        names::methods::WEB3_CLOSE,
        names::methods::WEB3_CONFIGURE,
        names::methods::WEB3_CONFIGURE_WITH_ENDPOINTS,
        names::methods::WEB3_CONFIGURE_WITH_ENDPOINTS,
        names::methods::NATIVE_WALLET_CONFIGURE,
        names::methods::NATIVE_WALLET_CLOSE,
        names::methods::NATIVE_WALLET_NETWORK_DEFAULTS,
        names::methods::NATIVE_WALLET_SUPPORTED_ASSETS,
        names::methods::NATIVE_WALLET_CHAIN_STATUS,
        names::methods::NATIVE_WALLET_BALANCES,
        names::methods::NATIVE_WALLET_PREPARE_TRANSFER,
        names::methods::NATIVE_WALLET_EXECUTE_PREPARED,
        names::methods::NATIVE_WALLET_TX_STATUS,
        names::methods::NATIVE_WALLET_TX_RECEIPT,
        names::methods::NATIVE_WALLET_LOOKUP_TX,
        names::methods::X402_PREPARE_PAYMENT,
        names::methods::X402_RECORD_PAYMENT,
        names::methods::X402_SPENDING_SUMMARY,
        names::methods::X402_SPENDING_SUMMARY_DETAILED,
        names::methods::X402_LIST_PAYMENTS,
        names::methods::X402_UPDATE_BUDGET,
        names::methods::X402_CLOSE,
        names::methods::X402_CONFIGURE,
    ] {
        assert!(
            METHODS.contains(&member),
            "{member} is missing from METHODS"
        );
    }
}

#[cfg(feature = "wire")]
#[test]
fn x402_history_and_budget_wire_vocabulary_preserves_rpc_record_shape() {
    use super::wire::{
        X402ListPaymentsRequest, X402ListPaymentsResponse, X402PaymentRecord, X402PaymentStatus,
        X402ServiceHandle, X402UpdateBudgetRequest,
    };

    let request = X402ListPaymentsRequest {
        service: X402ServiceHandle {
            handle: "opaque-service".into(),
        },
        limit: 50,
    };
    assert_eq!(
        serde_json::to_value(&request).unwrap(),
        serde_json::json!({ "service": { "handle": "opaque-service" }, "limit": 50 })
    );

    let response = X402ListPaymentsResponse {
        payments: vec![X402PaymentRecord {
            id: "payment-1".into(),
            url: "https://api.example/resource".into(),
            asset: "asset".into(),
            amount_atomic: 2500,
            amount_display: "0.002500 USDC".into(),
            recipient: "recipient".into(),
            network: "eip155:1".into(),
            tx_signature: None,
            status: X402PaymentStatus::Pending,
            timestamp: "2026-10-11T00:00:00Z".into(),
            authorization_valid_until: None,
            solana_last_valid_block_height: None,
            authorization_expired_at: None,
            authorization_expiry_observed_height: None,
            session_id: "session-1".into(),
            thread_id: Some("thread-1".into()),
        }],
    };
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(encoded["payments"][0]["amountAtomic"], 2500);
    assert_eq!(encoded["payments"][0]["status"], "pending");
    assert_eq!(encoded["payments"][0]["threadId"], "thread-1");
    assert!(encoded["payments"][0].get("txSignature").is_none());

    let budget = X402UpdateBudgetRequest {
        service: request.service,
        per_request_max_atomic: Some(1_000_000),
        daily_max_atomic: None,
        monthly_max_atomic: Some(9_000_000),
    };
    assert_eq!(
        serde_json::to_value(budget).unwrap(),
        serde_json::json!({
            "service": { "handle": "opaque-service" },
            "per_request_max_atomic": 1_000_000,
            "monthly_max_atomic": 9_000_000
        })
    );
}

#[test]
fn host_callbacks_are_the_used_typed_capabilities() {
    let mut sorted = HOST_METHODS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.as_slice(), HOST_METHODS);
    assert_eq!(HOST_METHODS.len(), 6);
    assert_eq!(HOST_INTERFACE, "ai.tinyhumans.tinywallet.Host");
    assert_eq!(HOST_OBJECT_PATH, "/ai/tinyhumans/tinywallet/Host");
    assert!(HOST_METHODS.contains(&names::host_methods::AUTHORIZE_WEB3_EXECUTION));
    assert!(HOST_METHODS.contains(&names::host_methods::AUTHORIZE_X402_PAYMENT));
    assert!(HOST_METHODS.contains(&names::host_methods::CHAIN_TRANSPORT));
    assert!(HOST_METHODS.contains(&names::host_methods::WALLET_ACCOUNTS));
    assert!(HOST_METHODS.contains(&names::host_methods::WALLET_BACKEND));
    assert!(HOST_METHODS.contains(&names::host_methods::AUTHORIZE_NATIVE_WALLET_EXECUTION));
}

#[test]
fn native_wallet_members_are_additive_and_use_one_typed_argument() {
    use names::{host_methods, methods};

    let native_members = [
        methods::NATIVE_WALLET_CONFIGURE,
        methods::NATIVE_WALLET_CLOSE,
        methods::NATIVE_WALLET_NETWORK_DEFAULTS,
        methods::NATIVE_WALLET_SUPPORTED_ASSETS,
        methods::NATIVE_WALLET_CHAIN_STATUS,
        methods::NATIVE_WALLET_BALANCES,
        methods::NATIVE_WALLET_PREPARE_TRANSFER,
        methods::NATIVE_WALLET_EXECUTE_PREPARED,
        methods::NATIVE_WALLET_TX_STATUS,
        methods::NATIVE_WALLET_TX_RECEIPT,
        methods::NATIVE_WALLET_LOOKUP_TX,
    ];
    assert_eq!(METHODS.len(), 38);
    assert!(native_members.iter().all(|member| METHODS.contains(member)));
    assert_eq!(HOST_METHODS.len(), 6);
    assert!(HOST_METHODS.contains(&host_methods::AUTHORIZE_NATIVE_WALLET_EXECUTION));
}

#[test]
fn native_wallet_configuration_serializes_only_endpoint_keys_and_opaque_references() {
    use crate::wire::{
        NativeWalletConfigRequest, NativeWalletConfigResponse, NativeWalletServiceHandle,
        RpcEndpointKey, SolanaCluster,
    };
    use serde_json::json;

    let request = NativeWalletConfigRequest {
        solana_cluster: SolanaCluster::Devnet,
        overridden_endpoints: vec![RpcEndpointKey::Evm {
            network: crate::wire::EvmNetwork::BaseMainnet,
        }],
    };
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        json!({
            "solanaCluster": "devnet",
            "overriddenEndpoints": [{ "evm": { "network": "base_mainnet" } }]
        })
    );

    let response = NativeWalletConfigResponse {
        service: NativeWalletServiceHandle {
            handle: "service-opaque".to_string(),
        },
        endpoint_references: vec![crate::wire::HostEndpointReference {
            key: RpcEndpointKey::Evm {
                network: crate::wire::EvmNetwork::BaseMainnet,
            },
            reference: "endpoint-opaque".to_string(),
        }],
    };
    let serialized = serde_json::to_value(response).unwrap();
    assert_eq!(
        serialized["endpointReferences"][0]["reference"],
        "endpoint-opaque"
    );
    assert!(!serialized.to_string().contains("credential"));
}

#[test]
fn x402_authorization_owner_is_optional_and_preserves_legacy_json() {
    use crate::wire::AuthorizeX402PaymentRequest;
    use serde_json::json;

    let legacy = json!({
        "url": "https://resource.example/item",
        "network": "eip155:1",
        "asset": "0x1111111111111111111111111111111111111111",
        "recipient": "0x2222222222222222222222222222222222222222",
        "amount_atomic": 17
    });
    let decoded: AuthorizeX402PaymentRequest = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(decoded.owner, None);
    assert_eq!(serde_json::to_value(decoded).unwrap(), legacy);
}

#[test]
fn native_wallet_approval_carries_the_quote_and_exact_chain_transaction() {
    use crate::wire::{
        AuthorizeNativeWalletExecutionRequest, NativeWalletExecutionIntent, PreparedKind,
        PreparedStatus, PreparedTransaction, TransactionSpec, WalletChain,
    };
    use serde_json::json;

    let request = AuthorizeNativeWalletExecutionRequest {
        quote_id: "quote-1".to_string(),
        operation: "transfer".to_string(),
        quote: PreparedTransaction {
            quote_id: "quote-1".to_string(),
            kind: PreparedKind::NativeTransfer,
            chain: WalletChain::Btc,
            evm_network: None,
            from_address: "from".to_string(),
            to_address: "to".to_string(),
            asset_symbol: "BTC".to_string(),
            amount_raw: "1000".to_string(),
            amount_formatted: "0.00001000".to_string(),
            receive_symbol: None,
            min_receive_raw: None,
            calldata: None,
            token_address: None,
            estimated_fee_raw: "10".to_string(),
            status: PreparedStatus::AwaitingConfirmation,
            created_at_ms: 1,
            expires_at_ms: 2,
            notes: vec![],
        },
        intent: NativeWalletExecutionIntent::Transaction {
            transaction: TransactionSpec::Btc {
                from: "from".to_string(),
                to: "to".to_string(),
                amount_sat: 1000,
                fee_sat: 10,
                utxos: vec![],
            },
        },
    };
    let serialized = serde_json::to_value(request).unwrap();
    assert_eq!(serialized["intent"]["transaction"]["kind"], "btc");
    assert_eq!(serialized["quote"]["amountRaw"], json!("1000"));
}

#[test]
fn every_confidential_member_is_a_member() {
    // The confidential set is a subset, not a parallel list: a name that
    // drifted out of `METHODS` would be a member nobody can call, advertised as
    // one that carries a recovery phrase.
    for member in CONFIDENTIAL_METHODS {
        assert!(METHODS.contains(member), "{member} is not a member");
    }
    // `BuildUnsigned` and `AttachSignature` carry no secret by construction —
    // that is the whole point of the two-round-trip flow.
    assert!(!CONFIDENTIAL_METHODS.contains(&names::methods::BUILD_UNSIGNED));
    assert!(!CONFIDENTIAL_METHODS.contains(&names::methods::ATTACH_SIGNATURE));
    assert!(CONFIDENTIAL_METHODS.contains(&names::methods::GENERATE_MNEMONIC));
    assert!(CONFIDENTIAL_METHODS.contains(&names::methods::DERIVE_MNEMONIC_SEED));
}
