//! An engine (and service) wired to every fake.

use std::sync::Arc;

use serde_json::json;

use crate::crypto::seams::{RpcEndpoints, WalletAccounts, WalletSigner};
use crate::crypto::service::Web3Service;
use crate::crypto::wallet::{WalletEngine, WalletSeams};
use crate::seams::QuoteScope;

use super::{
    FakeBackend, FakeQuoteScope, FakeRpcEndpoints, FakeSigner, FakeTransport, FakeWalletAccounts,
};

/// A [`WalletEngine`] with a handle on every fake behind it.
pub(crate) struct Rig {
    pub(crate) engine: Arc<WalletEngine>,
    pub(crate) transport: Arc<FakeTransport>,
    pub(crate) signer: Arc<FakeSigner>,
    pub(crate) accounts: Arc<FakeWalletAccounts>,
    pub(crate) endpoints: Arc<FakeRpcEndpoints>,
    pub(crate) scope: Arc<FakeQuoteScope>,
}

impl Rig {
    /// A configured wallet, no chain answers scripted, no chat context.
    pub(crate) fn new() -> Self {
        let transport = Arc::new(FakeTransport::default());
        let signer = Arc::new(FakeSigner::new());
        let accounts = Arc::new(FakeWalletAccounts::configured());
        let endpoints = Arc::new(FakeRpcEndpoints::new());
        let scope = Arc::new(FakeQuoteScope::default());
        let engine = Arc::new(WalletEngine::new(WalletSeams {
            transport: transport.clone(),
            endpoints: endpoints.clone() as Arc<dyn RpcEndpoints>,
            signer: signer.clone() as Arc<dyn WalletSigner>,
            accounts: accounts.clone() as Arc<dyn WalletAccounts>,
            scope: scope.clone() as Arc<dyn QuoteScope>,
        }));
        Self {
            engine,
            transport,
            signer,
            accounts,
            endpoints,
            scope,
        }
    }

    /// Script the EVM node so a native or token transfer can broadcast:
    /// chain id `chain_id_hex`, nonce 7, 1 gwei, 21000 gas, and a fixed hash.
    pub(crate) fn script_evm_node(&self, chain_id_hex: &str) {
        self.transport
            .on_rpc("eth_chainId", json!(chain_id_hex))
            .on_rpc("eth_getTransactionCount", json!("0x7"))
            .on_rpc("eth_gasPrice", json!("0x3b9aca00"))
            .on_rpc("eth_estimateGas", json!("0x5208"))
            .on_rpc(
                "eth_sendRawTransaction",
                json!(format!("0x{}", "aa".repeat(32))),
            );
    }
}

/// A [`Web3Service`] over a [`Rig`], with its backend fake.
pub(crate) struct ServiceRig {
    pub(crate) service: Arc<Web3Service>,
    pub(crate) rig: Rig,
    pub(crate) backend: Arc<FakeBackend>,
}

impl ServiceRig {
    /// A service whose wallet is configured and whose backend has no scripted
    /// replies.
    pub(crate) fn new() -> Self {
        let rig = Rig::new();
        let backend = Arc::new(FakeBackend::default());
        let service = Arc::new(Web3Service::new(rig.engine.clone(), backend.clone()));
        Self {
            service,
            rig,
            backend,
        }
    }
}
