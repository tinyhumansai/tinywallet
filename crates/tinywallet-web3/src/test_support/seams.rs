//! Fakes for the account, endpoint and scope seams.

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::crypto::defaults::{EvmNetwork, RpcSource, SolanaCluster};
use crate::crypto::seams::{RpcEndpoints, WalletAccounts};
use crate::crypto::wallet::{WalletChain, WalletStatus};
use crate::quote::QuoteOwner;
use crate::seams::QuoteScope;

use super::samples::configured_status;

/// Reports a scripted wallet status, or a scripted failure.
pub(crate) struct FakeWalletAccounts {
    status: Mutex<Result<WalletStatus, String>>,
}

impl FakeWalletAccounts {
    /// A fully configured wallet.
    pub(crate) fn configured() -> Self {
        Self {
            status: Mutex::new(Ok(configured_status())),
        }
    }

    /// Replace what the fake reports.
    pub(crate) fn set(&self, status: Result<WalletStatus, String>) {
        *self.status.lock() = status;
    }

    /// A wallet that was never set up.
    pub(crate) fn unconfigured() -> WalletStatus {
        WalletStatus {
            configured: false,
            onboarding_completed: false,
            consent_granted: false,
            secret_stored: false,
            source: None,
            mnemonic_word_count: None,
            accounts: vec![],
            updated_at_ms: None,
        }
    }
}

#[async_trait]
impl WalletAccounts for FakeWalletAccounts {
    async fn status(&self) -> Result<WalletStatus, String> {
        self.status.lock().clone()
    }
}

/// Endpoints that are recognisable in assertions: `https://rpc.test/<name>`,
/// with a scripted set of overridden chains.
pub(crate) struct FakeRpcEndpoints {
    cluster: Mutex<SolanaCluster>,
    overridden: Mutex<Vec<(WalletChain, Option<EvmNetwork>)>>,
}

impl FakeRpcEndpoints {
    /// Mainnet, nothing overridden.
    pub(crate) fn new() -> Self {
        Self {
            cluster: Mutex::new(SolanaCluster::Mainnet),
            overridden: Mutex::new(vec![]),
        }
    }

    /// Switch the Solana cluster.
    pub(crate) fn set_cluster(&self, cluster: SolanaCluster) {
        *self.cluster.lock() = cluster;
    }

    /// Mark an endpoint as a host override.
    pub(crate) fn override_endpoint(&self, chain: WalletChain, network: Option<EvmNetwork>) {
        self.overridden.lock().push((chain, network));
    }
}

impl RpcEndpoints for FakeRpcEndpoints {
    fn url(&self, chain: WalletChain, network: Option<EvmNetwork>) -> String {
        match (chain, network) {
            (WalletChain::Evm, Some(n)) => format!("https://rpc.test/{}", n.as_str()),
            (WalletChain::Evm, None) => "https://rpc.test/ethereum_mainnet".to_string(),
            (other, _) => format!("https://rpc.test/{}", other.as_str()),
        }
    }

    fn source(&self, chain: WalletChain, network: Option<EvmNetwork>) -> RpcSource {
        if self.overridden.lock().contains(&(chain, network)) {
            RpcSource::EnvOverride
        } else {
            RpcSource::Default
        }
    }

    fn solana_cluster(&self) -> SolanaCluster {
        *self.cluster.lock()
    }
}

/// A scope whose current owner a test sets.
#[derive(Default)]
pub(crate) struct FakeQuoteScope {
    owner: Mutex<Option<QuoteOwner>>,
}

impl FakeQuoteScope {
    /// Make `owner` the current chat thread (`None` for a non-chat caller).
    pub(crate) fn set(&self, owner: Option<QuoteOwner>) {
        *self.owner.lock() = owner;
    }
}

impl QuoteScope for FakeQuoteScope {
    fn current_owner(&self) -> Option<QuoteOwner> {
        self.owner.lock().clone()
    }
}
