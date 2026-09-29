//! [`WalletEngine`]: the wallet flows' instance-owned state.

use std::fmt;
use std::sync::Arc;

use tinywallet_crypto::rpc::{NetworkId, Transport, TransportError};

use crate::crypto::defaults::EvmNetwork;
use crate::crypto::execution::PreparedTransaction;
use crate::crypto::seams::{RpcEndpoints, WalletAccounts, WalletSigner};
use crate::quote::QuoteStore;
use crate::seams::QuoteScope;

use super::types::WalletChain;

/// How long a prepared transfer stays executable.
pub(crate) const QUOTE_TTL_MS: u64 = 5 * 60 * 1000;
/// How many prepared transfers are held before the oldest is evicted.
const QUOTE_STORE_CAP: usize = 64;

/// Everything a host supplies to build a [`WalletEngine`].
///
/// A plain struct rather than five positional arguments: the seams are all
/// `Arc<dyn …>` and easy to transpose.
#[derive(Clone)]
pub struct WalletSeams {
    /// Reaches the chains. Endpoint choice, failover and log redaction are the
    /// host's.
    pub transport: Arc<dyn Transport>,
    /// Resolves the endpoint and cluster the host configured.
    pub endpoints: Arc<dyn RpcEndpoints>,
    /// Derives accounts and signs. Key material never enters this crate.
    pub signer: Arc<dyn WalletSigner>,
    /// Reports whether the wallet is set up and which accounts it has.
    pub accounts: Arc<dyn WalletAccounts>,
    /// Says which chat thread is asking, to bind quotes to it.
    pub scope: Arc<dyn QuoteScope>,
}

impl fmt::Debug for WalletSeams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletSeams").finish_non_exhaustive()
    }
}

/// The wallet flows: balances, transfers, transaction lookups and the raw
/// sign-and-broadcast primitives the swap/bridge/dapp service builds on.
///
/// Instance-owned: two engines share nothing, quotes included.
pub struct WalletEngine {
    pub(crate) transport: Arc<dyn Transport>,
    pub(crate) endpoints: Arc<dyn RpcEndpoints>,
    pub(crate) signer: Arc<dyn WalletSigner>,
    pub(crate) accounts: Arc<dyn WalletAccounts>,
    pub(crate) scope: Arc<dyn QuoteScope>,
    pub(crate) quotes: QuoteStore<PreparedTransaction>,
}

impl fmt::Debug for WalletEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletEngine")
            .field("quotes", &self.quotes.len())
            .finish_non_exhaustive()
    }
}

impl WalletEngine {
    /// Build an engine over the host's seams.
    #[must_use]
    pub fn new(seams: WalletSeams) -> Self {
        Self {
            transport: seams.transport,
            endpoints: seams.endpoints,
            signer: seams.signer,
            accounts: seams.accounts,
            scope: seams.scope,
            quotes: QuoteStore::new("q", QUOTE_TTL_MS, QUOTE_STORE_CAP),
        }
    }

    /// The quotes that can still be executed. Used by test support to inspect
    /// what a flow prepared.
    #[must_use]
    pub fn prepared_quotes(&self) -> Vec<PreparedTransaction> {
        self.quotes.live()
    }

    /// The [`NetworkId`] a request for `chain` (and, for EVM, `network`) is
    /// bound for.
    pub(crate) fn network_id(chain: WalletChain, network: Option<EvmNetwork>) -> NetworkId {
        match chain {
            WalletChain::Evm => {
                NetworkId::evm(network.unwrap_or(EvmNetwork::EthereumMainnet).chain_id())
            }
            other => NetworkId::chain(other.to_chain()),
        }
    }
}

/// Flatten a [`TransportError`] to the message the host produced.
///
/// The messages are the wire the wallet has always reported (they are matched
/// on by callers, e.g. `status=404`), so they are passed through untouched
/// rather than through `Display`, which prefixes the network.
pub(crate) fn transport_message(error: TransportError) -> String {
    match error {
        TransportError::Unreachable { message, .. } | TransportError::Rpc { message, .. } => {
            message
        }
        other => other.to_string(),
    }
}
