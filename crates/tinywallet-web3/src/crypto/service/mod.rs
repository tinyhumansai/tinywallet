//! The swap, bridge and dapp flows, built on the wallet.
//!
//! Quotes and unsigned transactions come from the hosted deBridge proxy behind
//! [`Web3Backend`]; signing and broadcast are delegated to the
//! [`WalletEngine`]'s raw primitives, so private keys never leave the signer.
//! Three flows share one quote store:
//!
//! - **swap** — single-chain swaps (cross-chain requests are redirected to
//!   bridge).
//! - **bridge** — cross-chain DLN bridges; the unsigned transaction is always
//!   signed and broadcast on the source chain.
//! - **dapp** — generic EVM contract calls from caller-supplied calldata.
//!
//! Every flow is prepare-then-confirm: a quote is bound to the chat thread that
//! prepared it and expires after five minutes.

mod execute;
mod ops;
mod types;

use std::fmt;
use std::sync::Arc;

use crate::crypto::seams::Web3Backend;
use crate::crypto::wallet::WalletEngine;
use crate::quote::QuoteStore;

pub use types::{
    BridgeQuoteParams, ChainFamily, DEBRIDGE_SOLANA_CHAIN_ID, DappCallParams, ExecuteQuoteParams,
    StoredQuote, SwapQuoteParams, UnsignedTx, Web3ExecutionResult, Web3Quote, Web3QuoteKind,
    chain_family,
};

const LOG_PREFIX: &str = "[web3]";
const QUOTE_TTL_MS: u64 = 5 * 60 * 1000;
const QUOTE_STORE_CAP: usize = 64;

/// The swap/bridge/dapp service: the wallet engine, the backend and the quote
/// store shared by the three flows.
///
/// Instance-owned, like [`WalletEngine`]: two services share no quotes.
pub struct Web3Service {
    pub(crate) engine: Arc<WalletEngine>,
    pub(crate) backend: Arc<dyn Web3Backend>,
    pub(crate) quotes: QuoteStore<StoredQuote>,
}

impl fmt::Debug for Web3Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Web3Service")
            .field("quotes", &self.quotes.len())
            .finish_non_exhaustive()
    }
}

impl Web3Service {
    /// Build a service over `engine` and the host's backend.
    #[must_use]
    pub fn new(engine: Arc<WalletEngine>, backend: Arc<dyn Web3Backend>) -> Self {
        Self {
            engine,
            backend,
            quotes: QuoteStore::new("w3", QUOTE_TTL_MS, QUOTE_STORE_CAP),
        }
    }

    /// The quotes that can still be executed. Used by test support to inspect
    /// what a flow prepared.
    #[must_use]
    pub fn stored_quotes(&self) -> Vec<StoredQuote> {
        self.quotes.live()
    }
}

#[cfg(test)]
mod test;
