//! The cheap per-chain call `chain_status` makes to learn whether an endpoint
//! answers.
//!
//! Each probe asks for the chain tip through the
//! [`Transport`](tinywallet_crypto::rpc::Transport) seam, the smallest read
//! every provider serves, and checks the reply looks like one: an endpoint that
//! answers with something else (a captive portal, a stub) is not ready.

use log::debug;
use serde_json::{Value, json};

use crate::crypto::defaults::EvmNetwork;
use crate::crypto::wallet::{WalletChain, WalletEngine};

use super::LOG_PREFIX;
use super::validate::hex_to_u128;

impl WalletEngine {
    /// Ask the endpoint serving `chain` (and, for EVM, `network`) for its tip.
    ///
    /// EVM calls `eth_blockNumber`, Solana `getHealth`, Bitcoin reads Esplora's
    /// `blocks/tip/height` and Tron posts `wallet/getnowblock`.
    ///
    /// # Errors
    ///
    /// The transport's message when the endpoint cannot be reached or answers
    /// with an error, or a description of the reply when it is not a tip.
    pub(super) async fn probe_provider(
        &self,
        chain: WalletChain,
        network: Option<EvmNetwork>,
    ) -> Result<(), String> {
        let result = match chain {
            WalletChain::Evm => {
                let network = network.unwrap_or(EvmNetwork::EthereumMainnet);
                self.evm_rpc_call::<String>(network, "eth_blockNumber", json!([]))
                    .await
                    .and_then(|height| {
                        hex_to_u128(&height).map(drop).map_err(|e| {
                            format!("eth_blockNumber did not return a block number: {e}")
                        })
                    })
            }
            WalletChain::Solana => self
                .rpc_call::<Value>(WalletChain::Solana, "getHealth", json!([]))
                .await
                .map(drop),
            WalletChain::Btc => self
                .rest_get_text(WalletChain::Btc, "blocks/tip/height")
                .await
                .and_then(|body| {
                    body.trim()
                        .parse::<u64>()
                        .map(drop)
                        .map_err(|_| "BTC chain tip height was not a number".to_string())
                }),
            WalletChain::Tron => self
                .rest_post_json::<Value>(WalletChain::Tron, "wallet/getnowblock", &json!({}))
                .await
                .and_then(|block| {
                    block
                        .get("blockID")
                        .and_then(Value::as_str)
                        .map(drop)
                        .ok_or_else(|| "Tron getnowblock returned no block".to_string())
                }),
        };
        debug!(
            "{LOG_PREFIX} probe chain={} network={} ok={}",
            chain.as_str(),
            network.map_or("-", EvmNetwork::as_str),
            result.is_ok()
        );
        result
    }
}
