//! Read-only transaction lookups: lifecycle state, receipt and raw payload,
//! dispatched to the chain-specific client.

use log::debug;

use crate::crypto::chains::{btc, evm, solana, tron};
use crate::crypto::defaults::EvmNetwork;
use crate::crypto::wallet::{WalletChain, WalletEngine};

use super::LOG_PREFIX;
use super::types::{TxLookupInfo, TxReceiptInfo, TxStatusInfo};

/// Trim a hash and reject an empty one.
fn clean_hash(hash: &str) -> Result<&str, String> {
    let hash = hash.trim();
    if hash.is_empty() {
        return Err("tx hash is empty".to_string());
    }
    Ok(hash)
}

/// The EVM network for a read, defaulting to Ethereum mainnet.
fn read_network(evm_network: Option<EvmNetwork>) -> EvmNetwork {
    evm_network.unwrap_or(EvmNetwork::EthereumMainnet)
}

impl WalletEngine {
    /// Check the on-chain lifecycle state of a previously broadcast
    /// transaction.
    ///
    /// # Errors
    ///
    /// A message when `hash` is empty or the chain query fails.
    pub async fn tx_status(
        &self,
        chain: WalletChain,
        evm_network: Option<EvmNetwork>,
        hash: &str,
    ) -> Result<TxStatusInfo, String> {
        let hash = clean_hash(hash)?;
        let info = match chain {
            WalletChain::Evm => evm::tx_status(self, read_network(evm_network), hash).await?,
            WalletChain::Btc => btc::tx_status(self, hash).await?,
            WalletChain::Solana => solana::tx_status(self, hash).await?,
            WalletChain::Tron => tron::tx_status(self, hash).await?,
        };
        debug!(
            "{LOG_PREFIX} tx_status chain={} hash={hash} state={:?}",
            chain.as_str(),
            info.state
        );
        Ok(info)
    }

    /// Fetch the receipt of a broadcast transaction (success flag, fee, block).
    ///
    /// # Errors
    ///
    /// A message when `hash` is empty or the chain query fails.
    pub async fn tx_receipt(
        &self,
        chain: WalletChain,
        evm_network: Option<EvmNetwork>,
        hash: &str,
    ) -> Result<TxReceiptInfo, String> {
        let hash = clean_hash(hash)?;
        let info = match chain {
            WalletChain::Evm => evm::tx_receipt(self, read_network(evm_network), hash).await?,
            WalletChain::Btc => btc::tx_receipt(self, hash).await?,
            WalletChain::Solana => solana::tx_receipt(self, hash).await?,
            WalletChain::Tron => tron::tx_receipt(self, hash).await?,
        };
        debug!(
            "{LOG_PREFIX} tx_receipt chain={} hash={hash} found={}",
            chain.as_str(),
            info.found
        );
        Ok(info)
    }

    /// Look up the raw transaction payload by hash.
    ///
    /// # Errors
    ///
    /// A message when `hash` is empty or the chain query fails.
    pub async fn lookup_tx(
        &self,
        chain: WalletChain,
        evm_network: Option<EvmNetwork>,
        hash: &str,
    ) -> Result<TxLookupInfo, String> {
        let hash = clean_hash(hash)?;
        let info = match chain {
            WalletChain::Evm => evm::lookup_tx(self, read_network(evm_network), hash).await?,
            WalletChain::Btc => btc::lookup_tx(self, hash).await?,
            WalletChain::Solana => solana::lookup_tx(self, hash).await?,
            WalletChain::Tron => tron::lookup_tx(self, hash).await?,
        };
        debug!(
            "{LOG_PREFIX} lookup_tx chain={} hash={hash} found={}",
            chain.as_str(),
            info.found
        );
        Ok(info)
    }
}
