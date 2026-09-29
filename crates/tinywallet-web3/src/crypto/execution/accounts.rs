//! Resolving a derived wallet account for a chain, erroring cleanly when the
//! wallet has not been configured yet.

use crate::crypto::wallet::{WalletAccount, WalletChain, WalletEngine};
use crate::quote::WALLET_NOT_CONFIGURED_MESSAGE;

impl WalletEngine {
    /// Resolve the derived EVM account address, erroring if the wallet is not
    /// configured. Used by the swap/bridge/dapp signing primitives, which
    /// operate on the single shared EVM address.
    pub(crate) async fn require_evm_account(&self) -> Result<String, String> {
        Ok(self.require_account(WalletChain::Evm).await?.address)
    }

    /// Resolve the derived account for `chain`.
    pub(crate) async fn require_account(&self, chain: WalletChain) -> Result<WalletAccount, String> {
        let status = self.accounts.status().await?;
        if !status.configured {
            return Err(WALLET_NOT_CONFIGURED_MESSAGE.to_string());
        }
        status
            .accounts
            .into_iter()
            .find(|account| account.chain == chain)
            .ok_or_else(|| format!("no wallet account derived for chain '{}'", chain.as_str()))
    }
}
