//! The seams a host implements to run the crypto flows.
//!
//! Each trait is one thing the host owns: keys, account state, endpoints and
//! its backend. The crate never holds any of them.
//!
//! | Seam | The host owns |
//! | --- | --- |
//! | [`WalletSigner`] | keys: derivation and signing happen behind it |
//! | [`WalletAccounts`] | whether a wallet is set up, and its accounts |
//! | [`RpcEndpoints`] | which endpoint serves a chain, and which Solana cluster |
//! | [`Web3Backend`] | the hosted swap/bridge quote service |
//!
//! Errors are plain `String`s and are surfaced verbatim: the wording a model
//! reads to correct itself is the host's to choose, and the crate adds no
//! prefix to a signer or backend failure.
//!
//! The seams that are neutral about the rail live in [`crate::seams`] and
//! [`crate::quote`].

use async_trait::async_trait;
use serde_json::Value;
use tinywallet_bus::wire::{DerivedAccount, Scheme, Signature, SignedTransaction, TransactionSpec};

use crate::crypto::defaults::{EvmNetwork, RpcSource, SolanaCluster};
use crate::crypto::wallet::{WalletChain, WalletStatus};

/// Derives accounts and signs, without the crate ever seeing a key or a phrase.
///
/// A host typically implements this by calling the loaded wallet module over a
/// confidential call, resolving the recovery phrase for `chain` itself. No
/// mnemonic enters this crate.
#[async_trait]
pub trait WalletSigner: Send + Sync {
    /// The address and public key the wallet derives for `chain`.
    ///
    /// # Errors
    ///
    /// A message to surface to the caller: the wallet is not set up, the phrase
    /// is unavailable, or derivation failed.
    async fn derive_account(&self, chain: WalletChain) -> Result<DerivedAccount, String>;

    /// Build and sign the transaction described by `transaction` for `chain`.
    ///
    /// The returned `raw` is broadcast-ready in the encoding the chain's RPC
    /// expects (hex for Bitcoin and EVM, a signature for Tron).
    ///
    /// # Errors
    ///
    /// A message to surface to the caller.
    async fn sign_transaction(
        &self,
        chain: WalletChain,
        transaction: &TransactionSpec,
    ) -> Result<SignedTransaction, String>;

    /// Sign opaque bytes with the key derived for `chain`.
    ///
    /// Blind: the signer cannot check what the bytes mean. Used only for the
    /// Solana encodings [`TransactionSpec`] does not model (SPL transfers and
    /// externally-built versioned transactions).
    ///
    /// # Errors
    ///
    /// A message to surface to the caller.
    async fn sign_message(
        &self,
        chain: WalletChain,
        message: &[u8],
        scheme: Scheme,
    ) -> Result<Signature, String>;
}

/// Reports the wallet's set-up state and accounts.
#[async_trait]
pub trait WalletAccounts: Send + Sync {
    /// The current wallet status.
    ///
    /// # Errors
    ///
    /// A message to surface to the caller, for example when the host's state
    /// cannot be read.
    async fn status(&self) -> Result<WalletStatus, String>;
}

/// Resolves the endpoint and cluster a host has configured.
///
/// The environment variables and config that drive this are the host's; the
/// crate only asks.
pub trait RpcEndpoints: Send + Sync {
    /// The endpoint serving `chain`. For EVM, `network` picks the network and
    /// `None` means Ethereum mainnet.
    fn url(&self, chain: WalletChain, network: Option<EvmNetwork>) -> String;

    /// Whether that endpoint is the built-in default or a host override.
    fn source(&self, chain: WalletChain, network: Option<EvmNetwork>) -> RpcSource;

    /// The Solana cluster the wallet broadcasts to. It drives both the default
    /// endpoint and the USDC mint.
    fn solana_cluster(&self) -> SolanaCluster;
}

/// The hosted swap/bridge quote service.
///
/// Responses are the backend's `data` payload, passed through untouched: the
/// quote is a large nested object and only the unsigned transaction is read
/// here.
#[async_trait]
pub trait Web3Backend: Send + Sync {
    /// The chains the backend can swap and bridge between.
    ///
    /// # Errors
    ///
    /// A message to surface to the caller, for example when the user is not
    /// signed in.
    async fn routes(&self) -> Result<Value, String>;

    /// A single-chain swap quote and its unsigned transaction.
    ///
    /// # Errors
    ///
    /// A message to surface to the caller.
    async fn swap_tx(&self, body: &Value) -> Result<Value, String>;

    /// A cross-chain bridge quote and its unsigned transaction.
    ///
    /// # Errors
    ///
    /// A message to surface to the caller.
    async fn bridge_tx(&self, body: &Value) -> Result<Value, String>;
}
