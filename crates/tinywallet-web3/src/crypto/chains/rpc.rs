//! Typed helpers over the [`Transport`](tinywallet_crypto::rpc::Transport)
//! seam.
//!
//! The transport hands back raw JSON or text. These helpers decode it and, on
//! failure, produce the exact messages the wallet has always reported (they are
//! matched on by callers: `status=404` decides "not found" for Esplora), so the
//! wording here is a contract rather than decoration.

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::crypto::defaults::EvmNetwork;
use crate::crypto::wallet::{WalletChain, WalletEngine};

use crate::crypto::wallet::transport_message;

impl WalletEngine {
    /// JSON-RPC call against `chain`'s endpoint (Solana), decoding the result.
    pub(crate) async fn rpc_call<T: DeserializeOwned>(
        &self,
        chain: WalletChain,
        method: &str,
        params: Value,
    ) -> Result<T, String> {
        self.json_rpc(Self::network_id(chain, None), method, params)
            .await
    }

    /// JSON-RPC call against an EVM network's endpoint, decoding the result.
    pub(crate) async fn evm_rpc_call<T: DeserializeOwned>(
        &self,
        network: EvmNetwork,
        method: &str,
        params: Value,
    ) -> Result<T, String> {
        self.json_rpc(
            Self::network_id(WalletChain::Evm, Some(network)),
            method,
            params,
        )
        .await
    }

    async fn json_rpc<T: DeserializeOwned>(
        &self,
        network: tinywallet_crypto::rpc::NetworkId,
        method: &str,
        params: Value,
    ) -> Result<T, String> {
        let value = self
            .transport
            .json_rpc(network, method, params)
            .await
            .map_err(transport_message)?;
        serde_json::from_value(value)
            .map_err(|e| format!("wallet RPC invalid result for {method}: {e}"))
    }

    /// REST GET returning the raw body.
    pub(crate) async fn rest_get_text(
        &self,
        chain: WalletChain,
        path: &str,
    ) -> Result<String, String> {
        self.transport
            .rest_get(Self::network_id(chain, None), path)
            .await
            .map_err(transport_message)
    }

    /// REST GET decoding a JSON body.
    pub(crate) async fn rest_get_json<T: DeserializeOwned>(
        &self,
        chain: WalletChain,
        path: &str,
    ) -> Result<T, String> {
        let body = self.rest_get_text(chain, path).await?;
        serde_json::from_str(&body)
            .map_err(|e| format!("wallet REST GET decode failed: {e}; body={body}"))
    }

    /// REST POST with a raw text body.
    pub(crate) async fn rest_post_text(
        &self,
        chain: WalletChain,
        path: &str,
        body: &str,
        content_type: &str,
    ) -> Result<String, String> {
        self.transport
            .rest_post(
                Self::network_id(chain, None),
                path,
                body.to_string(),
                content_type,
            )
            .await
            .map_err(transport_message)
    }

    /// REST POST with a JSON body, decoding a JSON reply.
    pub(crate) async fn rest_post_json<T: DeserializeOwned>(
        &self,
        chain: WalletChain,
        path: &str,
        body: &Value,
    ) -> Result<T, String> {
        let text = self
            .rest_post_text(chain, path, &body.to_string(), "application/json")
            .await?;
        serde_json::from_str(&text)
            .map_err(|e| format!("wallet REST POST decode failed: {e}; body={text}"))
    }
}
