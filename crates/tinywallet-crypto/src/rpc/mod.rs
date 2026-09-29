//! The network seam: [`Transport`], the trait a host implements so this crate
//! can reach a chain without owning an HTTP client.
//!
//! Everything else in `tinywallet` is a pure function. Chain work is not — a
//! balance, a nonce, a UTXO set and a broadcast all require a network round
//! trip — so the chain modules take a `&dyn Transport` and the host supplies
//! it.
//!
//! ## What the host keeps, and why the trait names a network rather than a URL
//!
//! No method here accepts a URL. That is the whole point of the seam: endpoint
//! selection is a host concern that this crate must not quietly take over.
//! A host typically resolves an endpoint from its own config, allows an
//! operator to override it per chain, fails over across an ordered list when
//! one is unreachable, and redacts the URL before it reaches a log. Every one
//! of those depends on the host's configuration and deployment, and a crate
//! that hardcoded even a default endpoint would silently route a user's
//! transactions through whichever provider this crate's author happened to
//! pick.
//!
//! So the division is:
//!
//! | This crate | The host |
//! | --- | --- |
//! | which RPC method, with which params | which endpoint answers it |
//! | how to encode and sign the payload | failover, retries, timeouts |
//! | what a response means | connection pooling, TLS, redaction in logs |
//!
//! ## Errors are split by retryability, and that distinction is load-bearing
//!
//! [`TransportError`] separates an endpoint being unreachable from a healthy
//! endpoint returning an authoritative error. A host that fails over across
//! endpoints must advance on the first and stop dead on the second: retrying a
//! genuine "insufficient funds" against three more endpoints yields the same
//! answer three more times, and — far worse — retrying an *ambiguous* failure
//! risks broadcasting a transaction twice. Collapsing the two into one error
//! type is how a failover loop turns a declined transaction into a
//! double-spend, so the distinction is in the type rather than left to a
//! string match on the message.

use async_trait::async_trait;
use serde_json::Value;

use crate::chain::Chain;

/// Identifies which network a request is bound for.
///
/// A bare [`Chain`] is not enough for EVM: Ethereum, Base, Polygon and Arbitrum
/// share an address format and an RPC dialect but are different networks with
/// different endpoints. The EIP-155 chain id is the universal discriminator, so
/// it is what this carries — a host's own network enum does not have to leak
/// into this crate for it to say which network it meant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId {
    /// The chain family.
    pub chain: Chain,
    /// EIP-155 chain id, for [`Chain::Evm`] only.
    ///
    /// `None` on every other chain, and on EVM when the caller genuinely means
    /// "the host's default EVM network" rather than a specific one.
    pub evm_chain_id: Option<u64>,
}

impl NetworkId {
    /// A non-EVM network, identified by its chain alone.
    #[must_use]
    pub const fn chain(chain: Chain) -> Self {
        Self {
            chain,
            evm_chain_id: None,
        }
    }

    /// A specific EVM network, by EIP-155 chain id.
    #[must_use]
    pub const fn evm(chain_id: u64) -> Self {
        Self {
            chain: Chain::Evm,
            evm_chain_id: Some(chain_id),
        }
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.evm_chain_id {
            Some(id) => write!(f, "{}:{id}", self.chain),
            None => write!(f, "{}", self.chain),
        }
    }
}

/// A transport failure, split by whether retrying elsewhere could help.
///
/// See the module docs: this distinction is what lets a host fail over safely,
/// and collapsing it is how a retry loop causes a double broadcast.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// The endpoint could not be reached or did not answer usefully — DNS
    /// failure, connection refused, a timeout, a 5xx, an unparseable body.
    ///
    /// **Safe to retry against another endpoint** *for a read*. A host must
    /// still not blindly retry a broadcast on this: a request that timed out
    /// may well have been accepted.
    #[error("transport failure contacting {network}: {message}")]
    Unreachable {
        /// The network the request was bound for.
        network: NetworkId,
        /// What went wrong.
        message: String,
    },

    /// A healthy endpoint answered with an error — an invalid transaction,
    /// insufficient funds, a rejected signature, a malformed request.
    ///
    /// **Never retry this elsewhere.** It is the network's real answer, and
    /// another endpoint will give the same one.
    #[error("{network} returned an error: {message}")]
    Rpc {
        /// The network that answered.
        network: NetworkId,
        /// The error the node reported.
        message: String,
    },
}

impl TransportError {
    /// Whether trying a different endpoint could plausibly produce a different
    /// answer.
    ///
    /// True only for [`TransportError::Unreachable`]. Note this answers
    /// "could the *result* differ", not "is retrying safe" — a broadcast that
    /// timed out may already have been accepted, so a host must decide that
    /// separately.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Unreachable { .. })
    }

    /// The network this failure relates to.
    #[must_use]
    pub const fn network(&self) -> NetworkId {
        match self {
            Self::Unreachable { network, .. } | Self::Rpc { network, .. } => *network,
        }
    }
}

/// Result alias for transport operations.
pub type TransportResult<T> = std::result::Result<T, TransportError>;

/// The network seam a host implements.
///
/// Implementations are shared across concurrent chain operations, hence
/// `Send + Sync`. A host is expected to hold one long-lived HTTP client behind
/// this rather than building one per call, since rebuilding a TLS connector
/// per request also discards connection pooling.
///
/// # Implementing
///
/// ```
/// use async_trait::async_trait;
/// use serde_json::Value;
/// use tinywallet_bus::rpc::{NetworkId, Transport, TransportError, TransportResult};
///
/// struct MyTransport;
///
/// #[async_trait]
/// impl Transport for MyTransport {
///     async fn json_rpc(
///         &self,
///         network: NetworkId,
///         method: &str,
///         _params: Value,
///     ) -> TransportResult<Value> {
///         // Resolve `network` to an endpoint from your own config, POST the
///         // JSON-RPC envelope, and map a node-level `error` member onto
///         // TransportError::Rpc rather than Unreachable.
///         Err(TransportError::Unreachable {
///             network,
///             message: format!("{method}: not wired up"),
///         })
///     }
///
///     async fn rest_get(&self, network: NetworkId, path: &str) -> TransportResult<String> {
///         Err(TransportError::Unreachable { network, message: path.to_string() })
///     }
///
///     async fn rest_post(
///         &self,
///         network: NetworkId,
///         path: &str,
///         _body: String,
///         _content_type: &str,
///     ) -> TransportResult<String> {
///         Err(TransportError::Unreachable { network, message: path.to_string() })
///     }
/// }
/// ```
#[async_trait]
pub trait Transport: Send + Sync {
    /// Perform a JSON-RPC call and return the `result` member.
    ///
    /// Used by EVM and Solana. The implementation wraps `method` and `params`
    /// in the JSON-RPC envelope, sends it to whichever endpoint serves
    /// `network`, and returns the `result` member on success.
    ///
    /// # Errors
    ///
    /// [`TransportError::Rpc`] when the node answers with an `error` member —
    /// this is an authoritative answer and must not be retried elsewhere.
    /// [`TransportError::Unreachable`] for anything that prevented getting an
    /// answer at all.
    async fn json_rpc(
        &self,
        network: NetworkId,
        method: &str,
        params: Value,
    ) -> TransportResult<Value>;

    /// Perform a REST GET and return the raw body.
    ///
    /// Used by Bitcoin (Esplora) and Tron (`TronGrid`), whose APIs are REST
    /// rather than JSON-RPC. `path` is relative to whatever base the host has
    /// configured for `network`, without a leading slash.
    ///
    /// # Errors
    ///
    /// As [`Transport::json_rpc`]. A non-2xx status is
    /// [`TransportError::Rpc`] when the body carries the API's own error and
    /// [`TransportError::Unreachable`] when it does not.
    async fn rest_get(&self, network: NetworkId, path: &str) -> TransportResult<String>;

    /// Perform a REST POST and return the raw body.
    ///
    /// `path` is relative to the host's configured base for `network`, without
    /// a leading slash. `content_type` is passed because these APIs are not
    /// uniform: Esplora takes a raw transaction as `text/plain`, while
    /// `TronGrid` expects `application/json`.
    ///
    /// # Errors
    ///
    /// As [`Transport::json_rpc`].
    async fn rest_post(
        &self,
        network: NetworkId,
        path: &str,
        body: String,
        content_type: &str,
    ) -> TransportResult<String>;
}

/// Deserialize a JSON-RPC `result` into a typed value.
///
/// A small helper so every chain module does not repeat the same
/// `serde_json::from_value` plus error-mapping dance. A body that does not
/// match the expected shape is [`TransportError::Rpc`], not `Unreachable`:
/// the endpoint answered, it simply did not answer what was asked, and
/// retrying elsewhere will not fix a schema mismatch.
///
/// # Errors
///
/// [`TransportError::Rpc`] if `value` does not deserialize into `T`.
pub fn decode<T: serde::de::DeserializeOwned>(
    network: NetworkId,
    method: &str,
    value: Value,
) -> TransportResult<T> {
    serde_json::from_value(value).map_err(|e| TransportError::Rpc {
        network,
        message: format!("{method}: unexpected response shape: {e}"),
    })
}

#[cfg(test)]
mod test;
