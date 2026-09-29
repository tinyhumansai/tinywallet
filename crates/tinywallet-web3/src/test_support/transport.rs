//! A [`Transport`] that replays canned answers and logs every call.

use std::collections::HashMap;

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;
use tinywallet_crypto::rpc::{NetworkId, Transport, TransportError, TransportResult};

/// One call the engine made.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Call {
    /// A JSON-RPC call.
    JsonRpc {
        network: NetworkId,
        method: String,
        params: Value,
    },
    /// A REST GET.
    RestGet { network: NetworkId, path: String },
    /// A REST POST.
    RestPost {
        network: NetworkId,
        path: String,
        body: String,
        content_type: String,
    },
}

/// Canned answers per method or path. Each key holds a queue: a call takes the
/// front, and the last answer repeats, so a single canned answer serves every
/// call and a sequence can be scripted.
#[derive(Default)]
pub(crate) struct FakeTransport {
    rpc: Mutex<HashMap<String, Vec<TransportResult<Value>>>>,
    get: Mutex<HashMap<String, Vec<TransportResult<String>>>>,
    post: Mutex<HashMap<String, Vec<TransportResult<String>>>>,
    calls: Mutex<Vec<Call>>,
}

/// Take the next answer for `key`: the front of the queue, or the last one
/// repeated.
fn next<T: Clone>(map: &Mutex<HashMap<String, Vec<T>>>, key: &str) -> Option<T> {
    let mut map = map.lock();
    let queue = map.get_mut(key)?;
    if queue.len() > 1 {
        Some(queue.remove(0))
    } else {
        queue.first().cloned()
    }
}

impl FakeTransport {
    /// Answer JSON-RPC `method` with `result`.
    pub(crate) fn on_rpc(&self, method: &str, result: Value) -> &Self {
        self.rpc
            .lock()
            .entry(method.to_string())
            .or_default()
            .push(Ok(result));
        self
    }

    /// Answer JSON-RPC `method` with a node error.
    pub(crate) fn on_rpc_error(&self, method: &str, message: &str) -> &Self {
        self.rpc
            .lock()
            .entry(method.to_string())
            .or_default()
            .push(Err(TransportError::Rpc {
                network: NetworkId::chain(tinywallet_crypto::Chain::Evm),
                message: message.to_string(),
            }));
        self
    }

    /// Answer REST GET `path` with `body`.
    pub(crate) fn on_get(&self, path: &str, body: &str) -> &Self {
        self.get
            .lock()
            .entry(path.to_string())
            .or_default()
            .push(Ok(body.to_string()));
        self
    }

    /// Answer REST GET `path` with an error whose message is `message`.
    pub(crate) fn on_get_error(&self, path: &str, message: &str) -> &Self {
        self.get
            .lock()
            .entry(path.to_string())
            .or_default()
            .push(Err(TransportError::Rpc {
                network: NetworkId::chain(tinywallet_crypto::Chain::Btc),
                message: message.to_string(),
            }));
        self
    }

    /// Answer REST POST `path` with `body`.
    pub(crate) fn on_post(&self, path: &str, body: &str) -> &Self {
        self.post
            .lock()
            .entry(path.to_string())
            .or_default()
            .push(Ok(body.to_string()));
        self
    }

    /// Answer REST POST `path` with an unreachable-endpoint error.
    pub(crate) fn on_post_unreachable(&self, path: &str, message: &str) -> &Self {
        self.post
            .lock()
            .entry(path.to_string())
            .or_default()
            .push(Err(TransportError::Unreachable {
                network: NetworkId::chain(tinywallet_crypto::Chain::Tron),
                message: message.to_string(),
            }));
        self
    }

    /// Every call made so far, in order.
    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().clone()
    }

    /// The JSON-RPC calls made so far, as `(method, params)`.
    pub(crate) fn rpc_calls(&self) -> Vec<(String, Value)> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::JsonRpc { method, params, .. } => Some((method, params)),
                _ => None,
            })
            .collect()
    }

    /// The params of the first JSON-RPC call to `method`.
    pub(crate) fn first_rpc(&self, method: &str) -> Option<Value> {
        self.rpc_calls()
            .into_iter()
            .find(|(m, _)| m == method)
            .map(|(_, p)| p)
    }

    /// The REST POST bodies sent to `path`.
    pub(crate) fn posts_to(&self, path: &str) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::RestPost { path: p, body, .. } if p == path => Some(body),
                _ => None,
            })
            .collect()
    }

    fn unscripted(network: NetworkId, what: &str) -> TransportError {
        TransportError::Rpc {
            network,
            message: format!("no canned answer for {what}"),
        }
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn json_rpc(
        &self,
        network: NetworkId,
        method: &str,
        params: Value,
    ) -> TransportResult<Value> {
        self.calls.lock().push(Call::JsonRpc {
            network,
            method: method.to_string(),
            params,
        });
        next(&self.rpc, method).unwrap_or_else(|| Err(Self::unscripted(network, method)))
    }

    async fn rest_get(&self, network: NetworkId, path: &str) -> TransportResult<String> {
        self.calls.lock().push(Call::RestGet {
            network,
            path: path.to_string(),
        });
        next(&self.get, path).unwrap_or_else(|| Err(Self::unscripted(network, path)))
    }

    async fn rest_post(
        &self,
        network: NetworkId,
        path: &str,
        body: String,
        content_type: &str,
    ) -> TransportResult<String> {
        self.calls.lock().push(Call::RestPost {
            network,
            path: path.to_string(),
            body,
            content_type: content_type.to_string(),
        });
        next(&self.post, path).unwrap_or_else(|| Err(Self::unscripted(network, path)))
    }
}
