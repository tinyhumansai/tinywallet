//! A [`Web3Backend`] with scripted replies and a request log.

use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::Value;

use crate::crypto::seams::Web3Backend;

/// Scripted backend: each operation answers what a test set, or fails.
#[derive(Default)]
pub(crate) struct FakeBackend {
    routes: Mutex<Option<Result<Value, String>>>,
    swap: Mutex<Option<Result<Value, String>>>,
    bridge: Mutex<Option<Result<Value, String>>>,
    requests: Mutex<Vec<(String, Value)>>,
}

impl FakeBackend {
    /// Script the `routes` reply.
    pub(crate) fn set_routes(&self, reply: Result<Value, String>) {
        *self.routes.lock() = Some(reply);
    }

    /// Script the `swap_tx` reply.
    pub(crate) fn set_swap(&self, reply: Result<Value, String>) {
        *self.swap.lock() = Some(reply);
    }

    /// Script the `bridge_tx` reply.
    pub(crate) fn set_bridge(&self, reply: Result<Value, String>) {
        *self.bridge.lock() = Some(reply);
    }

    /// The `(operation, body)` pairs the service sent.
    pub(crate) fn requests(&self) -> Vec<(String, Value)> {
        self.requests.lock().clone()
    }

    fn answer(slot: &Mutex<Option<Result<Value, String>>>) -> Result<Value, String> {
        slot.lock()
            .clone()
            .unwrap_or_else(|| Err("no scripted backend reply".to_string()))
    }
}

#[async_trait]
impl Web3Backend for FakeBackend {
    async fn routes(&self) -> Result<Value, String> {
        self.requests
            .lock()
            .push(("routes".to_string(), Value::Null));
        Self::answer(&self.routes)
    }

    async fn swap_tx(&self, body: &Value) -> Result<Value, String> {
        self.requests
            .lock()
            .push(("swap".to_string(), body.clone()));
        Self::answer(&self.swap)
    }

    async fn bridge_tx(&self, body: &Value) -> Result<Value, String> {
        self.requests
            .lock()
            .push(("bridge".to_string(), body.clone()));
        Self::answer(&self.bridge)
    }
}
