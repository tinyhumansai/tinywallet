//! A loopback x402 server: answers 402 with a challenge until it sees a
//! `PAYMENT-SIGNATURE`, then answers with a configurable settlement.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;

use crate::wire::{HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SIGNATURE, PaymentRequired};

/// What the server does.
#[derive(Debug, Clone)]
pub(crate) struct ServerConfig {
    /// The challenge sent with a 402; `None` makes the server answer 200 always.
    pub(crate) challenge: Option<PaymentRequired>,
    /// The header name the challenge travels in.
    pub(crate) challenge_header: &'static str,
    /// Send the 402 without any challenge header.
    pub(crate) omit_challenge_header: bool,
    /// The status answered once a payment header arrives.
    pub(crate) paid_status: u16,
    /// The raw `PAYMENT-RESPONSE` header value sent with the paid response.
    pub(crate) receipt: Option<String>,
    /// The body of a paid or free response.
    pub(crate) body: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            challenge: None,
            challenge_header: "PAYMENT-REQUIRED",
            omit_challenge_header: false,
            paid_status: 200,
            receipt: None,
            body: "content".to_string(),
        }
    }
}

/// One request the server saw.
#[derive(Debug, Clone)]
pub(crate) struct RecordedRequest {
    pub(crate) method: Method,
    pub(crate) headers: HeaderMap,
    pub(crate) body: String,
}

impl RecordedRequest {
    /// The `PAYMENT-SIGNATURE` value, if the request carried one.
    pub(crate) fn payment_signature(&self) -> Option<String> {
        self.headers
            .get(HEADER_PAYMENT_SIGNATURE)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    }
}

/// A running loopback server.
#[derive(Debug)]
pub(crate) struct TestServer {
    /// `http://127.0.0.1:<port>`.
    pub(crate) url: String,
    /// Every request seen, in order.
    pub(crate) requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

struct Shared {
    config: ServerConfig,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
}

impl TestServer {
    /// Start a server on an ephemeral loopback port.
    pub(crate) async fn start(config: ServerConfig) -> Self {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let shared = Arc::new(Shared {
            config,
            requests: Arc::clone(&requests),
        });
        let app = Router::new().fallback(any(handle)).with_state(shared);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self {
            url: format!("http://{addr}"),
            requests,
        }
    }

    /// A snapshot of the requests seen so far.
    pub(crate) fn seen(&self) -> Vec<RecordedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

async fn handle(
    State(shared): State<Arc<Shared>>,
    method: Method,
    headers: HeaderMap,
    body: String,
) -> Response {
    let request = RecordedRequest {
        method,
        headers,
        body,
    };
    let paid = request.payment_signature().is_some();
    shared.requests.lock().unwrap().push(request);
    let config = &shared.config;

    let Some(challenge) = &config.challenge else {
        return (StatusCode::OK, config.body.clone()).into_response();
    };
    if paid {
        let mut response = (
            StatusCode::from_u16(config.paid_status).unwrap(),
            config.body.clone(),
        )
            .into_response();
        if let Some(receipt) = &config.receipt {
            response.headers_mut().insert(
                HeaderName::from_static("payment-response"),
                HeaderValue::from_str(receipt).unwrap(),
            );
            debug_assert_eq!(HEADER_PAYMENT_RESPONSE, "PAYMENT-RESPONSE");
        }
        return response;
    }
    let mut response = (StatusCode::PAYMENT_REQUIRED, "pay up").into_response();
    if !config.omit_challenge_header {
        response.headers_mut().insert(
            HeaderName::from_bytes(config.challenge_header.as_bytes()).unwrap(),
            HeaderValue::from_str(&super::challenge_header(challenge)).unwrap(),
        );
    }
    response
}
