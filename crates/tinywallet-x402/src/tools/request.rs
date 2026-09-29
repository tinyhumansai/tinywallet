//! [`X402RequestTool`]: make an HTTP request, pay the 402, return the result.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use log::debug;
use serde_json::json;
use tinytools::{PermissionLevel, Tool, ToolCallOptions, ToolExposure, ToolResult};
use tinywallet_crypto::rpc::Transport;

use crate::crypto::{CryptoPayments, PaymentSigner};
use crate::ledger::{self, PaymentRecord, PaymentStatus};
use crate::protocol::{PaymentBuilder, ProxyPolicy, handle_402_and_pay};
use crate::wire::{
    HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_REQUIRED_V1, HEADER_PAYMENT_RESPONSE,
    HEADER_PAYMENT_SIGNATURE, SettlementResponse,
};

const LOG_PREFIX: &str = "[tool.x402_request]";
const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// The label the proxy policy keys its per-service rules on.
const PROXY_SERVICE: &str = "tool.x402_request";
/// The most response body the tool returns to the model.
const MAX_BODY_BYTES: usize = 50_000;

/// Agent tool for making x402-paid HTTP requests.
#[derive(Clone)]
pub struct X402RequestTool {
    payments: Arc<dyn PaymentBuilder>,
    proxy: Arc<dyn ProxyPolicy>,
}

impl std::fmt::Debug for X402RequestTool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402RequestTool").finish_non_exhaustive()
    }
}

impl X402RequestTool {
    /// A tool that pays on the crypto rail: `signer` signs, `transport` reads
    /// the Solana blockhash, `proxy` shapes outbound HTTP.
    #[must_use]
    pub fn new(
        signer: Arc<dyn PaymentSigner>,
        transport: Arc<dyn Transport>,
        proxy: Arc<dyn ProxyPolicy>,
    ) -> Self {
        Self::with_builder(Arc::new(CryptoPayments::new(signer, transport)), proxy)
    }

    /// A tool that pays through any [`PaymentBuilder`].
    #[must_use]
    pub fn with_builder(payments: Arc<dyn PaymentBuilder>, proxy: Arc<dyn ProxyPolicy>) -> Self {
        Self { payments, proxy }
    }

    fn build_client(&self) -> Result<reqwest::Client, reqwest::Error> {
        let builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::limited(5));
        self.proxy.apply(builder, PROXY_SERVICE).build()
    }
}

#[async_trait]
impl Tool for X402RequestTool {
    fn exposure(&self) -> ToolExposure {
        ToolExposure::Deferred
    }

    fn name(&self) -> &str {
        "x402_request"
    }

    fn description(&self) -> &str {
        "Make an HTTP request to an x402-payable API endpoint. Automatically handles the \
         HTTP 402 payment challenge by signing a payment (EVM EIP-3009 on Base/Ethereum, or \
         Solana SPL transfer) with the wallet and retrying with the payment proof. \
         Returns the API response after payment. Use this for x402-enabled APIs like twit.sh. \
         The wallet must be set up with USDC on the target chain."
    }

    fn parameters_schema(&self) -> serde_json::Value {
        json!({
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the x402-payable API endpoint (e.g. https://x402.twit.sh/tweets/by/id?id=1110302988)"
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method (default: GET)",
                    "default": "GET",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"]
                },
                "headers": {
                    "type": "object",
                    "description": "Optional HTTP headers as key-value pairs",
                    "default": {}
                },
                "body": {
                    "type": "string",
                    "description": "Optional request body (for POST/PUT/PATCH)"
                }
            },
            "required": ["url"]
        })
    }

    fn permission_level(&self) -> PermissionLevel {
        PermissionLevel::Write
    }

    async fn execute(&self, args: serde_json::Value) -> anyhow::Result<ToolResult> {
        self.execute_with_options(args, ToolCallOptions::default())
            .await
    }

    async fn execute_with_options(
        &self,
        args: serde_json::Value,
        _options: ToolCallOptions,
    ) -> anyhow::Result<ToolResult> {
        let Some(url) = args.get("url").and_then(|v| v.as_str()).map(String::from) else {
            return Ok(ToolResult::error("Missing required 'url' parameter"));
        };

        let method_str = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        let Ok(method) = method_str.parse::<reqwest::Method>() else {
            return Ok(ToolResult::error(format!(
                "Unsupported HTTP method: {method_str}"
            )));
        };

        let headers = parse_header_args(args.get("headers"));
        let body = args.get("body").and_then(|v| v.as_str()).map(String::from);

        debug!("{LOG_PREFIX} requesting {method} {url}");

        // Step 1: initial request to get the 402 challenge.
        let client = match self.build_client() {
            Ok(c) => c,
            Err(e) => {
                return Ok(ToolResult::error(format!(
                    "Failed to build HTTP client: {e}"
                )));
            }
        };

        let initial_response =
            match send_request(&client, &method, &url, &headers, body.as_deref()).await {
                Ok(r) => r,
                Err(e) => return Ok(ToolResult::error(format!("Initial request failed: {e}"))),
            };

        // Not a 402: return it directly.
        if initial_response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            let status = initial_response.status().as_u16();
            debug!("{LOG_PREFIX} got {status} (not 402), returning directly");
            return Ok(format_response(initial_response, &url).await);
        }

        // Step 2: the challenge must be there.
        let initial_headers = initial_response.headers().clone();
        if initial_headers.get(HEADER_PAYMENT_REQUIRED).is_none()
            && initial_headers.get(HEADER_PAYMENT_REQUIRED_V1).is_none()
        {
            return Ok(ToolResult::error(
                "Server returned 402 but without a PAYMENT-REQUIRED header — not an x402 endpoint",
            ));
        }

        debug!("{LOG_PREFIX} got 402 with PAYMENT-REQUIRED header, processing payment");

        // Step 3: build and sign the payment.
        let payment_result =
            match handle_402_and_pay(self.payments.as_ref(), &initial_headers, &url).await {
                Ok(r) => r,
                Err(e) => return Ok(ToolResult::error(format!("x402 payment failed: {e}"))),
            };

        let amount_display = format_usdc(payment_result.amount_atomic);
        debug!(
            "{LOG_PREFIX} payment built: {} to {} on {} for {}",
            amount_display, payment_result.recipient, payment_result.network, url
        );

        // Record the pending payment.
        let record_id = uuid::Uuid::new_v4().to_string();
        let record = |status: PaymentStatus, tx_signature: Option<String>| PaymentRecord {
            id: record_id.clone(),
            url: url.clone(),
            asset: payment_result.asset.clone(),
            amount_atomic: payment_result.amount_atomic,
            amount_display: amount_display.clone(),
            recipient: payment_result.recipient.clone(),
            network: payment_result.network.clone(),
            tx_signature,
            status,
            timestamp: chrono::Utc::now(),
            session_id: String::new(),
        };
        let _ = ledger::with_ledger_mut(|l| l.record_payment(record(PaymentStatus::Pending, None)));

        // Step 4: retry with the payment signature.
        let mut retry_headers = headers.clone();
        retry_headers.push((
            HEADER_PAYMENT_SIGNATURE.to_string(),
            payment_result.header_value.clone(),
        ));

        let paid_response =
            match send_request(&client, &method, &url, &retry_headers, body.as_deref()).await {
                Ok(r) => r,
                Err(e) => {
                    let _ = ledger::with_ledger_mut(|l| {
                        l.record_payment(record(PaymentStatus::Failed, None));
                    });
                    return Ok(ToolResult::error(format!("x402 retry request failed: {e}")));
                }
            };

        // Step 5: read the settlement response and update the ledger.
        let settled_status = if paid_response.status().is_success() {
            PaymentStatus::Settled
        } else {
            PaymentStatus::Failed
        };

        let tx_sig = paid_response
            .headers()
            .get(HEADER_PAYMENT_RESPONSE)
            .and_then(|v| v.to_str().ok())
            .and_then(|b64| B64.decode(b64).ok())
            .and_then(|bytes| serde_json::from_slice::<SettlementResponse>(&bytes).ok())
            .and_then(|r| (r.success && !r.transaction.is_empty()).then_some(r.transaction));

        let _ = ledger::with_ledger_mut(|l| {
            l.record_payment(record(settled_status, tx_sig.clone()));
        });

        if settled_status == PaymentStatus::Settled {
            debug!(
                "{LOG_PREFIX} payment settled for {url} tx={:?} amount={}",
                tx_sig, amount_display
            );
        } else {
            log::warn!(
                "{LOG_PREFIX} payment failed for {url} status={}",
                paid_response.status()
            );
        }

        // Step 6: format and return the response with the payment metadata.
        Ok(format_response_with_payment(
            paid_response,
            &url,
            &amount_display,
            &payment_result.network,
            tx_sig.as_deref(),
        )
        .await)
    }
}

/// `0.002500 USDC` for `2500`.
#[allow(clippy::cast_precision_loss)] // atomic USDC amounts stay far below 2^53
fn format_usdc(amount_atomic: u64) -> String {
    format!("{:.6} USDC", amount_atomic as f64 / 1_000_000.0)
}

fn parse_header_args(headers_val: Option<&serde_json::Value>) -> Vec<(String, String)> {
    headers_val
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

async fn send_request(
    client: &reqwest::Client,
    method: &reqwest::Method,
    url: &str,
    headers: &[(String, String)],
    body: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut request = client.request(method.clone(), url);
    for (key, value) in headers {
        request = request.header(key, value);
    }
    if let Some(body_str) = body {
        request = request.body(body_str.to_string());
    }
    request.send().await
}

/// Cut `body` to [`MAX_BODY_BYTES`] on a character boundary.
fn truncate_body(body: String) -> String {
    if body.len() <= MAX_BODY_BYTES {
        return body;
    }
    let mut end = MAX_BODY_BYTES;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…(truncated)", &body[..end])
}

async fn format_response(response: reqwest::Response, url: &str) -> ToolResult {
    let status = response.status().as_u16();
    let body = truncate_body(response.text().await.unwrap_or_default());
    ToolResult::success(format!("HTTP {status} from {url}\n\n{body}"))
}

async fn format_response_with_payment(
    response: reqwest::Response,
    url: &str,
    amount_display: &str,
    network: &str,
    tx_sig: Option<&str>,
) -> ToolResult {
    let status = response.status().as_u16();
    let body = truncate_body(response.text().await.unwrap_or_default());

    let chain_label = if network.starts_with("eip155:8453") {
        "Base"
    } else if network.starts_with("eip155:1") {
        "Ethereum"
    } else if network.starts_with("eip155:") {
        "EVM"
    } else if network.starts_with("solana:") {
        "Solana"
    } else {
        network
    };

    let tx_line = tx_sig
        .map(|sig| format!("\nTransaction: {sig}"))
        .unwrap_or_default();

    ToolResult::success(format!(
        "HTTP {status} from {url}\n\
         x402 payment: {amount_display} on {chain_label}{tx_line}\n\n\
         {body}"
    ))
}
