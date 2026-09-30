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
use crate::session::{NoSession, SessionScope};
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
    session: Arc<dyn SessionScope>,
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
        Self {
            payments,
            proxy,
            session: Arc::new(NoSession),
        }
    }

    /// Stamp payments with the session `session` reports as active.
    ///
    /// Without this, or when the scope reports no session, a payment is
    /// attributed to the ledger's own session.
    #[must_use]
    pub fn with_session_scope(mut self, session: Arc<dyn SessionScope>) -> Self {
        self.session = session;
        self
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

    fn name(&self) -> &'static str {
        "x402_request"
    }

    fn description(&self) -> &'static str {
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
        Ok(match Call::parse(&args) {
            Ok(call) => self.run(&call).await,
            Err(refusal) => ToolResult::error(refusal),
        })
    }
}

/// One parsed `x402_request` invocation.
struct Call {
    url: String,
    method: reqwest::Method,
    headers: Vec<(String, String)>,
    body: Option<String>,
}

impl Call {
    /// Read the arguments, or the refusal message to hand back to the model.
    fn parse(args: &serde_json::Value) -> Result<Self, String> {
        let Some(url) = args.get("url").and_then(|v| v.as_str()).map(String::from) else {
            return Err("Missing required 'url' parameter".to_string());
        };
        let method_str = args.get("method").and_then(|v| v.as_str()).unwrap_or("GET");
        let Ok(method) = method_str.parse::<reqwest::Method>() else {
            return Err(format!("Unsupported HTTP method: {method_str}"));
        };
        Ok(Self {
            url,
            method,
            headers: parse_header_args(args.get("headers")),
            body: args.get("body").and_then(|v| v.as_str()).map(String::from),
        })
    }

    async fn send(
        &self,
        client: &reqwest::Client,
        extra_headers: Option<(&str, &str)>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        send_request(
            client,
            &self.method,
            &self.url,
            &self.headers,
            extra_headers,
            self.body.as_deref(),
        )
        .await
    }
}

impl X402RequestTool {
    /// The whole loop: ask, and if the answer is a 402, pay and ask again.
    async fn run(&self, call: &Call) -> ToolResult {
        debug!("{LOG_PREFIX} requesting {} {}", call.method, call.url);

        // Step 1: initial request to get the 402 challenge.
        let client = match self.build_client() {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("Failed to build HTTP client: {e}")),
        };
        let initial_response = match call.send(&client, None).await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("Initial request failed: {e}")),
        };

        // Not a 402: return it directly.
        if initial_response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            let status = initial_response.status().as_u16();
            debug!("{LOG_PREFIX} got {status} (not 402), returning directly");
            return format_response(initial_response, &call.url).await;
        }

        // Step 2: the challenge must be there.
        let initial_headers = initial_response.headers().clone();
        if initial_headers.get(HEADER_PAYMENT_REQUIRED).is_none()
            && initial_headers.get(HEADER_PAYMENT_REQUIRED_V1).is_none()
        {
            return ToolResult::error(
                "Server returned 402 but without a PAYMENT-REQUIRED header — not an x402 endpoint",
            );
        }
        debug!("{LOG_PREFIX} got 402 with PAYMENT-REQUIRED header, processing payment");

        self.pay_and_retry(call, &client, &initial_headers).await
    }

    /// Steps 3 to 6: build and sign the payment, record it, retry with the
    /// proof, settle the record and format the answer.
    async fn pay_and_retry(
        &self,
        call: &Call,
        client: &reqwest::Client,
        challenge_headers: &reqwest::header::HeaderMap,
    ) -> ToolResult {
        let url = &call.url;

        // Step 3: build and sign the payment.
        let payment = match handle_402_and_pay(self.payments.as_ref(), challenge_headers, url).await
        {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("x402 payment failed: {e}")),
        };
        // The hold on the budget, kept until the outcome is recorded below.
        let reservation = payment.reservation;
        let amount_display = format_usdc(payment.amount_atomic);
        debug!(
            "{LOG_PREFIX} payment built: {amount_display} to {} on {} for {url}",
            payment.recipient, payment.network
        );

        // The session the payment is attributed to: the host's active one, or
        // the ledger's own when the call runs outside any session. Read here, on
        // the tool's own task, where a host's task-local is still in scope.
        let session_id = self.session.current_session().unwrap_or_else(|| {
            ledger::with_ledger(|l| l.session_id().to_string()).unwrap_or_default()
        });

        // Record the pending payment. Every later state is a new line with the
        // same id.
        let record_id = uuid::Uuid::new_v4().to_string();
        let record = |status: PaymentStatus, tx_signature: Option<String>| PaymentRecord {
            id: record_id.clone(),
            url: url.clone(),
            asset: payment.asset.clone(),
            amount_atomic: payment.amount_atomic,
            amount_display: amount_display.clone(),
            recipient: payment.recipient.clone(),
            network: payment.network.clone(),
            tx_signature,
            status,
            timestamp: chrono::Utc::now(),
            session_id: session_id.clone(),
        };
        let _ = ledger::with_ledger_mut(|l| l.record_payment(record(PaymentStatus::Pending, None)));

        // Step 4: retry with the payment signature.
        let paid_response = match call
            .send(
                client,
                Some((HEADER_PAYMENT_SIGNATURE, payment.header_value.as_str())),
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                reservation.commit(record(PaymentStatus::Failed, None));
                return ToolResult::error(format!("x402 retry request failed: {e}"));
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
        // Recording the outcome and ending the budget hold are one step, so the
        // amount is counted exactly once at every instant.
        reservation.commit(record(settled_status, tx_sig.clone()));

        if settled_status == PaymentStatus::Settled {
            debug!("{LOG_PREFIX} payment settled for {url} tx={tx_sig:?} amount={amount_display}");
        } else {
            log::warn!(
                "{LOG_PREFIX} payment failed for {url} status={}",
                paid_response.status()
            );
        }

        // Step 6: format and return the response with the payment metadata.
        format_response_with_payment(
            paid_response,
            url,
            &amount_display,
            &payment.network,
            tx_sig.as_deref(),
        )
        .await
    }
}

/// `0.002500 USDC` for `2500`.
#[allow(clippy::cast_precision_loss)] // atomic USDC amounts stay far below 2^53
pub(super) fn format_usdc(amount_atomic: u64) -> String {
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
    extra_header: Option<(&str, &str)>,
    body: Option<&str>,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut request = client.request(method.clone(), url);
    for (key, value) in headers {
        request = request.header(key, value);
    }
    if let Some((key, value)) = extra_header {
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

pub(super) async fn format_response_with_payment(
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
