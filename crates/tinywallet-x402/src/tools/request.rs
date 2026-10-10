//! [`X402RequestTool`]: make an HTTP request, pay the 402, return the result.

use std::net::SocketAddr;
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
use crate::thread::{NoThread, ThreadScope};
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

/// The exact HTTP request proposed by the agent before host policy runs.
#[derive(Debug, Clone)]
pub struct ProposedRequest {
    /// Target URL.
    pub url: String,
    /// HTTP method.
    pub method: reqwest::Method,
    /// Agent-supplied headers.
    pub headers: Vec<(String, String)>,
    /// Optional request body.
    pub body: Option<String>,
}

/// The request content and destination approved by the host. The client pins
/// these addresses so a second DNS lookup cannot change the destination.
#[derive(Debug)]
pub struct AuthorizedRequest {
    /// Request sent on both the initial attempt and the paid retry.
    pub request: ProposedRequest,
    /// Host whose DNS answer was vetted by the host.
    pub host: String,
    /// Approved socket addresses for that host and port.
    pub addrs: Vec<SocketAddr>,
}

/// Compatibility name for the crate-wide authorization error.
pub use crate::Error as RequestAuthorizationError;

/// Host policy for agent-directed HTTP and payment requests.
#[async_trait]
pub trait RequestGuard: Send + Sync {
    /// Whether the host must approve this call before execution.
    fn needs_approval(&self) -> bool;

    /// Enforce action, rate, privacy and URL policy before any HTTP request.
    ///
    /// # Errors
    ///
    /// Returns [`RequestAuthorizationError::Denied`] when host policy rejects
    /// the request, or [`RequestAuthorizationError::InvalidDestination`] when
    /// it cannot supply a safe destination and approved socket addresses.
    async fn authorize(&self, request: &ProposedRequest) -> crate::Result<AuthorizedRequest>;
}

/// Agent tool for making x402-paid HTTP requests.
#[derive(Clone)]
pub struct X402RequestTool {
    payments: Arc<dyn PaymentBuilder>,
    proxy: Arc<dyn ProxyPolicy>,
    thread: Arc<dyn ThreadScope>,
    guard: Option<Arc<dyn RequestGuard>>,
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
            thread: Arc::new(NoThread),
            guard: None,
        }
    }

    /// Record the thread `thread` reports as active in each payment's
    /// `thread_id`.
    ///
    /// Without this, or when the scope reports no thread, `thread_id` is empty.
    /// Either way `session_id` is the ledger's own session.
    #[must_use]
    pub fn with_thread_scope(mut self, thread: Arc<dyn ThreadScope>) -> Self {
        self.thread = thread;
        self
    }

    /// Install the host's network policy. Calls without one fail closed.
    #[must_use]
    pub fn with_request_guard(mut self, guard: Arc<dyn RequestGuard>) -> Self {
        self.guard = Some(guard);
        self
    }

    fn build_client(&self, target: &AuthorizedRequest) -> Result<reqwest::Client, reqwest::Error> {
        let builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(&target.host, &target.addrs);
        // An HTTP proxy resolves the target itself, bypassing the approved
        // socket addresses. Keep other host client settings, but force this
        // guarded request to connect directly to the pinned destination.
        self.proxy.apply(builder, PROXY_SERVICE).no_proxy().build()
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

    fn external_effect_with_args(&self, _args: &serde_json::Value) -> bool {
        self.guard
            .as_ref()
            .is_some_and(|guard| guard.needs_approval())
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
        Ok(match ProposedRequest::parse(&args) {
            Ok(call) => self.run(&call).await,
            Err(refusal) => ToolResult::error(refusal),
        })
    }
}

impl ProposedRequest {
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
    async fn run(&self, call: &ProposedRequest) -> ToolResult {
        debug!("{LOG_PREFIX} requesting {} {}", call.method, call.url);

        let Some(guard) = &self.guard else {
            return ToolResult::error("[policy-blocked] Network policy is unavailable");
        };
        let target = match guard.authorize(call).await {
            Ok(target) if !target.addrs.is_empty() => target,
            Ok(_) => return ToolResult::error("[policy-blocked] No approved destination"),
            Err(reason) => return ToolResult::error(reason.to_string()),
        };
        let Ok(approved_url) = reqwest::Url::parse(&target.request.url) else {
            return ToolResult::error("[policy-blocked] Invalid approved URL");
        };
        let Some(host) = approved_url.host_str() else {
            return ToolResult::error("[policy-blocked] Approved URL has no host");
        };
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let Some(port) = approved_url.port_or_known_default() else {
            return ToolResult::error("[policy-blocked] Approved URL has no port");
        };
        if !host.eq_ignore_ascii_case(&target.host)
            || target.addrs.iter().any(|addr| addr.port() != port)
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| target.addrs.iter().any(|addr| addr.ip() != ip))
        {
            return ToolResult::error("[policy-blocked] Approved destination does not match URL");
        }

        if !self.proxy.allows_direct_connection(PROXY_SERVICE) {
            return ToolResult::error(
                "[policy-blocked] Direct connection is not allowed by the host proxy policy",
            );
        }

        // Step 1: initial request to get the 402 challenge.
        let client = match self.build_client(&target) {
            Ok(c) => c,
            Err(e) => return ToolResult::error(format!("Failed to build HTTP client: {e}")),
        };
        let authorized_call = target.request;
        let initial_response = match authorized_call.send(&client, None).await {
            Ok(r) => r,
            Err(e) => return ToolResult::error(format!("Initial request failed: {e}")),
        };

        // Not a 402: return it directly.
        if initial_response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            let status = initial_response.status().as_u16();
            debug!("{LOG_PREFIX} got {status} (not 402), returning directly");
            return format_response(initial_response, &authorized_call.url).await;
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

        self.pay_and_retry(&authorized_call, &client, &initial_headers)
            .await
    }

    /// Steps 3 to 6: build and sign the payment, record it, retry with the
    /// proof, settle the record and format the answer.
    async fn pay_and_retry(
        &self,
        call: &ProposedRequest,
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

        // `session_id` is always the ledger's own, so the session total counts
        // the payment; `thread_id` is the host's finer attribution. Both are read
        // here, on the tool's own task, where a host's task-local is in scope.
        let session_id = ledger::with_ledger(|l| l.session_id().to_string()).unwrap_or_default();
        let thread_id = self.thread.current_thread();

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
            thread_id: thread_id.clone(),
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
