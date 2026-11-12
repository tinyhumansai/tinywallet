//! Typed callbacks the wallet implementation asks its host to perform.
//!
//! The module owns wallet, quote, payment, budget, and ledger algorithms. The
//! host supplies custody, explicit authorization, endpoint policy, and the
//! authenticated transports those algorithms use.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Chain;

use super::{HostEndpointReference, RpcEndpointKey, SecretMaterial, SolanaCluster};

/// Host approval result for the exact transaction facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationResult {
    /// Whether the host authorized this transaction.
    pub approved: bool,
    /// Optional refusal reason safe to show the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Network identity selected by the wallet algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRequest {
    /// Chain family.
    pub chain: Chain,
    /// EIP-155 id for an EVM network. None means host default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_chain_id: Option<u64>,
    /// Opaque service-scoped host endpoint reference for a configured
    /// override. The host resolves it to a URL without returning that URL to
    /// the module.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_ref: Option<String>,
    /// Public module-selected RPC URL when no host override is configured.
    /// This is never populated together with `endpoint_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_url: Option<String>,
}

/// Chain transport operation. Endpoint resolution, failover, authentication,
/// proxy rules and connection pooling remain host-owned.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainTransportRequest {
    /// JSON-RPC call with method and parameters chosen by the wallet algorithm.
    JsonRpc {
        /// Target network.
        network: NetworkRequest,
        /// JSON-RPC method.
        method: String,
        /// JSON-RPC positional or named parameters.
        params: Value,
    },
    /// REST read from a chain provider using a relative provider path.
    RestGet {
        /// Target network.
        network: NetworkRequest,
        /// Provider-relative path, without a leading slash.
        path: String,
    },
    /// REST submission to a chain provider.
    RestPost {
        /// Target network.
        network: NetworkRequest,
        /// Provider-relative path, without a leading slash.
        path: String,
        /// Request body.
        body: String,
        /// MIME type of body.
        content_type: String,
    },
}

/// Chain transport result retaining the retry distinction required for safe
/// host failover.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ChainTransportResult {
    /// An authoritative provider response.
    Ok {
        /// JSON value or raw REST body.
        body: Value,
    },
    /// Provider could not be reached or returned no useful response.
    Unreachable {
        /// Safe-to-retry failure description.
        message: String,
    },
    /// Provider returned an authoritative error; do not retry elsewhere.
    RpcError {
        /// Provider error description.
        message: String,
    },
}

/// Authenticated `TinyHumans` wallet backend operation. The host executes only
/// the named HTTP service call; the module constructs and interprets payloads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WalletBackendRequest {
    /// Read supported routes.
    Routes,
    /// Ask for one single-chain swap quote.
    SwapTransaction {
        /// Backend request body assembled by the wallet algorithm.
        body: Value,
    },
    /// Ask for one cross-chain bridge quote.
    BridgeTransaction {
        /// Backend request body assembled by the wallet algorithm.
        body: Value,
    },
}

/// Result from the host's authenticated wallet-backend transport.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletBackendResponse {
    /// Response payload as returned by the backend's data field.
    pub data: Value,
}

/// Current account facts needed by wallet algorithms, without secret material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAccountInfo {
    /// Chain family name from `TinyWallet`'s stable wire vocabulary.
    pub chain: crate::Chain,
    /// Chain address.
    pub address: String,
    /// Derivation path associated with the account.
    pub derivation_path: String,
}

/// Account state the host reports to the module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WalletAccountsResponse {
    /// Whether wallet setup completed.
    pub configured: bool,
    /// Available public accounts.
    pub accounts: Vec<WalletAccountInfo>,
}

/// Workspace and budget policy supplied by the composing host when it opens
/// an x402 service. Reconfiguration closes the prior service first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ConfigResponse {
    /// Retained for wire compatibility. The ledger persists through the storage
    /// ports the host provisions, not a file under this directory.
    pub workspace_dir: String,
    /// Stable process session identifier used for ledger attribution.
    pub session_id: String,
    /// Maximum one payment in atomic USDC units.
    pub per_request_max_atomic: u64,
    /// Daily settled-payment budget in atomic USDC units.
    pub daily_max_atomic: u64,
    /// Monthly settled-payment budget in atomic USDC units.
    pub monthly_max_atomic: u64,
}

/// Open or replace the module's active x402 service with host-owned policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ConfigureRequest {
    /// Workspace and spending policy for the new service.
    pub config: X402ConfigResponse,
}

/// Opaque module-issued capability for one configured x402 service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ServiceHandle {
    /// Must accompany every operation on this configured service.
    pub handle: String,
}

/// Quote owner stamped by the composing host before it crosses into the
/// module. `TinyBus` callbacks cannot inherit the caller's task-local state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuoteOwner {
    /// Conversation or job identifier.
    pub thread_id: String,
    /// Client or connection identifier that owns the thread.
    pub client_id: String,
}

/// Opaque module-issued capability for one configured Web3 quote service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ServiceHandle {
    /// Must accompany quote preparation and execution requests.
    pub handle: String,
}

/// Host-owned Web3 endpoint and cluster policy, without endpoint URLs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Web3ConfigureRequest {
    /// Solana cluster; it selects the RPC default and module-owned reference data.
    pub solana_cluster: SolanaCluster,
    /// Endpoints overridden in the host configuration.
    pub overridden_endpoints: Vec<RpcEndpointKey>,
}

/// Service handle and opaque endpoint references to bind in the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Web3ConfigureResponse {
    /// Handle for all later operations.
    pub service: Web3ServiceHandle,
    /// Opaque references for the overridden endpoints; contains no URLs.
    pub endpoint_references: Vec<HostEndpointReference>,
}

/// Close one Web3 quote service and discard its unexecuted quotes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3CloseRequest {
    /// Handle returned by `Web3Configure`.
    pub service: Web3ServiceHandle,
}

/// Generic quote parameters plus the caller identity needed for module-owned
/// quote isolation. The operation-specific schema is validated in `TinyWallet`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3QuoteRequest {
    /// Handle returned by `Web3Configure`.
    pub service: Web3ServiceHandle,
    /// Quote owner, absent for direct non-conversation calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<QuoteOwner>,
    /// Operation-specific parameters decoded by the owning web3 service.
    pub params: Value,
}

/// The operation kind for a prepared Web3 quote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Web3QuoteKind {
    /// A single-chain swap.
    Swap,
    /// A cross-chain bridge.
    Bridge,
    /// A generic contract call.
    DappCall,
}

/// Public summary and authoritative signer chain for a prepared quote.
///
/// `signing_chain` is derived by the module from its stored unsigned
/// transaction. Hosts must use it to select confidential key material rather
/// than infer a signer from the provider response in `quote`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Web3QuoteResponse {
    /// The id to confirm and execute with.
    pub quote_id: String,
    /// The kind of operation.
    pub kind: Web3QuoteKind,
    /// When the quote stops being executable, in milliseconds since the epoch.
    pub expires_at_ms: u64,
    /// The chain whose key must sign the stored transaction.
    pub signing_chain: super::WalletChain,
    /// Provider quote passthrough or the module-owned dapp summary.
    pub quote: Value,
}

/// Quote execution request. Secret material is delivered only on the
/// confidential wallet interface member.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Web3ExecuteRequest {
    /// Handle returned by `Web3Configure`.
    pub service: Web3ServiceHandle,
    /// Quote owner supplied by the caller for owner-gated execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<QuoteOwner>,
    /// Prepared quote identifier.
    pub quote_id: String,
    /// Must be true to cross the explicit confirmation boundary.
    pub confirmed: bool,
    /// Key material held by the host and released only to an attested module.
    pub secret: SecretMaterial,
}

/// Exact transaction intent the module asks the host to approve before
/// signing. The module builds these facts from its stored quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Web3ExecutionIntent {
    /// EVM transaction fields, including the node-derived values used to sign.
    Evm {
        /// The selected network name.
        network: String,
        /// Destination address.
        to: String,
        /// Optional call data.
        data: Option<String>,
        /// Native value in wei.
        value: String,
        /// Nonce read for this exact signing attempt.
        nonce: u64,
        /// Gas limit estimated for this exact signing attempt.
        gas_limit: u64,
        /// Gas price in wei for this exact signing attempt.
        gas_price_wei: String,
        /// EIP-155 chain id.
        chain_id: u64,
    },
    /// Fully specified unsigned Solana transaction bytes.
    Solana {
        /// Hex encoded versioned transaction.
        tx_blob_hex: String,
    },
}

/// Approval request for one stored Web3 quote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeWeb3ExecutionRequest {
    /// Prepared quote identifier.
    pub quote_id: String,
    /// Operation represented by the quote.
    pub operation: String,
    /// Exact module-built transaction intent.
    pub transaction: Web3ExecutionIntent,
}

/// Host authorization for one exact native wallet transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeNativeWalletExecutionRequest {
    /// Prepared quote identifier.
    pub quote_id: String,
    /// Operation represented by the quote.
    pub operation: String,
    /// Public facts copied from the module's stored quote.
    pub quote: super::PreparedTransaction,
    /// Exact transaction or signing message passed to the module signer.
    pub intent: super::NativeWalletExecutionIntent,
}

/// Exact x402 payment terms approved by the host before module-side signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeX402PaymentRequest {
    /// Resource URL the payment buys access to.
    pub url: String,
    /// CAIP-2 network identifier.
    pub network: String,
    /// Token asset address or mint.
    pub asset: String,
    /// Payment recipient.
    pub recipient: String,
    /// Amount in token atomic units that the signed authorization allows: the
    /// exact price for `exact`, the most that can be charged for `upto`. A
    /// host cap compares against this value.
    pub amount_atomic: u64,
    /// Conversation owner used to route approval to the initiating client.
    /// Older hosts omit this field and retain their existing approval flow.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<QuoteOwner>,
    /// The x402 scheme the payment is signed under: `"exact"`, or `"upto"`,
    /// where `amount_atomic` is a ceiling and the server charges what it
    /// used, from zero up to it. Absent from older modules, which sign only
    /// `exact`. Contract 1.16.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
}

/// Request module-owned parsing and signing for a 402 challenge.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402PreparePaymentRequest {
    /// Handle returned by `X402Configure`.
    pub service: X402ServiceHandle,
    /// URL the payment buys access to.
    pub url: String,
    /// Raw `PAYMENT-REQUIRED` challenge header value.
    pub payment_required: String,
    /// Conversation owner used for ledger attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<QuoteOwner>,
    /// Wallet material consumed only inside the confidential module call.
    pub secret: SecretMaterial,
    /// Additional chain-specific wallet material for module-selected rails.
    /// Older hosts omit this field and keep sending only `secret`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub additional_secrets: Vec<SecretMaterial>,
    /// Pay only on this network. A CAIP-2 chain id (`eip155:8453`) must equal
    /// the option's network; a CAIP-2 namespace without a colon (`eip155`,
    /// `solana`) matches every chain in it. When no option matches, the
    /// request is refused before anything is reserved or signed. `None`, and
    /// older hosts that omit the field, keep the module's own preference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
}

/// Payment proof and pending-ledger handle returned to the host for retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402PreparePaymentResponse {
    /// Module-owned reservation id; the host returns it with the retry result.
    pub payment_id: String,
    /// Encoded value for the `PAYMENT-SIGNATURE` request header.
    pub payment_header: String,
    /// Payment amount, in token atomic units.
    pub amount_atomic: u64,
    /// Token asset paid.
    pub asset: String,
    /// Payment recipient.
    pub recipient: String,
    /// CAIP-2 network identifier.
    pub network: String,
}

/// Sign an x402 `sign-in-with-x` challenge with the wallet's EVM account.
///
/// The module signs only an EIP-4361 sign-in built from the challenge, and
/// only when its `domain` is the host of `url`, its `uri` and `resources` are
/// HTTPS on that origin, and its `expirationTime` is still ahead. It is not a
/// way to sign other text.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402SignInRequest {
    /// The URL whose 402 response carried the challenge.
    pub url: String,
    /// Raw `PAYMENT-REQUIRED` header value (base64 JSON) of that response.
    pub payment_required: String,
    /// The EVM wallet material, consumed only inside the confidential call.
    pub secret: SecretMaterial,
}

/// The signed sign-in for the host's retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402SignInResponse {
    /// Value for the `SIGN-IN-WITH-X` request header.
    pub header: String,
    /// The account that signed in, EIP-55 checksummed.
    pub address: String,
    /// The CAIP-2 chain the sign-in names, such as `eip155:8453`.
    pub chain_id: String,
}

/// Record the outcome after the host retries with the module-built proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402RecordPaymentRequest {
    /// Handle returned by `X402Configure`.
    pub service: X402ServiceHandle,
    /// Pending id returned by the preparation operation.
    pub payment_id: String,
    /// HTTP status from the paid retry.
    pub response_status: u16,
    /// Raw optional `PAYMENT-RESPONSE` settlement header value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_response: Option<String>,
}

/// Close the active x402 service and release any uncommitted reservations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402CloseRequest {
    /// Handle returned by `X402Configure`.
    pub service: X402ServiceHandle,
}

/// Read ledger totals for one configured x402 service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402SummaryRequest {
    /// Handle returned by `X402Configure`.
    pub service: X402ServiceHandle,
}

/// Read the newest payment records from one configured x402 service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ListPaymentsRequest {
    /// Handle returned by `X402Configure`.
    pub service: X402ServiceHandle,
    /// Maximum records to return, newest first.
    pub limit: u64,
}

/// Current public ledger facts for one x402 payment attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct X402PaymentRecord {
    /// Unique id of the attempt. A status change is a new row with the same id.
    pub id: String,
    /// URL the payment bought access to.
    pub url: String,
    /// Token mint or contract address paid.
    pub asset: String,
    /// Amount in token atomic units.
    pub amount_atomic: u64,
    /// Human-readable amount.
    pub amount_display: String,
    /// Payment recipient.
    pub recipient: String,
    /// CAIP-2 network identifier.
    pub network: String,
    /// Settlement transaction, when reported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_signature: Option<String>,
    /// Current payment lifecycle state.
    pub status: X402PaymentStatus,
    /// RFC3339 timestamp of this state.
    pub timestamp: String,
    /// End of the exported authorization window, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_valid_until: Option<String>,
    /// Solana's last valid block height, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana_last_valid_block_height: Option<u64>,
    /// Time when a finalized Solana height proved the authorization expired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_expired_at: Option<String>,
    /// Finalized height supporting the expiry observation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_expiry_observed_height: Option<u64>,
    /// Ledger session that made the payment.
    pub session_id: String,
    /// Conversation thread that requested the payment, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
}

/// State of one x402 payment record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum X402PaymentStatus {
    /// Signed and sent, with no confirmed settlement result yet.
    Pending,
    /// A trusted settlement receipt confirms payment.
    Settled,
    /// The payment did not settle or was rejected.
    Failed,
    /// The request was refused before signing.
    Denied,
}

/// Result of listing recent x402 payment records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402ListPaymentsResponse {
    /// Records newest first.
    pub payments: Vec<X402PaymentRecord>,
}

/// Update limits on one active x402 service without replacing its ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402UpdateBudgetRequest {
    /// Handle returned by `X402Configure`.
    pub service: X402ServiceHandle,
    /// New per-request limit in atomic units, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_request_max_atomic: Option<u64>,
    /// New daily limit in atomic units, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daily_max_atomic: Option<u64>,
    /// New monthly limit in atomic units, when supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_max_atomic: Option<u64>,
}

/// Module-owned budget and ledger summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402SpendingSummary {
    /// Settled amount for the current ledger session.
    pub session_total_atomic: u64,
    /// Settled amount today (UTC).
    pub daily_total_atomic: u64,
    /// Settled amount this month (UTC).
    pub monthly_total_atomic: u64,
    /// Current in-flight budget reservations.
    pub reserved_atomic: u64,
    /// Current per-request ceiling.
    pub per_request_max_atomic: u64,
    /// Current daily ceiling.
    pub daily_max_atomic: u64,
    /// Current monthly ceiling.
    pub monthly_max_atomic: u64,
}

/// Complete x402 ledger totals, including counts retained by the host RPC API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct X402DetailedSpendingSummary {
    /// Settled amount for the current ledger session.
    pub session_total_atomic: u64,
    /// Settled amount today (UTC).
    pub daily_total_atomic: u64,
    /// Settled amount this month (UTC).
    pub monthly_total_atomic: u64,
    /// Settled payment count for the current ledger session.
    pub session_count: u64,
    /// Settled payment count today.
    pub daily_count: u64,
    /// Settled payment count this month.
    pub monthly_count: u64,
    /// Current in-flight budget reservations.
    pub reserved_atomic: u64,
    /// Current per-request ceiling.
    pub per_request_max_atomic: u64,
    /// Current daily ceiling.
    pub daily_max_atomic: u64,
    /// Current monthly ceiling.
    pub monthly_max_atomic: u64,
}

/// One typed host callback response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
pub enum HostResponse {
    /// Public account facts.
    WalletAccounts(WalletAccountsResponse),
    /// Approval decision.
    Authorization(AuthorizationResult),
    /// Chain provider result.
    ChainTransport(ChainTransportResult),
    /// Authenticated backend response.
    WalletBackend(WalletBackendResponse),
}
