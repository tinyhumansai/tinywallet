//! Shared, transport-only vocabulary for the native wallet engine.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Chain;

use super::{QuoteOwner, SecretMaterial, TransactionSpec};

/// Requests standard ERC-20 `transfer(address,uint256)` calldata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodeErc20TransferRequest {
    /// The 20-byte recipient address, with or without an `0x` prefix.
    pub to_address: String,
    /// The unsigned base-unit amount as a decimal string.
    pub amount_raw: String,
}

/// The module-encoded ERC-20 transfer calldata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncodeErc20TransferResponse {
    /// Hex calldata including the `0x` prefix.
    pub calldata: String,
}

/// Requests a freshly generated BIP-39 recovery phrase.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenerateMnemonicRequest {
    /// Number of words in the phrase; supported values are 12, 15, 18, 21,
    /// and 24.
    pub word_count: u8,
}

/// A new BIP-39 recovery phrase returned to the host for encryption and custody.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerateMnemonicResponse {
    /// The newly generated English recovery phrase. Treat this field as secret.
    pub phrase: String,
    /// Number of words in `phrase`.
    pub word_count: u8,
}

impl std::fmt::Debug for GenerateMnemonicResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenerateMnemonicResponse")
            .field("phrase", &"<redacted>")
            .field("word_count", &self.word_count)
            .finish()
    }
}

/// Requests a BIP-39 seed for a phrase whose storage key must remain compatible.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeriveMnemonicSeedRequest {
    /// Phrase to derive. This field is secret and the call must be confidential.
    pub mnemonic: String,
}

impl std::fmt::Debug for DeriveMnemonicSeedRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeriveMnemonicSeedRequest")
            .field("mnemonic", &"<redacted>")
            .finish()
    }
}

/// Returns the standard 64-byte BIP-39 seed from a confidential call.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeriveMnemonicSeedResponse {
    /// Seed bytes. Treat these as secret key material.
    pub seed: Vec<u8>,
}

impl std::fmt::Debug for DeriveMnemonicSeedResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeriveMnemonicSeedResponse")
            .field("seed", &"<redacted>")
            .finish()
    }
}

/// A wallet chain family.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WalletChain {
    /// An EVM chain.
    Evm,
    /// Bitcoin.
    Btc,
    /// Solana.
    Solana,
    /// Tron.
    Tron,
}

impl WalletChain {
    /// Every chain, in the order a wallet setup supplies accounts.
    pub const ALL: [Self; 4] = [Self::Evm, Self::Btc, Self::Solana, Self::Tron];

    /// Lowercase machine name matching this type's serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Btc => "btc",
            Self::Solana => "solana",
            Self::Tron => "tron",
        }
    }

    /// The matching chain identifier in the transport-neutral bus contract.
    #[must_use]
    pub const fn to_chain(self) -> Chain {
        match self {
            Self::Evm => Chain::Evm,
            Self::Btc => Chain::Btc,
            Self::Solana => Chain::Solana,
            Self::Tron => Chain::Tron,
        }
    }
}

/// An EVM network identifier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EvmNetwork {
    /// Ethereum mainnet.
    EthereumMainnet,
    /// Base.
    BaseMainnet,
    /// Arbitrum One.
    ArbitrumOne,
    /// Optimism.
    OptimismMainnet,
    /// Polygon `PoS`.
    PolygonMainnet,
    /// BNB Smart Chain.
    BscMainnet,
}

impl EvmNetwork {
    /// Every network supported by this contract version.
    pub const ALL: [Self; 6] = [
        Self::EthereumMainnet,
        Self::BaseMainnet,
        Self::ArbitrumOne,
        Self::OptimismMainnet,
        Self::PolygonMainnet,
        Self::BscMainnet,
    ];

    /// The lowercase identifier used by the wire vocabulary.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EthereumMainnet => "ethereum_mainnet",
            Self::BaseMainnet => "base_mainnet",
            Self::ArbitrumOne => "arbitrum_one",
            Self::OptimismMainnet => "optimism_mainnet",
            Self::PolygonMainnet => "polygon_mainnet",
            Self::BscMainnet => "bsc_mainnet",
        }
    }

    /// The EIP-155 chain identifier.
    #[must_use]
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::EthereumMainnet => 1,
            Self::BaseMainnet => 8453,
            Self::ArbitrumOne => 42161,
            Self::OptimismMainnet => 10,
            Self::PolygonMainnet => 137,
            Self::BscMainnet => 56,
        }
    }
}

/// A Solana cluster selected by the host.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SolanaCluster {
    /// Mainnet-beta.
    Mainnet,
    /// Devnet.
    Devnet,
}

/// Where a host endpoint came from.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpcSource {
    /// The built-in endpoint.
    Default,
    /// A host-supplied endpoint override.
    EnvOverride,
}

/// The key for one host-resolved chain endpoint.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
#[serde(deny_unknown_fields)]
pub enum RpcEndpointKey {
    /// One EVM network endpoint.
    Evm {
        /// Network identifier.
        network: EvmNetwork,
    },
    /// Bitcoin endpoint.
    Btc,
    /// Solana endpoint.
    Solana,
    /// Tron endpoint.
    Tron,
}

/// An opaque, handle-scoped reference to a host endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEndpointReference {
    /// Endpoint key whose actual URL remains in the host.
    pub key: RpcEndpointKey,
    /// Opaque value to return with transport requests for this service epoch.
    pub reference: String,
}

/// Current service configuration without endpoint URLs or credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeWalletConfigRequest {
    /// Solana cluster; controls module-owned mint and explorer defaults.
    pub solana_cluster: SolanaCluster,
    /// Host endpoint keys overridden in the current user configuration.
    pub overridden_endpoints: Vec<RpcEndpointKey>,
}

/// Opaque capability for a configured native wallet service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletServiceHandle {
    /// Must accompany every operation on this configured service.
    pub handle: String,
}

/// Configured service handle and its opaque endpoint references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeWalletConfigResponse {
    /// Handle for subsequent operations.
    pub service: NativeWalletServiceHandle,
    /// Endpoint references the host binds to its private URL configuration.
    pub endpoint_references: Vec<HostEndpointReference>,
}

/// Close one configured native wallet service and invalidate its quotes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletCloseRequest {
    /// Handle returned by native wallet configuration.
    pub service: NativeWalletServiceHandle,
}

/// A request scoped to one configured native wallet service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletServiceRequest {
    /// Handle returned by native wallet configuration.
    pub service: NativeWalletServiceHandle,
}

/// Prepare a native or token transfer under the configured service and owner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletPrepareTransferRequest {
    /// Handle returned by native wallet configuration.
    pub service: NativeWalletServiceHandle,
    /// Conversation or job owner; absent for non-conversation callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<QuoteOwner>,
    /// Validated by the wallet implementation.
    pub params: PrepareTransferParams,
}

/// Execute one owner-scoped prepared transfer confidentially.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWalletExecuteRequest {
    /// Handle returned by native wallet configuration.
    pub service: NativeWalletServiceHandle,
    /// Conversation or job owner; absent for non-conversation callers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<QuoteOwner>,
    /// Quote returned by transfer preparation.
    pub quote_id: String,
    /// Must be true to cross the explicit confirmation boundary.
    pub confirmed: bool,
    /// Key material delivered only to an attested module through a confidential call.
    pub secret: SecretMaterial,
}

/// Query status, receipt, or raw transaction by chain and hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeWalletTransactionRequest {
    /// Handle returned by native wallet configuration.
    pub service: NativeWalletServiceHandle,
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM queries; omitted selects Ethereum mainnet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Transaction hash or signature.
    pub hash: String,
}

/// An exact native transaction or signed message presented for host approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NativeWalletExecutionIntent {
    /// Structured transaction passed to the module signer.
    Transaction {
        /// The exact chain transaction fields being signed.
        transaction: TransactionSpec,
    },
    /// Solana message bytes passed to the module signer.
    SolanaMessage {
        /// Lowercase hex message bytes.
        message_hex: String,
    },
}

/// A network/asset row returned by the wallet implementation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletAssetDefinition {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Ticker symbol.
    pub symbol: String,
    /// Display name.
    pub name: String,
    /// Native chain asset flag.
    pub native: bool,
    /// Smallest-unit decimal places.
    pub decimals: u8,
    /// Contract or mint address, absent for native assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
}

/// Default endpoint and capabilities for one network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletNetworkDefaults {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Network label.
    pub network: String,
    /// EIP-155 chain identifier for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// Public URL for defaults, or opaque host endpoint reference for overrides.
    pub rpc_url: String,
    /// Endpoint source.
    pub rpc_source: RpcSource,
    /// Explorer URL prefix.
    pub explorer_tx_url_base: String,
    /// Explorer suffix where required.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_tx_url_suffix: Option<String>,
    /// Whether broadcast is supported.
    pub supports_broadcast: bool,
    /// Whether token transfers are supported.
    pub supports_token_transfers: bool,
    /// Whether generic contract calls are supported.
    pub supports_contract_calls: bool,
    /// Assets catalogued for this network.
    pub assets: Vec<WalletAssetDefinition>,
}

/// Provider readiness.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    /// The endpoint answered its probe.
    Ready,
    /// No configured account or the provider is unavailable.
    Missing,
}

/// Whether a chain has an account and responding endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChainStatus {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Whether the wallet has an account for the chain.
    pub configured: bool,
    /// Provider state.
    pub provider_status: ProviderStatus,
    /// Public endpoint URL or opaque host endpoint reference.
    pub rpc_url: String,
    /// Safe provider failure reason, when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A supported asset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SupportedAsset {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Ticker symbol.
    pub symbol: String,
    /// Display name.
    pub name: String,
    /// Whether this is the native asset.
    pub native: bool,
    /// Smallest-unit decimal places.
    pub decimals: u8,
    /// Contract or mint address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
}

/// A native-asset balance row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BalanceInfo {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Account address.
    pub address: String,
    /// Asset symbol.
    pub asset_symbol: String,
    /// Smallest-unit decimal places.
    pub decimals: u8,
    /// Raw smallest-unit amount.
    pub raw: String,
    /// Human-readable amount.
    pub formatted: String,
    /// Provider state.
    pub provider_status: ProviderStatus,
}

/// A token balance row: one catalogued token (an SPL mint on Solana) held by
/// one wallet account. Native balances stay in [`BalanceInfo`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TokenBalanceInfo {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Account (owner) address.
    pub address: String,
    /// Asset symbol from the catalog.
    pub asset_symbol: String,
    /// Token contract or mint address.
    pub token_address: String,
    /// Smallest-unit decimal places.
    pub decimals: u8,
    /// Raw smallest-unit amount, summed over every token account the owner
    /// holds for this mint.
    pub raw: String,
    /// Human-readable amount.
    pub formatted: String,
    /// Provider state; `missing` rows read as zero.
    pub provider_status: ProviderStatus,
}

/// What a prepared transfer moves.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreparedKind {
    /// The chain's native asset.
    NativeTransfer,
    /// A chain token.
    TokenTransfer,
}

/// Where a prepared transfer is in its lifecycle.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreparedStatus {
    /// Waiting for confirmation.
    AwaitingConfirmation,
    /// Signed and broadcast.
    Broadcasted,
    /// Consumed.
    Consumed,
}

/// A prepared transfer awaiting confirmation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PreparedTransaction {
    /// Identifier returned to execute this transfer.
    pub quote_id: String,
    /// Native or token transfer.
    pub kind: PreparedKind,
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Wallet sender address.
    pub from_address: String,
    /// Recipient address.
    pub to_address: String,
    /// Asset ticker.
    pub asset_symbol: String,
    /// Amount in smallest units.
    pub amount_raw: String,
    /// Human-readable amount.
    pub amount_formatted: String,
    /// Received token symbol for swaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receive_symbol: Option<String>,
    /// Minimum received amount for swaps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_receive_raw: Option<String>,
    /// Contract call data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calldata: Option<String>,
    /// Contract or mint address for token transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_address: Option<String>,
    /// Estimated fee in smallest units.
    pub estimated_fee_raw: String,
    /// Lifecycle status.
    pub status: PreparedStatus,
    /// Creation time in epoch milliseconds.
    pub created_at_ms: u64,
    /// Expiration time in epoch milliseconds.
    pub expires_at_ms: u64,
    /// Human-readable notes.
    pub notes: Vec<String>,
}

/// The result of executing a prepared transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExecutionResult {
    /// Executed quote identifier.
    pub quote_id: String,
    /// Final transfer status.
    pub status: PreparedStatus,
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM transfers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Network hash, signature, or transaction id.
    pub transaction_hash: String,
    /// Explorer URL for this transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_url: Option<String>,
    /// Transfer facts that were executed.
    pub transaction: PreparedTransaction,
}

/// The lifecycle state of a transaction.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxState {
    /// Seen by a node, not yet included in a block.
    Pending,
    /// Included and succeeded.
    Confirmed,
    /// Included and failed.
    Failed,
    /// Unknown to the provider.
    NotFound,
}

/// Transaction lifecycle status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TxStatusInfo {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Queried hash.
    pub hash: String,
    /// Lifecycle state.
    pub state: TxState,
    /// Confirmations, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
    /// Block or slot number, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
}

/// Transaction receipt facts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TxReceiptInfo {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Queried hash.
    pub hash: String,
    /// Whether a transaction was found.
    pub found: bool,
    /// Whether it succeeded, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub success: Option<bool>,
    /// Block or slot number, when available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Gas or energy used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_used: Option<String>,
    /// Fee in smallest units.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_raw: Option<String>,
    /// Raw provider response.
    pub raw: Value,
}

/// Transaction data returned by a provider.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TxLookupInfo {
    /// Chain family.
    pub chain: WalletChain,
    /// EVM network for EVM queries.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Queried hash.
    pub hash: String,
    /// Whether a transaction was found.
    pub found: bool,
    /// Raw provider response.
    pub raw: Value,
}

/// Parameters for preparing a transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrepareTransferParams {
    /// Chain family.
    pub chain: WalletChain,
    /// Recipient address.
    pub to_address: String,
    /// Amount in smallest units.
    pub amount_raw: String,
    /// Asset ticker; omitted selects the native asset.
    #[serde(default)]
    pub asset_symbol: Option<String>,
    /// EVM network; omitted selects Ethereum mainnet.
    #[serde(default)]
    pub evm_network: Option<EvmNetwork>,
}

/// Parameters for executing a prepared transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutePreparedParams {
    /// Prepared quote identifier.
    pub quote_id: String,
    /// Must be true to execute.
    pub confirmed: bool,
}
