//! The static reference types: EVM networks, Solana clusters, and the asset
//! and network rows a wallet reports.

use serde::{Deserialize, Serialize};

use crate::crypto::wallet::WalletChain;

const ETHERSCAN_TX_BASE: &str = "https://etherscan.io/tx/";
const BASESCAN_TX_BASE: &str = "https://basescan.org/tx/";
const ARBISCAN_TX_BASE: &str = "https://arbiscan.io/tx/";
const OPTIMISTIC_TX_BASE: &str = "https://optimistic.etherscan.io/tx/";
const POLYGONSCAN_TX_BASE: &str = "https://polygonscan.com/tx/";
const BSCSCAN_TX_BASE: &str = "https://bscscan.com/tx/";

const DEFAULT_SOLANA_RPC_URL: &str = "https://api.mainnet-beta.solana.com";
const DEVNET_SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

// USDC SPL-token mint per Solana cluster. The mainnet and devnet mints differ,
// so the selected cluster must drive both the RPC endpoint and the mint.
const SOLANA_USDC_MINT_MAINNET: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const SOLANA_USDC_MINT_DEVNET: &str = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";

/// The Solana cluster the wallet broadcasts to.
///
/// Drives **both** the default Solana RPC endpoint and the USDC SPL mint, so a
/// devnet x402 payment challenge's on-chain transfer lands on devnet with the
/// devnet mint rather than mainnet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SolanaCluster {
    /// Mainnet-beta, the default.
    Mainnet,
    /// Devnet.
    Devnet,
}

impl SolanaCluster {
    /// Default JSON-RPC endpoint for the cluster (a host may override it).
    #[must_use]
    pub const fn rpc_url(self) -> &'static str {
        match self {
            Self::Mainnet => DEFAULT_SOLANA_RPC_URL,
            Self::Devnet => DEVNET_SOLANA_RPC_URL,
        }
    }

    /// USDC SPL-token mint address for the cluster.
    #[must_use]
    pub const fn usdc_mint(self) -> &'static str {
        match self {
            Self::Mainnet => SOLANA_USDC_MINT_MAINNET,
            Self::Devnet => SOLANA_USDC_MINT_DEVNET,
        }
    }
}

/// Recognized EVM networks. New L2s plug in here.
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
    /// Every supported network.
    pub const ALL: [Self; 6] = [
        Self::EthereumMainnet,
        Self::BaseMainnet,
        Self::ArbitrumOne,
        Self::OptimismMainnet,
        Self::PolygonMainnet,
        Self::BscMainnet,
    ];

    /// The `snake_case` machine name, matching the serde representation.
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

    /// The EIP-155 chain id.
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

    /// The built-in public JSON-RPC endpoint.
    #[must_use]
    pub const fn default_rpc_url(self) -> &'static str {
        match self {
            Self::EthereumMainnet => "https://ethereum-rpc.publicnode.com",
            Self::BaseMainnet => "https://mainnet.base.org",
            Self::ArbitrumOne => "https://arb1.arbitrum.io/rpc",
            Self::OptimismMainnet => "https://mainnet.optimism.io",
            Self::PolygonMainnet => "https://polygon-rpc.com",
            Self::BscMainnet => "https://bsc-dataseed.binance.org",
        }
    }

    /// The block explorer's transaction-URL prefix.
    #[must_use]
    pub const fn explorer_tx_base(self) -> &'static str {
        match self {
            Self::EthereumMainnet => ETHERSCAN_TX_BASE,
            Self::BaseMainnet => BASESCAN_TX_BASE,
            Self::ArbitrumOne => ARBISCAN_TX_BASE,
            Self::OptimismMainnet => OPTIMISTIC_TX_BASE,
            Self::PolygonMainnet => POLYGONSCAN_TX_BASE,
            Self::BscMainnet => BSCSCAN_TX_BASE,
        }
    }

    /// The kebab-case label used in summaries.
    #[must_use]
    pub const fn network_label(self) -> &'static str {
        match self {
            Self::EthereumMainnet => "ethereum-mainnet",
            Self::BaseMainnet => "base-mainnet",
            Self::ArbitrumOne => "arbitrum-one",
            Self::OptimismMainnet => "optimism-mainnet",
            Self::PolygonMainnet => "polygon-mainnet",
            Self::BscMainnet => "bsc-mainnet",
        }
    }
}

/// Where an endpoint came from.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RpcSource {
    /// The built-in default.
    Default,
    /// A host-supplied override.
    EnvOverride,
}

/// One asset the wallet knows about.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAssetDefinition {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM assets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Ticker symbol.
    pub symbol: String,
    /// Display name.
    pub name: String,
    /// Whether this is the chain's native asset.
    pub native: bool,
    /// Decimal places of the smallest unit.
    pub decimals: u8,
    /// Token contract or mint address; `None` for a native asset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<String>,
}

/// Defaults for one network: endpoint, explorer, capabilities and assets.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletNetworkDefaults {
    /// The chain family.
    pub chain: WalletChain,
    /// The EVM network, for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_network: Option<EvmNetwork>,
    /// Network label.
    pub network: String,
    /// EIP-155 chain id, for EVM rows.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<u64>,
    /// The endpoint the host resolved.
    pub rpc_url: String,
    /// Whether that endpoint is a default or an override.
    pub rpc_source: RpcSource,
    /// Explorer transaction-URL prefix.
    pub explorer_tx_url_base: String,
    /// Whether the wallet can broadcast here.
    pub supports_broadcast: bool,
    /// Whether token transfers are supported.
    pub supports_token_transfers: bool,
    /// Whether generic contract calls are supported.
    pub supports_contract_calls: bool,
    /// The assets catalogued for the network.
    pub assets: Vec<WalletAssetDefinition>,
}
