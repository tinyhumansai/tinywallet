//! Networks and the assets that exist on them.
//!
//! Reference data: which EVM networks exist and what their chain ids are, which
//! tokens live on each network, their decimals, and their contract addresses.
//! All of it is pure — [`catalog`] is a function of its arguments and nothing
//! else.
//!
//! ## Decimals are the reason this belongs in a library
//!
//! Every entry here carries [`Asset::decimals`], and getting one wrong
//! misprices a transfer by orders of magnitude while looking perfectly
//! plausible. Two traps are baked into the tables below precisely because they
//! catch people out:
//!
//! - **USDC is not always 6 decimals.** On Ethereum, Base, Arbitrum, Optimism
//!   and Polygon it is. On BNB Chain the BEP-20 version is **18**, so the same
//!   symbol on the same chain family needs a different scale.
//! - **Solana's USDC mint differs per cluster.** Mainnet and devnet are
//!   different addresses, so a devnet transfer built with the mainnet mint
//!   silently targets a token that does not exist there.
//!
//! ## No endpoints, and no environment
//!
//! This module holds no RPC URLs and reads no environment variables. Which
//! endpoint serves a network is endpoint selection, which belongs to the host
//! for the reasons set out in [`crate::rpc`]; and reading configuration out of
//! the process environment is a host's job by definition.
//!
//! That is why [`SolanaCluster`] is a *parameter* of [`catalog`] rather than
//! something resolved internally. The host decides which cluster it is on and
//! says so, instead of this crate guessing from a variable it does not own.
//!
//! Explorer links are a different matter and *are* here: a block explorer URL
//! is public reference data about a network, not a service this crate talks to.

use crate::chain::Chain;

/// An EVM network.
///
/// One variant per network the catalog knows. These share an address format
/// and an RPC dialect but are distinct networks with distinct token contracts,
/// which is why [`Chain::Evm`] alone is never enough to price a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum EvmNetwork {
    /// Ethereum mainnet (chain id 1).
    Ethereum,
    /// Base mainnet (chain id 8453).
    Base,
    /// Arbitrum One (chain id 42161).
    Arbitrum,
    /// OP Mainnet (chain id 10).
    Optimism,
    /// Polygon mainnet (chain id 137).
    Polygon,
    /// BNB Smart Chain mainnet (chain id 56).
    Bsc,
}

impl EvmNetwork {
    /// Every EVM network in the catalog.
    pub const ALL: &'static [Self] = &[
        Self::Ethereum,
        Self::Base,
        Self::Arbitrum,
        Self::Optimism,
        Self::Polygon,
        Self::Bsc,
    ];

    /// The EIP-155 chain id.
    ///
    /// This is the value that must be signed into a transaction; a mismatch
    /// between it and the network actually being broadcast to is what replay
    /// protection exists to catch.
    #[must_use]
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Ethereum => 1,
            Self::Base => 8453,
            Self::Arbitrum => 42161,
            Self::Optimism => 10,
            Self::Polygon => 137,
            Self::Bsc => 56,
        }
    }

    /// Machine-readable network name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ethereum => "ethereum_mainnet",
            Self::Base => "base_mainnet",
            Self::Arbitrum => "arbitrum_one",
            Self::Optimism => "optimism_mainnet",
            Self::Polygon => "polygon_mainnet",
            Self::Bsc => "bsc_mainnet",
        }
    }

    /// Look a network up by its EIP-155 chain id.
    #[must_use]
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        Self::ALL.iter().copied().find(|n| n.chain_id() == chain_id)
    }

    /// The network's native gas asset — `ETH`, `POL` or `BNB`.
    const fn native(self) -> (&'static str, &'static str) {
        match self {
            Self::Polygon => ("POL", "Polygon"),
            Self::Bsc => ("BNB", "BNB"),
            _ => ("ETH", "Ether"),
        }
    }

    /// Base URL a transaction hash is appended to on this network's explorer.
    const fn explorer_tx_base(self) -> &'static str {
        match self {
            Self::Ethereum => "https://etherscan.io/tx/",
            Self::Base => "https://basescan.org/tx/",
            Self::Arbitrum => "https://arbiscan.io/tx/",
            Self::Optimism => "https://optimistic.etherscan.io/tx/",
            Self::Polygon => "https://polygonscan.com/tx/",
            Self::Bsc => "https://bscscan.com/tx/",
        }
    }
}

impl std::fmt::Display for EvmNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which Solana cluster a wallet is operating against.
///
/// Selects the USDC mint as well as, host-side, the endpoint — see
/// [`SolanaCluster::usdc_mint`] for why conflating the two breaks a devnet
/// transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SolanaCluster {
    /// Mainnet-beta.
    #[default]
    Mainnet,
    /// Devnet.
    Devnet,
}

impl SolanaCluster {
    /// The USDC SPL-token mint for this cluster.
    ///
    /// Mainnet and devnet USDC are genuinely different mints. Building a
    /// devnet transfer against the mainnet mint produces a transaction
    /// referencing a token account that does not exist on devnet — which fails
    /// late and confusingly, rather than at the point the wrong constant was
    /// chosen.
    #[must_use]
    pub const fn usdc_mint(self) -> &'static str {
        match self {
            Self::Mainnet => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            Self::Devnet => "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        }
    }
}

/// A network the catalog can describe.
///
/// Carries the discriminator each chain needs: an [`EvmNetwork`] for EVM and a
/// [`SolanaCluster`] for Solana, since on both the chain alone does not
/// determine which token contracts are correct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    /// Bitcoin mainnet.
    Btc,
    /// A specific EVM network.
    Evm(EvmNetwork),
    /// A specific Solana cluster.
    Solana(SolanaCluster),
    /// Tron mainnet.
    Tron,
}

impl Network {
    /// The chain family this network belongs to.
    #[must_use]
    pub const fn chain(self) -> Chain {
        match self {
            Self::Btc => Chain::Btc,
            Self::Evm(_) => Chain::Evm,
            Self::Solana(_) => Chain::Solana,
            Self::Tron => Chain::Tron,
        }
    }

    /// The EIP-155 chain id, for EVM networks only.
    #[must_use]
    pub const fn chain_id(self) -> Option<u64> {
        match self {
            Self::Evm(network) => Some(network.chain_id()),
            _ => None,
        }
    }

    /// A link to `tx_hash` on this network's block explorer.
    ///
    /// Always `Some` for the networks in this catalog; the `Option` is kept so
    /// adding a network without a known explorer stays expressible.
    #[must_use]
    pub fn explorer_tx_url(self, tx_hash: &str) -> Option<String> {
        let base = match self {
            Self::Btc => "https://blockstream.info/tx/",
            Self::Evm(network) => network.explorer_tx_base(),
            Self::Solana(_) => "https://solscan.io/tx/",
            Self::Tron => "https://tronscan.org/#/transaction/",
        };
        Some(format!("{base}{tx_hash}"))
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Evm(network) => f.write_str(network.as_str()),
            Self::Btc => f.write_str("bitcoin_mainnet"),
            Self::Solana(SolanaCluster::Mainnet) => f.write_str("solana_mainnet"),
            Self::Solana(SolanaCluster::Devnet) => f.write_str("solana_devnet"),
            Self::Tron => f.write_str("tron_mainnet"),
        }
    }
}

/// An asset that can be held and transferred on a network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// The network the asset lives on.
    pub network: Network,
    /// Ticker symbol, e.g. `USDC`. Not unique across networks.
    pub symbol: String,
    /// Human-readable name.
    pub name: String,
    /// Whether this is the network's native gas asset rather than a token.
    ///
    /// A native asset has no [`Asset::contract_address`] and is transferred by
    /// the chain itself rather than by calling a contract.
    pub native: bool,
    /// How many base units make one whole unit, as a power of ten.
    ///
    /// See the module docs — this is the field that misprices a transfer when
    /// it is wrong, and it genuinely varies for the same symbol across
    /// networks.
    pub decimals: u8,
    /// Token contract or mint address. `None` for a native asset.
    pub contract_address: Option<String>,
}

impl Asset {
    fn native(network: Network, symbol: &str, name: &str, decimals: u8) -> Self {
        Self {
            network,
            symbol: symbol.to_string(),
            name: name.to_string(),
            native: true,
            decimals,
            contract_address: None,
        }
    }

    fn token(network: Network, symbol: &str, name: &str, decimals: u8, contract: &str) -> Self {
        Self {
            network,
            symbol: symbol.to_string(),
            name: name.to_string(),
            native: false,
            decimals,
            contract_address: Some(contract.to_string()),
        }
    }
}

/// Every asset the catalog knows for `network`.
///
/// The native asset is always first; tokens follow in no guaranteed order.
///
/// # Examples
///
/// ```
/// use tinywallet_bus::asset::{self, EvmNetwork, Network, SolanaCluster};
///
/// // The same symbol, a different scale, on the same chain family.
/// let ethereum = asset::find(Network::Evm(EvmNetwork::Ethereum), "USDC").unwrap();
/// let bsc = asset::find(Network::Evm(EvmNetwork::Bsc), "USDC").unwrap();
/// assert_eq!(ethereum.decimals, 6);
/// assert_eq!(bsc.decimals, 18);
///
/// // And a different mint per Solana cluster.
/// let mainnet = asset::find(Network::Solana(SolanaCluster::Mainnet), "USDC").unwrap();
/// let devnet = asset::find(Network::Solana(SolanaCluster::Devnet), "USDC").unwrap();
/// assert_ne!(mainnet.contract_address, devnet.contract_address);
/// ```
#[must_use]
pub fn catalog(network: Network) -> Vec<Asset> {
    match network {
        Network::Btc => vec![Asset::native(network, "BTC", "Bitcoin", 8)],

        Network::Tron => vec![
            Asset::native(network, "TRX", "Tron", 6),
            Asset::token(
                network,
                "USDT",
                "Tether USD (TRC20)",
                6,
                "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
            ),
        ],

        Network::Solana(cluster) => vec![
            Asset::native(network, "SOL", "Solana", 9),
            Asset::token(network, "USDC", "USD Coin (Solana)", 6, cluster.usdc_mint()),
        ],

        Network::Evm(evm) => evm_catalog(network, evm),
    }
}

/// The EVM half of [`catalog`], split out because it is the only one with
/// per-network token variation.
fn evm_catalog(network: Network, evm: EvmNetwork) -> Vec<Asset> {
    let (symbol, name) = evm.native();
    let mut assets = vec![Asset::native(network, symbol, name, 18)];

    // 6-decimal native USDC. BNB Chain is absent deliberately — its BEP-20
    // USDC is 18 decimals and is added below.
    let usdc_6dp = match evm {
        EvmNetwork::Ethereum => Some("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
        EvmNetwork::Base => Some("0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"),
        EvmNetwork::Arbitrum => Some("0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
        EvmNetwork::Optimism => Some("0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85"),
        EvmNetwork::Polygon => Some("0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"),
        EvmNetwork::Bsc => None,
    };
    if let Some(contract) = usdc_6dp {
        assets.push(Asset::token(network, "USDC", "USD Coin", 6, contract));
    }

    match evm {
        // BEP-20 stablecoins are 18 decimals, unlike the 6-decimal USDC
        // everywhere else. Catalogued separately so the scale cannot be
        // inherited from the branch above by accident.
        EvmNetwork::Bsc => assets.extend([
            Asset::token(
                network,
                "USDT",
                "Tether USD (BEP20)",
                18,
                "0x55d398326f99059fF775485246999027B3197955",
            ),
            Asset::token(
                network,
                "USDC",
                "USD Coin (BEP20)",
                18,
                "0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d",
            ),
        ]),
        EvmNetwork::Ethereum => assets.extend([
            Asset::token(
                network,
                "USDT",
                "Tether USD",
                6,
                "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            ),
            Asset::token(
                network,
                "DAI",
                "Dai",
                18,
                "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            ),
            Asset::token(
                network,
                "WETH",
                "Wrapped Ether",
                18,
                "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            ),
        ]),
        _ => {}
    }

    assets
}

/// Find an asset on `network` by symbol, case-insensitively.
///
/// Symbols are not unique across networks, which is why this takes a
/// [`Network`] rather than a [`Chain`]: `USDC` names three different contracts
/// with two different decimal scales in this catalog alone.
#[must_use]
pub fn find(network: Network, symbol: &str) -> Option<Asset> {
    let wanted = symbol.trim();
    catalog(network)
        .into_iter()
        .find(|a| a.symbol.eq_ignore_ascii_case(wanted))
}

/// Every network the catalog knows, for a given Solana cluster.
///
/// The cluster is a parameter for the same reason it is on [`catalog`]: this
/// crate does not read the environment to discover which one a host is on.
#[must_use]
pub fn networks(solana: SolanaCluster) -> Vec<Network> {
    let mut out: Vec<Network> = EvmNetwork::ALL.iter().copied().map(Network::Evm).collect();
    out.push(Network::Btc);
    out.push(Network::Solana(solana));
    out.push(Network::Tron);
    out
}

#[cfg(test)]
mod test;
