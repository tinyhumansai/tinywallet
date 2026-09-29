//! Static reference data: networks, clusters, asset catalogs and explorer
//! links.
//!
//! Pure data and pure functions. What a deployment can change (the endpoint a
//! chain talks to, and which Solana cluster) is asked of
//! [`RpcEndpoints`](crate::crypto::seams::RpcEndpoints); the environment
//! variables that drive it stay in the host.

mod catalog;
mod types;

pub use catalog::{
    asset_catalog, default_rpc_url, evm_asset_catalog, explorer_tx_url,
    explorer_tx_url_for_evm_network, find_asset, find_asset_for_network, network_defaults,
};
pub use types::{
    EvmNetwork, RpcSource, SolanaCluster, WalletAssetDefinition, WalletNetworkDefaults,
};

#[cfg(test)]
mod test;
