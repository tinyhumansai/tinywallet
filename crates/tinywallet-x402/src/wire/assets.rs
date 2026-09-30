//! The allowlist of networks and the one asset payable on each.
//!
//! x402 lets the *server* name the network and the asset it wants paid, so
//! without a list a hostile endpoint could ask for any token on any chain. This
//! crate pays only in USDC, on the networks whose USDC it knows; everything else
//! is refused before a requirement is selected or signed.

use super::types::{
    BASE_MAINNET_CAIP2, BASE_SEPOLIA_CAIP2, ETHEREUM_MAINNET_CAIP2, SOLANA_DEVNET_CAIP2,
    SOLANA_MAINNET_CAIP2, USDC_BASE_MAINNET, USDC_BASE_SEPOLIA, USDC_ETHEREUM_MAINNET,
    USDC_MINT_DEVNET, USDC_MINT_MAINNET,
};

/// Every payable network (CAIP-2) with its USDC mint or contract.
pub const SUPPORTED_USDC: [(&str, &str); 5] = [
    (SOLANA_MAINNET_CAIP2, USDC_MINT_MAINNET),
    (SOLANA_DEVNET_CAIP2, USDC_MINT_DEVNET),
    (BASE_MAINNET_CAIP2, USDC_BASE_MAINNET),
    (BASE_SEPOLIA_CAIP2, USDC_BASE_SEPOLIA),
    (ETHEREUM_MAINNET_CAIP2, USDC_ETHEREUM_MAINNET),
];

/// The verdict of [`check_usdc`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssetCheck {
    /// The asset is the USDC of that network.
    Allowed,
    /// The network is not one this crate pays on.
    UnknownNetwork,
    /// The network is known, but the asset is not its USDC.
    WrongAsset,
}

/// Whether `asset` is the USDC of `network`.
///
/// EVM contract addresses are compared without regard to case (EIP-55
/// checksumming is presentation); Solana mints are base58 and compared exactly.
#[must_use]
pub fn check_usdc(network: &str, asset: &str) -> AssetCheck {
    let Some((_, usdc)) = SUPPORTED_USDC.iter().find(|(n, _)| *n == network) else {
        return AssetCheck::UnknownNetwork;
    };
    let same = if network.starts_with("eip155:") {
        usdc.eq_ignore_ascii_case(asset)
    } else {
        *usdc == asset
    };
    if same {
        AssetCheck::Allowed
    } else {
        AssetCheck::WrongAsset
    }
}
