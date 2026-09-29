//! The wallet's own vocabulary: which chain, which account, and what status a
//! host reports about them.

use serde::{Deserialize, Serialize};

/// The four chain families the wallet signs for.
///
/// EVM is one family covering every network in
/// [`EvmNetwork`](crate::crypto::defaults::EvmNetwork); the account (and so the
/// address) is shared across them.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum WalletChain {
    /// An EVM chain (Ethereum and the L2s).
    Evm,
    /// Bitcoin.
    Btc,
    /// Solana.
    Solana,
    /// Tron.
    Tron,
}

impl WalletChain {
    /// Every chain, in the order a wallet setup must supply accounts.
    pub const ALL: [Self; 4] = [Self::Evm, Self::Btc, Self::Solana, Self::Tron];

    /// The lowercase machine name, matching the serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Btc => "btc",
            Self::Solana => "solana",
            Self::Tron => "tron",
        }
    }

    /// The matching `tinywallet-crypto` chain.
    #[must_use]
    pub const fn to_chain(self) -> tinywallet_crypto::Chain {
        match self {
            Self::Evm => tinywallet_crypto::Chain::Evm,
            Self::Btc => tinywallet_crypto::Chain::Btc,
            Self::Solana => tinywallet_crypto::Chain::Solana,
            Self::Tron => tinywallet_crypto::Chain::Tron,
        }
    }
}

/// How a wallet came to exist.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletSetupSource {
    /// A fresh recovery phrase generated for the user.
    Generated,
    /// A recovery phrase the user brought.
    Imported,
}

/// A derived per-chain account.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletAccount {
    /// The chain family the account belongs to.
    pub chain: WalletChain,
    /// The address in the chain's canonical text form.
    pub address: String,
    /// The derivation path the account was derived at.
    pub derivation_path: String,
}

/// What a host reports about the wallet: whether it is set up, and its
/// accounts.
// The four flags are the wire shape hosts already serialize to the frontend;
// folding them into an enum would change the JSON.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WalletStatus {
    /// Whether a wallet exists.
    pub configured: bool,
    /// Whether onboarding finished.
    pub onboarding_completed: bool,
    /// Whether the user consented to local wallet custody.
    pub consent_granted: bool,
    /// Whether the encrypted secret material is stored.
    pub secret_stored: bool,
    /// How the wallet was created, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<WalletSetupSource>,
    /// Recovery phrase length, when configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnemonic_word_count: Option<u8>,
    /// The derived accounts, one per chain.
    pub accounts: Vec<WalletAccount>,
    /// When the wallet state was last written, in milliseconds since the epoch.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at_ms: Option<u64>,
}
