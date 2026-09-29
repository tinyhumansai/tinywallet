//! Well-known test data: the standard mnemonic's addresses, a status that has
//! them all, quote owners and a quote builder.

use crate::crypto::defaults::EvmNetwork;
use crate::crypto::execution::{PreparedKind, PreparedStatus, PreparedTransaction};
use crate::crypto::wallet::{WalletAccount, WalletChain, WalletSetupSource, WalletStatus};
use crate::quote::{QuoteOwner, now_ms};

/// Standard BIP-39 test mnemonic: every chain derives a deterministic account.
pub(crate) const TEST_MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// The address the test mnemonic derives for `chain`.
pub(crate) fn sample_address(chain: WalletChain) -> &'static str {
    match chain {
        WalletChain::Evm => "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        WalletChain::Btc => "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        WalletChain::Solana => "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
        WalletChain::Tron => "TUEZSdKsoDHQMeZwihtdoBiN46zxhGWYdH",
    }
}

/// The derivation path used for `chain`.
pub(crate) fn derivation_path(chain: WalletChain) -> &'static str {
    match chain {
        WalletChain::Evm => "m/44'/60'/0'/0/0",
        WalletChain::Btc => "m/84'/0'/0'/0/0",
        WalletChain::Solana => "m/44'/501'/0'/0'",
        WalletChain::Tron => "m/44'/195'/0'/0/0",
    }
}

/// The account the test wallet holds for `chain`.
pub(crate) fn sample_account(chain: WalletChain) -> WalletAccount {
    WalletAccount {
        chain,
        address: sample_address(chain).to_string(),
        derivation_path: derivation_path(chain).to_string(),
    }
}

/// A fully configured wallet with one account per chain.
pub(crate) fn configured_status() -> WalletStatus {
    WalletStatus {
        configured: true,
        onboarding_completed: true,
        consent_granted: true,
        secret_stored: true,
        source: Some(WalletSetupSource::Imported),
        mnemonic_word_count: Some(12),
        accounts: WalletChain::ALL.into_iter().map(sample_account).collect(),
        updated_at_ms: Some(1),
    }
}

/// One chat thread.
pub(crate) fn owner_a() -> QuoteOwner {
    QuoteOwner {
        thread_id: "thread-A".into(),
        client_id: "client-A".into(),
    }
}

/// A different chat thread.
pub(crate) fn owner_b() -> QuoteOwner {
    QuoteOwner {
        thread_id: "thread-B".into(),
        client_id: "client-B".into(),
    }
}

/// A prepared quote with the given id, chain and kind, expiring in a minute.
pub(crate) fn prepared_quote(
    quote_id: &str,
    chain: WalletChain,
    kind: PreparedKind,
) -> PreparedTransaction {
    let now = now_ms();
    PreparedTransaction {
        quote_id: quote_id.to_string(),
        kind,
        chain,
        evm_network: (chain == WalletChain::Evm).then_some(EvmNetwork::EthereumMainnet),
        from_address: sample_address(chain).to_string(),
        to_address: "0x1111111111111111111111111111111111111111".to_string(),
        asset_symbol: "ETH".to_string(),
        amount_raw: "1".to_string(),
        amount_formatted: "0.000000000000000001".to_string(),
        receive_symbol: None,
        min_receive_raw: None,
        calldata: None,
        token_address: None,
        estimated_fee_raw: "0".to_string(),
        status: PreparedStatus::AwaitingConfirmation,
        created_at_ms: now,
        expires_at_ms: now + 60_000,
        notes: vec![],
        owner: None,
    }
}
