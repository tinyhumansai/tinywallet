//! Choosing which requirement of a challenge to pay, and refusing the rest.

use super::error::X402Error;
use crate::wire::{AssetCheck, PaymentChain, PaymentRequired, PaymentRequirements, check_usdc};

/// The chain family a network belongs to, from its CAIP-2 prefix.
fn chain_of(network: &str) -> Option<PaymentChain> {
    if network.starts_with("solana:") {
        Some(PaymentChain::Solana)
    } else if network.starts_with("eip155:") {
        Some(PaymentChain::Evm)
    } else {
        None
    }
}

/// Whether `requirement` asks for USDC on a network this crate pays on.
///
/// # Errors
///
/// [`X402Error::UnsupportedNetwork`] or [`X402Error::UnsupportedAsset`].
pub(crate) fn ensure_payable(requirement: &PaymentRequirements) -> Result<(), X402Error> {
    match check_usdc(&requirement.network, &requirement.asset) {
        AssetCheck::Allowed => Ok(()),
        AssetCheck::UnknownNetwork => Err(X402Error::UnsupportedNetwork {
            network: requirement.network.clone(),
        }),
        AssetCheck::WrongAsset => Err(X402Error::UnsupportedAsset {
            network: requirement.network.clone(),
            asset: requirement.asset.clone(),
        }),
    }
}

/// The index and chain of the requirement to pay: the first payable Solana
/// `exact` option, else the first payable EVM one.
///
/// Options on networks or in assets outside the allowlist are skipped, so a
/// server that also offers a payable one is still paid.
///
/// # Errors
///
/// [`X402Error::NoPaymentOption`] when the challenge has no `exact` option on a
/// Solana or EVM network at all; otherwise the refusal for the first such option
/// when none of them is payable.
pub(crate) fn select_requirement(
    challenge: &PaymentRequired,
) -> Result<(usize, PaymentChain), X402Error> {
    let mut first_refusal = None;
    let mut evm = None;
    for (index, requirement) in challenge.accepts.iter().enumerate() {
        let Some(chain) = chain_of(&requirement.network).filter(|_| requirement.scheme == "exact")
        else {
            continue;
        };
        match ensure_payable(requirement) {
            Ok(()) if chain == PaymentChain::Solana => return Ok((index, chain)),
            Ok(()) => {
                evm.get_or_insert((index, chain));
            }
            Err(refusal) => {
                first_refusal.get_or_insert(refusal);
            }
        }
    }
    match (evm, first_refusal) {
        (Some(choice), _) => Ok(choice),
        (None, Some(refusal)) => Err(refusal),
        (None, None) => Err(X402Error::NoPaymentOption),
    }
}
