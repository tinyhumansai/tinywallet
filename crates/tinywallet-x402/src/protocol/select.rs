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

/// Whether `network` falls under the caller's pin: a pin with a `:` is a full
/// CAIP-2 chain id and must match exactly; a pin without one is a CAIP-2
/// namespace (`eip155`, `solana`) and matches every chain in it.
fn matches_pin(network: &str, pin: &str) -> bool {
    if pin.contains(':') {
        network == pin
    } else {
        network.split(':').next() == Some(pin)
    }
}

/// Whether an `upto` requirement carries what a Permit2 authorization needs:
/// an EVM network, a facilitator address to bind into the witness, and no
/// transfer method other than Permit2 (the only one `upto` allows; absent
/// means Permit2). Anything else is refused rather than guessed at.
fn is_payable_upto(requirement: &PaymentRequirements) -> bool {
    let Some(extra) = requirement.extra.as_ref() else {
        return false;
    };
    requirement.evm_chain_id().is_some()
        && extra
            .asset_transfer_method
            .as_deref()
            .is_none_or(|method| method == "permit2")
        && extra
            .facilitator_address
            .as_deref()
            .is_some_and(|address| tinywallet_crypto::address::evm::validate(address).is_ok())
}

/// How strongly a requirement is preferred, best first, or `None` when this
/// crate cannot pay it at all.
///
/// Solana `exact` first, then EVM `exact`, then EVM `upto`: a fixed price is
/// preferred to a ceiling, which keeps today's choice for every challenge
/// that offers `exact`.
fn rank(requirement: &PaymentRequirements) -> Option<(u8, PaymentChain)> {
    match (requirement.scheme.as_str(), chain_of(&requirement.network)?) {
        ("exact", PaymentChain::Solana) => Some((0, PaymentChain::Solana)),
        ("exact", PaymentChain::Evm) => Some((1, PaymentChain::Evm)),
        ("upto", PaymentChain::Evm) if is_payable_upto(requirement) => {
            Some((2, PaymentChain::Evm))
        }
        _ => None,
    }
}

/// The index and chain of the requirement to pay: the best-ranked payable
/// option (see `rank`), the first one of that rank on a tie.
///
/// Options on networks or in assets outside the allowlist are skipped, so a
/// server that also offers a payable one is still paid. With a `network` pin
/// (a CAIP-2 chain id such as `eip155:8453`, or a namespace such as `eip155`),
/// options on any other network are not considered at all.
///
/// # Errors
///
/// [`X402Error::NoPaymentOptionOnNetwork`] when a pin leaves no option;
/// [`X402Error::NoPaymentOption`] when the challenge has no option this crate
/// can pay at all; otherwise the refusal for the first such option when none
/// of them is in an allowed network and asset.
pub(crate) fn select_requirement(
    challenge: &PaymentRequired,
    network: Option<&str>,
) -> Result<(usize, PaymentChain), X402Error> {
    let mut first_refusal = None;
    let mut best: Option<(u8, usize, PaymentChain)> = None;
    let mut pinned_any = false;
    for (index, requirement) in challenge.accepts.iter().enumerate() {
        if network.is_some_and(|pin| !matches_pin(&requirement.network, pin)) {
            continue;
        }
        pinned_any = true;
        let Some((rank, chain)) = rank(requirement) else {
            continue;
        };
        match ensure_payable(requirement) {
            Ok(()) if best.is_none_or(|(best_rank, _, _)| rank < best_rank) => {
                best = Some((rank, index, chain));
            }
            Ok(()) => {}
            Err(refusal) => {
                first_refusal.get_or_insert(refusal);
            }
        }
    }
    match (best, first_refusal, network) {
        (Some((_, index, chain)), _, _) => Ok((index, chain)),
        (None, Some(refusal), _) => Err(refusal),
        (None, None, Some(pin)) if !pinned_any => Err(X402Error::NoPaymentOptionOnNetwork {
            network: pin.to_string(),
        }),
        (None, None, _) => Err(X402Error::NoPaymentOption),
    }
}

#[cfg(test)]
#[path = "select_tests.rs"]
mod tests;
