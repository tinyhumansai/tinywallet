//! Unit tests for chain-generic address dispatch.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::validate;
use crate::{Chain, Error};

/// One valid mainnet address per chain.
const FIXTURES: [(Chain, &str); 4] = [
    (Chain::Btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"),
    (Chain::Evm, "0x52908400098527886E0F7030069857D2E4169EE7"),
    (Chain::Solana, "11111111111111111111111111111111"),
    (Chain::Tron, "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"),
];

/// Whether the feature gate behind `chain` is on in this build.
///
/// The dispatch assertions have to reflect the gated contract: a chain whose
/// gate is off is *supposed* to answer `ChainNotCompiled`, so the tests expect
/// success exactly for the chains that are compiled in.
const fn chain_enabled(chain: Chain) -> bool {
    match chain {
        #[cfg(feature = "btc")]
        Chain::Btc => true,
        #[cfg(feature = "evm")]
        Chain::Evm => true,
        #[cfg(feature = "solana")]
        Chain::Solana => true,
        #[cfg(feature = "tron")]
        Chain::Tron => true,
        #[cfg(not(all(feature = "btc", feature = "evm", feature = "solana", feature = "tron")))]
        _ => false,
    }
}

#[test]
fn dispatches_every_chain_to_its_own_validator() {
    for (chain, address) in FIXTURES {
        if chain_enabled(chain) {
            assert_eq!(
                validate(chain, address).unwrap(),
                address,
                "{chain} dispatch failed"
            );
        } else {
            assert!(
                matches!(
                    validate(chain, address),
                    Err(Error::ChainNotCompiled { .. })
                ),
                "{chain} gate is off in this build, so validation must report \
                 ChainNotCompiled, not validate"
            );
        }
    }
}

#[test]
fn every_known_chain_has_a_fixture() {
    // If `Chain::ALL` grows, this test fails until the new chain is covered
    // above — otherwise a new variant would silently go untested.
    assert_eq!(Chain::ALL.len(), FIXTURES.len());
    for chain in Chain::ALL {
        assert!(
            FIXTURES.iter().any(|(c, _)| c == chain),
            "no dispatch fixture for {chain}"
        );
    }
}

#[test]
fn an_address_from_the_wrong_chain_is_rejected() {
    // The dispatch must actually route: a Solana address handed to the Tron
    // arm has to fail, or the match is not doing its job.
    for (chain, address) in FIXTURES {
        for (other_chain, _) in FIXTURES {
            if chain == other_chain {
                continue;
            }
            assert!(
                validate(other_chain, address).is_err(),
                "{chain} address {address} was wrongly accepted as {other_chain}"
            );
        }
    }
}

#[test]
fn dispatch_rejects_empty_input_on_every_chain() {
    for (chain, _) in FIXTURES {
        assert!(
            validate(chain, "   ").is_err(),
            "{chain} accepted whitespace"
        );
    }
}
