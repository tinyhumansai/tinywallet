//! Tests for choosing the requirement to pay: which `upto` options are
//! payable, how they rank against `exact`, and the caller's network pin.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;
use crate::test_support::{challenge, evm_requirement, solana_requirement};
use crate::wire::{BASE_MAINNET_CAIP2, PaymentExtra};

const TWITR_UPTO: &str = include_str!("../wire/fixtures/twitr-upto-challenge.json");
const FACILITATOR: &str = "0x4c934c63C786157Fefd990945b25eA60a0FB0205";

fn upto_requirement(method: Option<&str>, facilitator: Option<&str>) -> PaymentRequirements {
    let mut requirement = evm_requirement();
    requirement.scheme = "upto".into();
    requirement.extra = Some(PaymentExtra {
        name: Some("USD Coin".into()),
        version: Some("2".into()),
        asset_transfer_method: method.map(Into::into),
        facilitator_address: facilitator.map(Into::into),
        ..PaymentExtra::default()
    });
    requirement
}

fn pick(accepts: Vec<PaymentRequirements>) -> Result<(usize, PaymentChain), X402Error> {
    select_requirement(&challenge(accepts), None)
}

#[test]
fn the_twitr_volume_challenge_selects_its_upto_option() {
    let twitr: PaymentRequired = serde_json::from_str(TWITR_UPTO).unwrap();
    assert_eq!(
        select_requirement(&twitr, None).unwrap(),
        (0, PaymentChain::Evm)
    );
}

#[test]
fn a_permit2_upto_option_is_payable() {
    let upto = upto_requirement(Some("permit2"), Some(FACILITATOR));
    assert_eq!(pick(vec![upto]).unwrap(), (0, PaymentChain::Evm));
}

#[test]
fn an_upto_option_without_a_transfer_method_defaults_to_permit2() {
    let upto = upto_requirement(None, Some(FACILITATOR));
    assert_eq!(pick(vec![upto]).unwrap(), (0, PaymentChain::Evm));
}

#[test]
fn exact_is_preferred_over_upto_whatever_the_order() {
    let upto = upto_requirement(Some("permit2"), Some(FACILITATOR));
    assert_eq!(
        pick(vec![upto.clone(), evm_requirement()]).unwrap(),
        (1, PaymentChain::Evm)
    );
    assert_eq!(
        pick(vec![upto, solana_requirement()]).unwrap(),
        (1, PaymentChain::Solana)
    );
}

#[test]
fn a_malformed_upto_option_is_never_selected() {
    let refused = [
        upto_requirement(Some("permit2"), None),
        upto_requirement(Some("permit2"), Some("0xnot-an-address")),
        upto_requirement(Some("eip3009"), Some(FACILITATOR)),
        {
            let mut no_extra = upto_requirement(None, Some(FACILITATOR));
            no_extra.extra = None;
            no_extra
        },
        {
            let mut on_solana = solana_requirement();
            on_solana.scheme = "upto".into();
            on_solana
        },
    ];
    for requirement in refused {
        assert!(
            matches!(pick(vec![requirement.clone()]), Err(X402Error::NoPaymentOption)),
            "{requirement:?} must not be selectable"
        );
    }
}

#[test]
fn an_upto_option_in_the_wrong_asset_is_refused_by_the_allowlist() {
    let mut upto = upto_requirement(Some("permit2"), Some(FACILITATOR));
    upto.asset = "0x1111111111111111111111111111111111111111".into();
    assert!(matches!(
        pick(vec![upto]),
        Err(X402Error::UnsupportedAsset { .. })
    ));
}

#[test]
fn a_network_pin_selects_only_matching_options() {
    let accepts = vec![solana_requirement(), evm_requirement()];
    let both = challenge(accepts);
    assert_eq!(
        select_requirement(&both, Some(BASE_MAINNET_CAIP2)).unwrap(),
        (1, PaymentChain::Evm)
    );
    assert_eq!(
        select_requirement(&both, Some("eip155")).unwrap(),
        (1, PaymentChain::Evm)
    );
    assert_eq!(
        select_requirement(&both, Some("solana")).unwrap(),
        (0, PaymentChain::Solana)
    );
}

#[test]
fn a_network_pin_with_no_match_is_refused() {
    let solana_only = challenge(vec![solana_requirement()]);
    for pin in ["eip155", BASE_MAINNET_CAIP2, "eip155:84532", "eip"] {
        let error = select_requirement(&solana_only, Some(pin)).unwrap_err();
        assert!(
            matches!(&error, X402Error::NoPaymentOptionOnNetwork { network } if network == pin),
            "{pin}: {error:?}"
        );
    }
}
