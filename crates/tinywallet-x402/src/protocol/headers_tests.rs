//! Tests for reading the amount a settlement receipt actually charged.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::*;

fn receipt(success: bool, network: &str, amount: Option<&str>) -> SettlementResponse {
    SettlementResponse {
        success,
        transaction: String::new(),
        network: network.into(),
        payer: None,
        error_reason: None,
        amount: amount.map(Into::into),
        extensions: serde_json::Map::new(),
    }
}

const BASE: &str = "eip155:8453";

#[test]
fn an_upto_receipt_settles_for_the_amount_it_reports() {
    let cases = [
        (Some("1200"), Some(1200)),
        (Some("0"), Some(0)),
        (Some("3600"), Some(3600)),
        (Some("3601"), None),
        (Some("-1"), None),
        (Some("lots"), None),
        // `amount` is required for upto; without it, count the signed ceiling.
        (None, Some(3600)),
    ];
    for (reported, settled) in cases {
        assert_eq!(
            settled_amount(&receipt(true, BASE, reported), BASE, Some("upto"), 3600),
            settled,
            "{reported:?}"
        );
    }
}

#[test]
fn an_exact_receipt_must_report_the_signed_amount() {
    for scheme in [None, Some("exact")] {
        assert_eq!(
            settled_amount(&receipt(true, BASE, Some("2500")), BASE, scheme, 2500),
            Some(2500)
        );
        assert_eq!(
            settled_amount(&receipt(true, BASE, None), BASE, scheme, 2500),
            Some(2500)
        );
        assert_eq!(
            settled_amount(&receipt(true, BASE, Some("1")), BASE, scheme, 2500),
            None,
            "an exact payment cannot be under-reported"
        );
    }
}

#[test]
fn a_failed_or_foreign_receipt_settles_nothing() {
    assert_eq!(
        settled_amount(&receipt(false, BASE, Some("1")), BASE, Some("upto"), 3600),
        None
    );
    assert_eq!(
        settled_amount(
            &receipt(true, "eip155:1", Some("1")),
            BASE,
            Some("upto"),
            3600
        ),
        None
    );
}

#[test]
fn settles_is_the_exact_rule() {
    assert!(settles(&receipt(true, BASE, Some("2500")), BASE, 2500));
    assert!(settles(&receipt(true, BASE, None), BASE, 2500));
    assert!(!settles(&receipt(true, BASE, Some("2499")), BASE, 2500));
    assert!(!settles(&receipt(false, BASE, Some("2500")), BASE, 2500));
}
