//! Tests that a requirement survives the round trip into `accepted`.
//!
//! A v2 server matches the `accepted` requirement it gets back against what it
//! advertised: every field outside `extra` must be equal, and `extra` must still
//! hold every server field. A field this crate does not model therefore has to
//! be echoed back untouched, or the payment is refused as an unknown option.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{PaymentRequired, PaymentRequirements};

const TWITR_UPTO: &str = include_str!("fixtures/twitr-upto-challenge.json");

fn twitr_upto() -> (PaymentRequired, serde_json::Value) {
    let raw: serde_json::Value = serde_json::from_str(TWITR_UPTO).unwrap();
    (serde_json::from_value(raw.clone()).unwrap(), raw)
}

#[test]
fn a_requirement_echoes_every_field_the_server_sent() {
    let (challenge, raw) = twitr_upto();
    let echoed = serde_json::to_value(&challenge.accepts[0]).unwrap();
    assert_eq!(echoed, raw["accepts"][0]);
}

#[test]
fn an_unmodelled_extra_field_round_trips() {
    let requirement: PaymentRequirements = serde_json::from_value(serde_json::json!({
        "scheme": "exact",
        "network": "eip155:8453",
        "amount": "1",
        "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
        "payTo": "0xb5194A98DbDBb7028B585Db26B972e7F0F3f826A",
        "maxTimeoutSeconds": 60,
        "extra": {"name": "USD Coin", "version": "2", "somethingNew": {"nested": [1, 2]}},
        "topLevelNew": true
    }))
    .unwrap();
    let echoed = serde_json::to_value(&requirement).unwrap();
    assert_eq!(echoed["extra"]["somethingNew"]["nested"][1], 2);
    assert_eq!(echoed["topLevelNew"], true);
}
