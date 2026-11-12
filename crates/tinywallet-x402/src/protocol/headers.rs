//! The `PAYMENT-REQUIRED` challenge and `PAYMENT-RESPONSE` settlement headers,
//! both base64-encoded JSON, and the encoding of the proof that answers them.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use log::warn;
use reqwest::header::HeaderMap;

use super::LOG_PREFIX;
use super::error::X402Error;
use crate::wire::{
    HEADER_PAYMENT_REQUIRED, HEADER_PAYMENT_REQUIRED_V1, PaymentPayload, PaymentRequired,
    SettlementResponse, X402_VERSION,
};

/// Read the 402 challenge out of a response's headers.
///
/// Accepts the v2 header name and the v1 spelling. A challenge with an
/// unexpected `x402Version` is still returned, with a warning: servers that
/// mislabel the version usually still speak the v2 shape.
///
/// # Errors
///
/// [`X402Error::NoPaymentHeader`] when neither header is present, and
/// [`X402Error::Protocol`] when the header is not UTF-8, base64 or a challenge.
pub fn parse_402_headers(headers: &HeaderMap) -> Result<PaymentRequired, X402Error> {
    let raw = headers
        .get(HEADER_PAYMENT_REQUIRED)
        .or_else(|| headers.get(HEADER_PAYMENT_REQUIRED_V1))
        .ok_or(X402Error::NoPaymentHeader)?;
    let b64_str = raw.to_str().map_err(|e| {
        X402Error::Protocol(format!("PAYMENT-REQUIRED header not valid UTF-8: {e}"))
    })?;
    let json_bytes = B64
        .decode(b64_str.trim())
        .map_err(|e| X402Error::Protocol(format!("PAYMENT-REQUIRED base64 decode: {e}")))?;
    let challenge: PaymentRequired = serde_json::from_slice(&json_bytes)
        .map_err(|e| X402Error::Protocol(format!("PAYMENT-REQUIRED JSON parse: {e}")))?;
    if challenge.x402_version != X402_VERSION {
        warn!(
            "{LOG_PREFIX} unexpected x402 version {} (expected {X402_VERSION})",
            challenge.x402_version
        );
    }
    Ok(challenge)
}

/// Read a `PAYMENT-RESPONSE` header value.
///
/// # Errors
///
/// A description of what failed to decode, as a plain string: the caller only
/// logs it, since a receipt that cannot be read does not undo the payment.
pub fn parse_settlement_response(b64_str: &str) -> Result<SettlementResponse, String> {
    let json_bytes = B64
        .decode(b64_str.trim())
        .map_err(|e| format!("PAYMENT-RESPONSE base64 decode: {e}"))?;
    serde_json::from_slice(&json_bytes).map_err(|e| format!("PAYMENT-RESPONSE JSON parse: {e}"))
}

/// Whether `receipt` settles the `exact` payment we sent: a successful receipt
/// for the same network and, when the receipt names one, the same atomic
/// amount. See [`settled_amount`] for a payment of any scheme.
#[must_use]
pub fn settles(receipt: &SettlementResponse, network: &str, amount_atomic: u64) -> bool {
    settled_amount(receipt, network, None, amount_atomic).is_some()
}

/// The atomic amount `receipt` says was charged for a payment signed for
/// `signed_atomic` under `scheme`, or `None` when it does not settle it.
///
/// A receipt settles only when it succeeded on the payment's network. Then:
///
/// - `upto`: the reported `amount`, which may be anything from zero to the
///   signed ceiling. A larger or unreadable amount settles nothing. A receipt
///   without one (the field is required for `upto`) counts the whole ceiling.
/// - `exact`, or no scheme recorded: the signed amount, and only if the
///   receipt names no amount or exactly that one, so a receipt cannot make an
///   exact payment look cheaper than what was signed.
#[must_use]
pub fn settled_amount(
    receipt: &SettlementResponse,
    network: &str,
    scheme: Option<&str>,
    signed_atomic: u64,
) -> Option<u64> {
    if !receipt.success || receipt.network != network {
        return None;
    }
    let reported = receipt.amount.as_deref().map(str::parse::<u64>);
    match (scheme, reported) {
        (Some("upto"), None) => Some(signed_atomic),
        (Some("upto"), Some(Ok(actual))) => (actual <= signed_atomic).then_some(actual),
        (Some("upto"), Some(Err(_))) => None,
        (_, None) => Some(signed_atomic),
        (_, Some(reported)) => (reported == Ok(signed_atomic)).then_some(signed_atomic),
    }
}

/// Encode a payment proof as the `PAYMENT-SIGNATURE` header value.
///
/// # Errors
///
/// [`X402Error::Protocol`] if the payload cannot be serialised.
pub fn encode_payment(payment: &PaymentPayload) -> Result<String, X402Error> {
    serde_json::to_string(payment)
        .map(|json| B64.encode(json))
        .map_err(|e| X402Error::Protocol(format!("serialize payment: {e}")))
}

#[cfg(test)]
#[path = "headers_tests.rs"]
mod tests;
