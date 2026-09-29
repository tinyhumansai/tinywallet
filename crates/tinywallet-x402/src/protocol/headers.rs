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
