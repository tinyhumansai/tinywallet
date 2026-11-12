//! Owner-local conversion from legacy x402 payment rows to the shared
//! `wallet.payments` storage record.

use serde::Deserialize;
use serde::de::Deserializer;
use tinywallet_bus::storage::{StoredPaymentRecord, StoredPaymentStatus};

pub(crate) type StoredPayment = StoredPaymentRecord;

/// Convert one previous camelCase `x402.payments` body to the current typed
/// `wallet.payments` storage contract.
///
/// The legacy row's ID and all optional payment and authorization data are
/// retained. RFC 3339 instants become epoch milliseconds, truncating
/// sub-millisecond precision. The caller owns source ordering and should keep
/// repeated IDs because they can represent successive payment states.
#[must_use]
pub(crate) fn convert_legacy_payment(legacy: LegacyPayment) -> StoredPaymentRecord {
    legacy.into()
}

/// Typed row from the previous camelCase `x402.payments` stream.
///
/// Deserialize the source row into this type before passing it to
/// [`convert_legacy_payment`]. Timestamp fields are parsed and normalized
/// during deserialization, so malformed or unsupported instants are rejected
/// before a canonical record is produced.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyPayment {
    /// Stable ID shared by successive states of the same payment attempt.
    pub id: String,
    /// The URL the payment bought access to.
    pub url: String,
    /// The asset paid in.
    pub asset: String,
    /// Amount in atomic units.
    pub amount_atomic: u64,
    /// Human-readable amount.
    pub amount_display: String,
    /// Payment recipient.
    pub recipient: String,
    /// CAIP-2 network identifier.
    pub network: String,
    #[serde(default)]
    /// Settlement transaction, if available.
    pub tx_signature: Option<String>,
    /// Payment lifecycle state.
    pub status: StoredPaymentStatus,
    #[serde(rename = "timestamp", deserialize_with = "instant_ms")]
    /// Timestamp of this state, normalized to epoch milliseconds.
    pub timestamp_ms: i64,
    #[serde(
        default,
        rename = "authorizationValidUntil",
        deserialize_with = "optional_instant_ms"
    )]
    /// Authorization expiration, normalized to epoch milliseconds.
    pub authorization_valid_until_ms: Option<i64>,
    #[serde(default)]
    /// Solana's `lastValidBlockHeight` for the exported transaction.
    pub solana_last_valid_block_height: Option<u64>,
    #[serde(
        default,
        rename = "authorizationExpiredAt",
        deserialize_with = "optional_instant_ms"
    )]
    /// Time when the authorization was observed expired, in epoch milliseconds.
    pub authorization_expired_at_ms: Option<i64>,
    #[serde(default)]
    /// Block height at which expiry was observed.
    pub authorization_expiry_observed_height: Option<u64>,
    /// Session that initiated the payment.
    pub session_id: String,
    #[serde(default)]
    /// Conversation thread that initiated the payment, if available.
    pub thread_id: Option<String>,
    #[serde(default, rename = "committed_hold")]
    /// Budget hold committed by this payment, if available.
    pub committed_hold: Option<String>,
}

impl From<LegacyPayment> for StoredPaymentRecord {
    fn from(legacy: LegacyPayment) -> Self {
        Self {
            id: legacy.id,
            url: legacy.url,
            asset: legacy.asset,
            amount_atomic: legacy.amount_atomic,
            amount_display: legacy.amount_display,
            recipient: legacy.recipient,
            network: legacy.network,
            tx_signature: legacy.tx_signature,
            status: legacy.status,
            timestamp_ms: legacy.timestamp_ms,
            authorization_valid_until_ms: legacy.authorization_valid_until_ms,
            solana_last_valid_block_height: legacy.solana_last_valid_block_height,
            authorization_expired_at_ms: legacy.authorization_expired_at_ms,
            authorization_expiry_observed_height: legacy.authorization_expiry_observed_height,
            session_id: legacy.session_id,
            thread_id: legacy.thread_id,
            // Legacy rows predate `upto`; every one of them was `exact`.
            scheme: None,
            committed_hold: legacy.committed_hold,
        }
    }
}

fn instant_ms<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    let text = String::deserialize(deserializer)?;
    parse_rfc3339_ms(&text)
        .ok_or_else(|| serde::de::Error::custom(format!("`{text}` is not an RFC 3339 instant")))
}

fn optional_instant_ms<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<i64>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|text| {
            parse_rfc3339_ms(&text).ok_or_else(|| {
                serde::de::Error::custom(format!("`{text}` is not an RFC 3339 instant"))
            })
        })
        .transpose()
}

/// Parse an RFC 3339 instant using integer arithmetic, truncating fractions
/// finer than milliseconds without introducing a date/time dependency into
/// the bus contract crate.
fn parse_rfc3339_ms(text: &str) -> Option<i64> {
    let bytes = text.as_bytes();
    let digits = |from: usize, len: usize| -> Option<i64> {
        let part = bytes.get(from..from + len)?;
        if !part.iter().all(u8::is_ascii_digit) {
            return None;
        }
        part.iter()
            .try_fold(0_i64, |n, d| Some(n * 10 + i64::from(d - b'0')))
    };
    let separator = |at: usize, want: &[u8]| bytes.get(at).is_some_and(|b| want.contains(b));
    if !(separator(4, b"-")
        && separator(7, b"-")
        && separator(10, b"Tt ")
        && separator(13, b":")
        && separator(16, b":"))
    {
        return None;
    }
    let (year, month, day) = (digits(0, 4)?, digits(5, 2)?, digits(8, 2)?);
    let (hour, minute, second) = (digits(11, 2)?, digits(14, 2)?, digits(17, 2)?);
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap_year => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=days_in_month).contains(&day) || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let mut at = 19;
    let mut millis = 0;
    if bytes.get(at) == Some(&b'.') {
        let start = at + 1;
        let mut end = start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end == start {
            return None;
        }
        for (place, digit) in bytes[start..end].iter().take(3).enumerate() {
            millis += i64::from(digit - b'0') * [100, 10, 1][place];
        }
        at = end;
    }
    let offset_minutes = match bytes.get(at)? {
        b'Z' | b'z' if at + 1 == bytes.len() => 0,
        sign @ (b'+' | b'-') if at + 6 == bytes.len() && separator(at + 3, b":") => {
            let hours = digits(at + 1, 2)?;
            let minute_part = digits(at + 4, 2)?;
            if hours > 23 || minute_part > 59 {
                return None;
            }
            let minutes = hours * 60 + minute_part;
            if *sign == b'-' { -minutes } else { minutes }
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant's algorithm), proleptic Gregorian.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let year_of_era = y - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second - offset_minutes * 60;
    Some(seconds * 1_000 + millis)
}

#[cfg(test)]
#[path = "schema_payment_tests.rs"]
mod tests;
