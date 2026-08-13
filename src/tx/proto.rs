//! The sliver of protobuf wire format a Tron transaction actually needs.
//!
//! Tron has the node build a transaction and hand it back, so a client that
//! signs what it is given signs whatever a compromised endpoint chose to
//! return. Checking it means reading the `raw_data` bytes — and `raw_data` is
//! protobuf.
//!
//! A full protobuf implementation is a schema compiler plus a runtime. What is
//! needed here is a reader for four wire types over a message whose shape is
//! already known, which is why this is ~120 lines of `&[u8]` walking rather
//! than a `prost` dependency and a `build.rs`. The parser is deliberately
//! *structural*: it recovers field numbers and their raw values and stops
//! there, leaving the meaning of field 11 to [`super::tron`].
//!
//! It borrows throughout — [`Value::Bytes`] points into the caller's buffer —
//! so parsing a nested message costs no allocation beyond the field vector.
//!
//! # Strictness
//!
//! Every accessor here is *singular*: it refuses a field that repeats rather
//! than taking the first or the last. That is not pedantry about the spec,
//! which does permit repetition. It is that "last one wins" is exactly how a
//! malicious node smuggles a second recipient past a checker that reads the
//! first — so a repeated singular field is treated as the attack it would be,
//! not as a value to disambiguate.

use super::{Error, Result};

/// A field's value, as far as the wire format alone can tell.
#[derive(Debug)]
pub enum Value<'a> {
    /// Wire type 0: a base-128 varint.
    Varint(u64),
    /// Wire type 2: a length-delimited byte run, borrowed from the input.
    Bytes(&'a [u8]),
    /// Wire types 1 and 5: fixed-width, skipped rather than decoded.
    ///
    /// Nothing this crate reads out of a Tron transaction is fixed-width, so
    /// decoding them would be unused code on a security-relevant path. They
    /// are still *consumed* correctly, because the parser has to stay in sync
    /// with the byte stream to read the fields that do matter.
    Other,
}

/// One field of a protobuf message: its number, and its value.
#[derive(Debug)]
pub struct Field<'a> {
    /// The field number, as declared in the `.proto`.
    pub number: u64,
    /// The decoded value.
    pub value: Value<'a>,
}

fn invalid(reason: impl Into<String>) -> Error {
    Error::InvalidField {
        field: "protobuf",
        reason: reason.into(),
    }
}

/// Encode a `u64` as a base-128 varint.
///
/// The inverse of [`take_varint`], and the only writer here: it is needed to
/// re-encode a field when checking a node's transaction byte-for-byte.
#[must_use]
pub fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut encoded = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        encoded.push(byte);
        if value == 0 {
            return encoded;
        }
    }
}

/// Parse a flat protobuf message into its fields.
///
/// Does not recurse: a nested message arrives as [`Value::Bytes`] and is
/// parsed by calling this again on it. That keeps the borrow flat and lets the
/// caller decide how deep to go.
///
/// # Errors
///
/// [`Error::InvalidField`] if the input is truncated, carries field number
/// zero, uses a wire type this parser does not implement (3 and 4, the
/// deprecated groups), or contains a varint that overruns 64 bits.
pub fn parse_fields(mut input: &[u8]) -> Result<Vec<Field<'_>>> {
    let mut fields = Vec::new();
    while !input.is_empty() {
        let key = take_varint(&mut input)?;
        let number = key >> 3;
        if number == 0 {
            return Err(invalid("contains field zero"));
        }
        let value = match key & 0x07 {
            0 => Value::Varint(take_varint(&mut input)?),
            1 => {
                take_exact(&mut input, 8)?;
                Value::Other
            }
            2 => {
                let length = usize::try_from(take_varint(&mut input)?)
                    .map_err(|_| invalid("field length is too large"))?;
                Value::Bytes(take_exact(&mut input, length)?)
            }
            5 => {
                take_exact(&mut input, 4)?;
                Value::Other
            }
            wire => return Err(invalid(format!("unsupported wire type {wire}"))),
        };
        fields.push(Field { number, value });
    }
    Ok(fields)
}

/// Read exactly one length-delimited field.
///
/// # Errors
///
/// [`Error::InvalidField`] if the field is absent, repeated, or not
/// length-delimited.
pub fn one_bytes<'a>(fields: &[Field<'a>], number: u64, name: &str) -> Result<&'a [u8]> {
    match single(fields, number, name)? {
        Value::Bytes(value) => Ok(value),
        _ => Err(invalid(format!("field {name} has the wrong wire type"))),
    }
}

/// Read exactly one varint field.
///
/// # Errors
///
/// [`Error::InvalidField`] if the field is absent, repeated, or not a varint.
pub fn one_varint(fields: &[Field<'_>], number: u64, name: &str) -> Result<u64> {
    optional_varint(fields, number, name)?.ok_or_else(|| invalid(format!("is missing {name}")))
}

/// Read at most one varint field.
///
/// `Ok(None)` means absent, which for an optional protobuf field is a value
/// rather than an error — but a *repeated* one is still refused.
///
/// # Errors
///
/// [`Error::InvalidField`] if the field repeats or is not a varint.
pub fn optional_varint(fields: &[Field<'_>], number: u64, name: &str) -> Result<Option<u64>> {
    let mut matches = fields.iter().filter(|field| field.number == number);
    let Some(field) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err(invalid(format!("repeats singular field {name}")));
    }
    match field.value {
        Value::Varint(value) => Ok(Some(value)),
        _ => Err(invalid(format!("field {name} has the wrong wire type"))),
    }
}

/// The shared "exactly one, or refuse" lookup behind the accessors above.
fn single<'f, 'a>(fields: &'f [Field<'a>], number: u64, name: &str) -> Result<&'f Value<'a>> {
    let mut matches = fields.iter().filter(|field| field.number == number);
    let Some(field) = matches.next() else {
        return Err(invalid(format!("is missing {name}")));
    };
    if matches.next().is_some() {
        return Err(invalid(format!("repeats singular field {name}")));
    }
    Ok(&field.value)
}

/// Decode one base-128 varint, advancing `input` past it.
fn take_varint(input: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..=63).step_by(7) {
        let (&byte, rest) = input
            .split_first()
            .ok_or_else(|| invalid("truncated varint"))?;
        *input = rest;
        let part = u64::from(byte & 0x7f);
        // At shift 63 only one bit is left, so a part above 1 would silently
        // discard the high bits rather than overflow.
        if shift == 63 && part > 1 {
            return Err(invalid("varint overflows u64"));
        }
        value |= part << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(invalid("varint is too long"))
}

/// Split exactly `length` bytes off the front of `input`.
fn take_exact<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8]> {
    if input.len() < length {
        return Err(invalid("truncated field"));
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

#[cfg(test)]
#[path = "proto/test.rs"]
mod test;
