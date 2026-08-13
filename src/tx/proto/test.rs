//! Tests for the Tron protobuf reader.
//!
//! The parser exists to catch a node that returned something other than what
//! was asked for, so most of these are malformed or adversarial inputs rather
//! than happy-path decodes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{Value, encode_varint, one_bytes, one_varint, optional_varint, parse_fields};

/// Build a `(number, wire_type)` protobuf key byte-sequence.
fn key(number: u64, wire: u64) -> Vec<u8> {
    encode_varint((number << 3) | wire)
}

/// Build one length-delimited field.
fn bytes_field(number: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = key(number, 2);
    out.extend(encode_varint(payload.len() as u64));
    out.extend(payload);
    out
}

/// Build one varint field.
fn varint_field(number: u64, value: u64) -> Vec<u8> {
    let mut out = key(number, 0);
    out.extend(encode_varint(value));
    out
}

#[test]
fn varint_round_trips_across_the_encoding_boundaries() {
    // 127/128 and 16383/16384 are where the continuation bit turns on.
    for value in [0, 1, 127, 128, 16383, 16384, u64::MAX] {
        let encoded = encode_varint(value);
        let field = {
            let mut out = key(1, 0);
            out.extend(&encoded);
            out
        };
        let fields = parse_fields(&field).unwrap();
        assert_eq!(one_varint(&fields, 1, "f").unwrap(), value);
    }
}

#[test]
fn parses_a_flat_message_of_mixed_wire_types() {
    let mut input = varint_field(3, 42);
    input.extend(bytes_field(2, b"hello"));
    let fields = parse_fields(&input).unwrap();

    assert_eq!(fields.len(), 2);
    assert_eq!(one_varint(&fields, 3, "amount").unwrap(), 42);
    assert_eq!(one_bytes(&fields, 2, "to").unwrap(), b"hello");
}

#[test]
fn nested_messages_are_parsed_by_recursing_on_the_borrowed_bytes() {
    let inner = varint_field(1, 7);
    let outer = bytes_field(11, &inner);

    let outer_fields = parse_fields(&outer).unwrap();
    let inner_bytes = one_bytes(&outer_fields, 11, "contract").unwrap();
    let inner_fields = parse_fields(inner_bytes).unwrap();

    assert_eq!(one_varint(&inner_fields, 1, "type").unwrap(), 7);
}

#[test]
fn fixed_width_wire_types_are_skipped_but_stay_in_sync() {
    // A fixed64 and a fixed32 the parser does not decode, followed by a field
    // it must still read correctly — the point being that miscounting either
    // width would desynchronise the stream and corrupt what follows.
    let mut input = key(1, 1);
    input.extend([0u8; 8]);
    input.extend(key(2, 5));
    input.extend([0u8; 4]);
    input.extend(varint_field(3, 99));

    let fields = parse_fields(&input).unwrap();
    assert!(matches!(fields[0].value, Value::Other));
    assert!(matches!(fields[1].value, Value::Other));
    assert_eq!(one_varint(&fields, 3, "after").unwrap(), 99);
}

#[test]
fn a_repeated_singular_field_is_refused_rather_than_disambiguated() {
    // The attack this guards: a node appends a second recipient, betting the
    // checker reads one occurrence and the chain reads the other.
    let mut input = bytes_field(2, b"first");
    input.extend(bytes_field(2, b"second"));

    let fields = parse_fields(&input).unwrap();
    assert!(one_bytes(&fields, 2, "to_address").is_err());

    let mut varints = varint_field(3, 1);
    varints.extend(varint_field(3, 2));
    let fields = parse_fields(&varints).unwrap();
    assert!(one_varint(&fields, 3, "amount").is_err());
    // Optional reads refuse repetition too — absent is a value, repeated is not.
    assert!(optional_varint(&fields, 3, "amount").is_err());
}

#[test]
fn an_absent_optional_field_is_none_but_an_absent_required_one_is_an_error() {
    let input = varint_field(1, 5);
    let fields = parse_fields(&input).unwrap();
    assert_eq!(optional_varint(&fields, 18, "fee_limit").unwrap(), None);
    assert!(one_varint(&fields, 18, "fee_limit").is_err());
    assert!(one_bytes(&fields, 18, "data").is_err());
}

#[test]
fn a_field_read_at_the_wrong_wire_type_is_refused() {
    let varint = varint_field(3, 42);
    let fields = parse_fields(&varint).unwrap();
    assert!(one_bytes(&fields, 3, "amount").is_err());

    let bytes = bytes_field(2, b"x");
    let fields = parse_fields(&bytes).unwrap();
    assert!(one_varint(&fields, 2, "to").is_err());
    assert!(optional_varint(&fields, 2, "to").is_err());
}

#[test]
fn field_number_zero_is_refused() {
    // Field 0 is illegal in protobuf; accepting it would let a crafted key
    // byte introduce a field no schema can name.
    assert!(parse_fields(&varint_field(0, 1)).is_err());
}

#[test]
fn unsupported_wire_types_are_refused_rather_than_skipped() {
    // Wire types 3 and 4 are the deprecated start/end-group markers. Skipping
    // an unknown type is impossible without knowing its width, so guessing
    // would desynchronise the stream.
    for wire in [3, 4, 6, 7] {
        assert!(parse_fields(&key(1, wire)).is_err(), "wire type {wire}");
    }
}

#[test]
fn truncated_input_is_refused_at_every_stage() {
    // Truncated varint: continuation bit set, nothing follows.
    assert!(parse_fields(&[0x08, 0x80]).is_err());
    // Truncated length-delimited payload: claims 5 bytes, supplies 2.
    assert!(parse_fields(&[0x12, 0x05, b'a', b'b']).is_err());
    // Truncated fixed64: claims 8 bytes, supplies 3.
    assert!(parse_fields(&[0x09, 0, 0, 0]).is_err());
}

#[test]
fn a_varint_that_overruns_64_bits_is_refused() {
    // Ten continuation bytes then a final byte above 1 — the tenth group
    // carries a single usable bit, so anything larger would be discarded
    // silently rather than overflow.
    let mut overlong = vec![0x08];
    overlong.extend(std::iter::repeat_n(0xff, 9));
    overlong.push(0x02);
    assert!(parse_fields(&overlong).is_err());

    // Eleven groups is too long regardless of the values.
    let mut too_long = vec![0x08];
    too_long.extend(std::iter::repeat_n(0x80, 11));
    too_long.push(0x00);
    assert!(parse_fields(&too_long).is_err());
}

#[test]
fn an_empty_message_parses_to_no_fields() {
    assert!(parse_fields(&[]).unwrap().is_empty());
}
