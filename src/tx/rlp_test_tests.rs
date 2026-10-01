#![allow(clippy::unwrap_used, clippy::panic)]

use super::{encode_bytes, encode_list, encode_uint, encode_uint_bytes};

#[test]
fn a_single_low_byte_is_itself() {
    assert_eq!(encode_bytes(&[0x00]), vec![0x00]);
    assert_eq!(encode_bytes(&[0x7f]), vec![0x7f]);
}

#[test]
fn a_single_high_byte_takes_a_prefix() {
    // 0x80 is not below 0x80, so it is a one-byte string, not a bare byte.
    assert_eq!(encode_bytes(&[0x80]), vec![0x81, 0x80]);
}

#[test]
fn an_empty_string_is_0x80() {
    assert_eq!(encode_bytes(&[]), vec![0x80]);
}

#[test]
fn short_strings_take_a_single_length_prefix() {
    // "dog" — the specification's own example.
    assert_eq!(encode_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
}

#[test]
fn strings_longer_than_55_bytes_take_a_length_of_length() {
    let payload = vec![0xaa_u8; 56];
    let encoded = encode_bytes(&payload);
    assert_eq!(encoded[0], 0xb8, "0xb7 + 1 length byte");
    assert_eq!(encoded[1], 56);
    assert_eq!(encoded.len(), 58);

    let long = vec![0xbb_u8; 1024];
    let encoded = encode_bytes(&long);
    assert_eq!(encoded[0], 0xb9, "0xb7 + 2 length bytes");
    assert_eq!(&encoded[1..3], &[0x04, 0x00]);
}

#[test]
fn zero_encodes_as_the_empty_string_not_as_a_zero_byte() {
    // The rule that silently changes what a signature commits to.
    assert_eq!(encode_uint(0), vec![0x80]);
    assert_ne!(encode_uint(0), vec![0x00]);
}

#[test]
fn integers_carry_no_leading_zeros() {
    assert_eq!(encode_uint(1), vec![0x01]);
    assert_eq!(encode_uint(127), vec![0x7f]);
    assert_eq!(encode_uint(128), vec![0x81, 0x80]);
    assert_eq!(encode_uint(1024), vec![0x82, 0x04, 0x00]);
    // 20 gwei, from the EIP-155 vector.
    assert_eq!(
        encode_uint(20_000_000_000),
        vec![0x85, 0x04, 0xa8, 0x17, 0xc8, 0x00]
    );
}

#[test]
fn integer_byte_slices_are_stripped_the_same_way() {
    let mut padded = [0u8; 32];
    padded[31] = 1;
    assert_eq!(encode_uint_bytes(&padded), vec![0x01]);
    assert_eq!(
        encode_uint_bytes(&[0u8; 32]),
        vec![0x80],
        "all-zero is empty"
    );
}

#[test]
fn an_empty_list_is_0xc0() {
    assert_eq!(encode_list(&[]), vec![0xc0]);
}

#[test]
fn a_list_prefixes_the_concatenated_encodings() {
    // ["cat", "dog"] from the specification.
    let items = vec![encode_bytes(b"cat"), encode_bytes(b"dog")];
    assert_eq!(
        encode_list(&items),
        vec![0xc8, 0x83, b'c', b'a', b't', 0x83, b'd', b'o', b'g']
    );
}

#[test]
fn a_long_list_takes_a_length_of_length() {
    let items: Vec<Vec<u8>> = (0..30).map(|_| encode_bytes(&[0xcc_u8; 2])).collect();
    let encoded = encode_list(&items);
    assert_eq!(encoded[0], 0xf8, "0xf7 + 1 length byte");
    assert_eq!(encoded[1], 90, "30 items x 3 bytes each");
}
