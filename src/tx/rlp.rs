//! Minimal RLP encoder — enough to serialise an Ethereum legacy transaction.
//!
//! RLP encodes exactly two things: a byte string and a list of items. That is
//! the whole specification, and a legacy transaction is one list of nine byte
//! strings, so this is deliberately small rather than a general-purpose codec.
//!
//! ## Why this is hand-written rather than a dependency
//!
//! An RLP crate would arrive with an entire Ethereum type stack behind it. The
//! encoder is under a hundred lines and is pinned against the published EIP-155
//! vector in [`super::evm`], which exercises every branch below — so the
//! trade is a small, tested, dependency-free encoder against a large
//! transitive graph.
//!
//! ## The integer rule is where RLP implementations go wrong
//!
//! RLP has no integer type. Numbers are encoded as **big-endian byte strings
//! with no leading zeros**, and zero is the *empty* string rather than `0x00`.
//! Get that wrong and the encoding is still well-formed RLP — it simply hashes
//! to a different value, so the signature is valid for a transaction nobody
//! meant to send. [`encode_uint`] is the only place that rule lives.

/// Encode a byte string.
///
/// Three cases, per the specification:
/// - a single byte below `0x80` is itself, with no prefix;
/// - up to 55 bytes take a `0x80 + len` prefix;
/// - longer takes `0xb7 + len_of_len`, then the length, then the payload.
pub(super) fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return vec![bytes[0]];
    }
    let mut out = encode_length(bytes.len(), 0x80);
    out.extend_from_slice(bytes);
    out
}

/// Encode a list of already-encoded items.
///
/// Takes encoded items rather than raw ones because RLP lists are defined over
/// encoded payloads — the length prefix covers the concatenated *encodings*,
/// not the values.
pub(super) fn encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = encode_length(payload.len(), 0xc0);
    out.extend_from_slice(&payload);
    out
}

/// Encode an unsigned integer as RLP's canonical big-endian, no-leading-zeros
/// byte string.
///
/// Zero encodes as the empty string — **not** as `0x00`. See the module docs:
/// this is the rule that silently changes what a signature commits to.
pub(super) fn encode_uint(value: u128) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    encode_bytes(&bytes[first..])
}

/// Encode a big-endian byte slice as an integer, stripping leading zeros.
///
/// Used for signature `r` and `s`, which are 32-byte values that must follow
/// the same no-leading-zeros rule as any other RLP integer.
pub(super) fn encode_uint_bytes(bytes: &[u8]) -> Vec<u8> {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    encode_bytes(&bytes[first..])
}

/// Build the length prefix for a payload, given the offset that distinguishes
/// strings (`0x80`) from lists (`0xc0`).
fn encode_length(len: usize, offset: u8) -> Vec<u8> {
    if len <= 55 {
        // `len` is at most 55 here, so this cannot truncate.
        #[allow(clippy::cast_possible_truncation)]
        return vec![offset + len as u8];
    }
    let len_bytes = len.to_be_bytes();
    let first = len_bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(len_bytes.len());
    let significant = &len_bytes[first..];
    // `significant.len()` is at most 8 (usize), well inside u8.
    #[allow(clippy::cast_possible_truncation)]
    let mut out = vec![offset + 55 + significant.len() as u8];
    out.extend_from_slice(significant);
    out
}

#[cfg(test)]
#[path = "rlp_test_tests.rs"]
mod test;
