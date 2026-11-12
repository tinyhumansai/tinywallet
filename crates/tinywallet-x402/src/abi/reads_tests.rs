//! Tests for the read-only ERC-20 / EIP-2612 calls the `upto` flow makes:
//! `allowance(owner, spender)` and `nonces(owner)`, and their `uint256` reply.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::keccak;
use super::*;

const OWNER: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const PERMIT2: &str = "0x000000000022D473030F116dDEE9F6B43aC78BA3";

#[test]
fn the_pinned_selectors_match_their_signatures() {
    assert_eq!(
        keccak(b"allowance(address,address)")[..4],
        ALLOWANCE_SELECTOR
    );
    assert_eq!(keccak(b"nonces(address)")[..4], NONCES_SELECTOR);
}

#[test]
fn allowance_calldata_is_the_selector_and_two_address_words() {
    assert_eq!(
        encode_erc20_allowance(OWNER, PERMIT2).unwrap(),
        "0xdd62ed3e\
         0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda94\
         000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3"
    );
}

#[test]
fn nonces_calldata_is_the_selector_and_one_address_word() {
    assert_eq!(
        encode_eip2612_nonces(OWNER).unwrap(),
        "0x7ecebe00\
         0000000000000000000000009858effd232b4033e47d90003d41ec34ecaeda94"
    );
}

#[test]
fn a_bad_address_is_refused() {
    assert!(matches!(
        encode_eip2612_nonces("0x1234"),
        Err(Error::InvalidRecipient { .. })
    ));
    assert!(encode_erc20_allowance(OWNER, "nope").is_err());
}

#[test]
fn a_uint256_reply_decodes_to_its_big_endian_word() {
    let word = decode_uint256("0x0000000000000000000000000000000000000000000000000000000000000e10")
        .unwrap();
    assert_eq!(word[30..], [0x0e, 0x10]);
    assert!(word[..30].iter().all(|b| *b == 0));
}

#[test]
fn a_reply_that_is_not_one_word_is_refused() {
    for reply in [
        "0x",
        "0x00",
        "",
        "0xzz00000000000000000000000000000000000000000000000000000000000000",
    ] {
        assert!(
            matches!(decode_uint256(reply), Err(Error::InvalidReply { .. })),
            "{reply}"
        );
    }
}
