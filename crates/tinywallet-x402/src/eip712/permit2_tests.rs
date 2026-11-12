//! Tests for the Permit2 `upto` witness and EIP-2612 `Permit` hashing.
//!
//! The digests are not this module's own output played back: they were
//! computed by viem's `hashTypedData` (the library the x402 reference client
//! signs with) over the reference implementation's own type definitions
//! (`uptoPermit2WitnessTypes`, `eip2612PermitTypes` in coinbase/x402
//! `typescript/packages/mechanisms/evm/src/constants.ts`). The signatures are
//! viem's `signTypedData` with the BIP-39 vector account, and k256 signs
//! deterministically (RFC 6979) exactly as viem does, so they must match too.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::super::{keccak, signing_digest, u256_from_decimal, u256_from_u64};
use super::*;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn address(text: &str) -> [u8; 20] {
    let body = text.trim_start_matches("0x");
    let mut out = [0u8; 20];
    for (index, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&body[index * 2..index * 2 + 2], 16).unwrap();
    }
    out
}

const USDC_BASE: &str = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
const PAYER: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

/// The twitr.sh volume-tool terms with a fixed nonce and deadline.
fn twitr_permit() -> UptoPermit {
    UptoPermit {
        token: address(USDC_BASE),
        amount: u256_from_u64(3600),
        spender: UPTO_PERMIT2_PROXY,
        nonce: u256_from_decimal(
            "33247007178036348590600198031289925668252061821958005840077069883511451257277",
        )
        .unwrap(),
        deadline: u256_from_u64(1_740_672_154),
        to: address("0xb5194A98DbDBb7028B585Db26B972e7F0F3f826A"),
        facilitator: address("0x4c934c63C786157Fefd990945b25eA60a0FB0205"),
        valid_after: u256_from_u64(0),
    }
}

#[test]
fn the_pinned_addresses_are_the_canonical_contracts() {
    assert_eq!(
        hex(&PERMIT2),
        "000000000022d473030f116ddee9f6b43ac78ba3",
        "canonical Permit2"
    );
    assert_eq!(
        hex(&UPTO_PERMIT2_PROXY),
        "4020a4f3b7b90cca423b9fabcc0ce57c6c240002",
        "x402UptoPermit2Proxy"
    );
}

#[test]
fn the_token_permissions_type_hash_is_permit2s_constant() {
    // `_TOKEN_PERMISSIONS_TYPEHASH` in Uniswap's PermitHash.sol.
    assert_eq!(
        hex(&keccak(TOKEN_PERMISSIONS_TYPE)),
        "618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1"
    );
}

#[test]
fn the_eip2612_permit_type_hash_is_the_published_constant() {
    // `PERMIT_TYPEHASH` from EIP-2612.
    assert_eq!(
        hex(&keccak(PERMIT_TYPE)),
        "6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9"
    );
}

#[test]
fn the_upto_digest_matches_the_reference_client() {
    let digest = signing_digest(
        permit2_domain_separator(8453),
        twitr_permit().struct_hash(),
    );
    assert_eq!(
        hex(&digest),
        "8e8c28bb23e744c0eb81bdfab664afc6c046d317a33873fdf0ffa275ecee94f9"
    );
}

#[test]
fn every_upto_field_is_bound_into_the_digest() {
    let base = twitr_permit().struct_hash();
    let changes: [fn(&mut UptoPermit); 8] = [
        |p| p.token[19] ^= 1,
        |p| p.amount[31] ^= 1,
        |p| p.spender[19] ^= 1,
        |p| p.nonce[31] ^= 1,
        |p| p.deadline[31] ^= 1,
        |p| p.to[19] ^= 1,
        |p| p.facilitator[19] ^= 1,
        |p| p.valid_after[31] ^= 1,
    ];
    for change in changes {
        let mut permit = twitr_permit();
        change(&mut permit);
        assert_ne!(permit.struct_hash(), base);
    }
    assert_ne!(
        permit2_domain_separator(8453),
        permit2_domain_separator(84532)
    );
}

#[test]
fn the_eip2612_digest_matches_the_reference_client() {
    let permit = Eip2612Permit {
        owner: address(PAYER),
        spender: PERMIT2,
        value: u256_from_u64(3600),
        nonce: u256_from_u64(7),
        deadline: u256_from_u64(1_740_672_154),
    };
    let domain = super::super::domain_separator(address(USDC_BASE), 8453, "USD Coin", "2");
    assert_eq!(
        hex(&signing_digest(domain, permit.struct_hash())),
        "f4935bb06c8d01cdab90133ce4a8c1040124320fb214773633ebaa37b3883cbe"
    );
}

#[test]
fn a_uint256_prints_as_the_decimal_it_was_parsed_from() {
    for text in [
        "0",
        "3600",
        "33247007178036348590600198031289925668252061821958005840077069883511451257277",
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    ] {
        assert_eq!(
            super::super::u256_to_decimal(&u256_from_decimal(text).unwrap()),
            text
        );
    }
}
