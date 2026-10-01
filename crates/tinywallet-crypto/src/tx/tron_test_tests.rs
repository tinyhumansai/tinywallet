#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use super::{
    CONTRACT_TYPE_TRANSFER, CONTRACT_TYPE_TRIGGER_SMART_CONTRACT, TRC20_TRANSFER_SELECTOR_HEX,
    attach_signature, digest, hex_lower, recompute_txid, signature_hex, verify_transfer,
};
use crate::TronTransfer;
use crate::tx::Error;

const TO: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

/// A `raw_data`-shaped hex blob embedding the recipient's hex address.
///
/// Not a real protobuf — `verify_transfer` deliberately does not parse
/// one, it checks the recipient's bytes are present, so a representative
/// blob is enough and avoids pinning a schema the node owns.
fn raw_data() -> String {
    let to_hex = crate::address::tron::to_hex(TO).unwrap();
    format!("0a02b1f42208{to_hex}5a0f")
}

#[test]
fn the_txid_is_sha256_of_the_raw_data() {
    let raw = raw_data();
    let id = recompute_txid(&raw).unwrap();
    assert_eq!(id.len(), 64, "sha256 is 32 bytes of hex");
    // Deterministic.
    assert_eq!(id, recompute_txid(&raw).unwrap());
}

#[test]
fn a_tampered_raw_data_no_longer_matches_its_txid() {
    // The defence against signing whatever a node hands back.
    let raw = raw_data();
    let id = recompute_txid(&raw).unwrap();
    let tampered = raw.replace("0a02", "0a03");
    assert_ne!(tampered, raw);

    match verify_transfer(&tampered, TO, &id, &TronTransfer::Native { amount_sun: 15 }).unwrap_err()
    {
        Error::UntrustedResponse { reason } => assert!(reason.contains("altered")),
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_transaction_paying_someone_else_is_rejected() {
    // A node that substituted the recipient must not get a signature.
    let raw = raw_data();
    let id = recompute_txid(&raw).unwrap();
    let other = "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH";
    match verify_transfer(&raw, other, &id, &TronTransfer::Native { amount_sun: 15 }).unwrap_err() {
        Error::UntrustedResponse { reason } => {
            assert!(reason.contains("does not pay the requested recipient"));
        }
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_well_formed_transaction_verifies() {
    let raw = raw_data();
    let id = recompute_txid(&raw).unwrap();
    assert!(verify_transfer(&raw, TO, &id, &TronTransfer::Native { amount_sun: 15 }).is_ok());
}

#[test]
fn a_native_transfer_with_the_wrong_amount_is_rejected() {
    let raw = raw_data();
    let id = recompute_txid(&raw).unwrap();
    let error =
        verify_transfer(&raw, TO, &id, &TronTransfer::Native { amount_sun: 16 }).unwrap_err();
    assert!(format!("{error:?}").contains("requested amount"));
}

#[test]
fn a_trc20_transfer_must_contain_the_exact_parameter() {
    let to_hex = crate::address::tron::to_hex(TO).unwrap();
    let parameter = format!("{}{}", "00".repeat(11), &to_hex[2..]);
    let raw = format!("0a02b1f42208{to_hex}5a{parameter}");
    let id = recompute_txid(&raw).unwrap();
    assert!(
        verify_transfer(
            &raw,
            TO,
            &id,
            &TronTransfer::Trc20 {
                parameter_hex: parameter.clone(),
            }
        )
        .is_ok()
    );
    let error = verify_transfer(
        &raw,
        TO,
        &id,
        &TronTransfer::Trc20 {
            parameter_hex: format!("{parameter}00"),
        },
    )
    .unwrap_err();
    assert!(format!("{error:?}").contains("TRC20 transfer parameter"));
}

#[test]
fn malformed_hex_is_rejected() {
    assert!(matches!(
        recompute_txid("abc").unwrap_err(),
        Error::InvalidField { .. }
    ));
}
#[test]
fn a_signature_is_r_s_and_a_bare_recovery_id() {
    // The assembly half of signing lives here even though producing the
    // 64 bytes does not: a host that signs elsewhere still has to put the
    // 65-byte value together, and getting the trailing byte wrong yields a
    // signature Tron rejects rather than one that fails to build.
    let signature = attach_signature(&[7u8; 64], 1).unwrap();
    assert_eq!(signature.len(), 65);
    assert_eq!(signature[64], 1, "a bare recovery id, not EIP-155's v");
    assert_eq!(signature_hex(&signature).len(), 130);

    assert!(matches!(
        attach_signature(&[7u8; 64], 4).unwrap_err(),
        Error::Signing { .. }
    ));
}

#[test]
fn the_digest_is_the_txid_bytes() {
    // `digest` and `recompute_txid` must not drift: the id a caller checks
    // against the node's answer is exactly the value it then signs.
    let raw = raw_data();
    assert_eq!(
        hex_lower(&digest(&raw).unwrap()),
        recompute_txid(&raw).unwrap()
    );
    assert!(matches!(
        digest("abc").unwrap_err(),
        Error::InvalidField { .. }
    ));
}

// ---- verify_contract: the structural check -----------------------------

use super::verify_contract;
use crate::tx::proto::encode_varint;

fn field(number: u64, wire: u64) -> Vec<u8> {
    encode_varint((number << 3) | wire)
}

fn bytes_field(number: u64, payload: &[u8]) -> Vec<u8> {
    let mut out = field(number, 2);
    out.extend(encode_varint(payload.len() as u64));
    out.extend(payload);
    out
}

fn varint_field(number: u64, value: u64) -> Vec<u8> {
    let mut out = field(number, 0);
    out.extend(encode_varint(value));
    out
}

fn to_bytes(address: &str) -> Vec<u8> {
    hex_decode(&crate::address::tron::to_hex(address).unwrap())
}

fn hex_decode(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
        .collect()
}

/// Wrap a contract payload in `Transaction.raw` → `contract` → `Any`.
fn wrap(kind: u64, type_url: &str, payload: &[u8], extra: &[u8]) -> String {
    let mut any = bytes_field(1, type_url.as_bytes());
    any.extend(bytes_field(2, payload));

    let mut contract = varint_field(1, kind);
    contract.extend(bytes_field(2, &any));

    let mut raw = bytes_field(11, &contract);
    raw.extend(extra);
    hex_lower(&raw)
}

fn native_raw(to: &str, amount_sun: u64) -> String {
    let mut payload = bytes_field(2, &to_bytes(to));
    payload.extend(varint_field(3, amount_sun));
    wrap(
        CONTRACT_TYPE_TRANSFER,
        "type.googleapis.com/protocol.TransferContract",
        &payload,
        &[],
    )
}

fn trc20_raw(contract_address: &str, parameter_hex: &str, fee_limit: Option<u64>) -> String {
    let mut data = hex_decode(TRC20_TRANSFER_SELECTOR_HEX);
    data.extend(hex_decode(parameter_hex));

    let mut payload = bytes_field(2, &to_bytes(contract_address));
    payload.extend(bytes_field(4, &data));

    let extra = fee_limit
        .map(|limit| varint_field(18, limit))
        .unwrap_or_default();
    wrap(
        CONTRACT_TYPE_TRIGGER_SMART_CONTRACT,
        "type.googleapis.com/protocol.TriggerSmartContract",
        &payload,
        &extra,
    )
}

/// 32-byte-padded recipient and amount, the ERC-20 `transfer` parameters.
fn trc20_parameter(to: &str, amount: u64) -> String {
    let recipient = to_bytes(to);
    let mut param = vec![0u8; 32];
    // Tron's 21-byte address drops its 0x41 prefix in ABI encoding.
    param[12..32].copy_from_slice(&recipient[1..21]);
    let mut amount_word = vec![0u8; 32];
    amount_word[24..32].copy_from_slice(&amount.to_be_bytes());
    param.extend(amount_word);
    hex_lower(&param)
}

#[test]
fn a_well_formed_native_transfer_verifies_structurally() {
    let raw = native_raw(TO, 1_000_000);
    let id = recompute_txid(&raw).unwrap();
    let transfer = TronTransfer::Native {
        amount_sun: 1_000_000,
    };
    assert!(verify_contract(&raw, TO, &id, &transfer, None).is_ok());
}

#[test]
fn a_native_transfer_for_a_different_amount_is_rejected() {
    // The amount is read from `TransferContract.amount` rather than found
    // anywhere in the bytes. `verify_transfer` also rejects this one — it
    // searches for the amount's varint as a byte run — but it rejects it
    // for a reason that happens to coincide, not because it looked at the
    // field. The decoy test below is where the two answers diverge.
    let raw = native_raw(TO, 1_000_000);
    let id = recompute_txid(&raw).unwrap();

    let transfer = TronTransfer::Native { amount_sun: 42 };
    match verify_contract(&raw, TO, &id, &transfer, None).unwrap_err() {
        Error::UntrustedResponse { reason } => {
            assert!(reason.contains("different native amount"));
        }
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_recipient_present_but_not_as_the_to_address_is_rejected() {
    // The substring scan's blind spot, made concrete: the requested
    // address appears in the bytes — as an unrelated trailing field —
    // while `to_address` pays someone else entirely.
    let other = "TLyqzVGLV1srkB7dToTAEqgDSfPtXRJZYH";
    let mut payload = bytes_field(2, &to_bytes(other));
    payload.extend(varint_field(3, 1_000_000));
    // Smuggle the requested recipient in somewhere harmless.
    let decoy = bytes_field(99, &to_bytes(TO));
    let raw = wrap(
        CONTRACT_TYPE_TRANSFER,
        "type.googleapis.com/protocol.TransferContract",
        &payload,
        &decoy,
    );
    let id = recompute_txid(&raw).unwrap();
    let transfer = TronTransfer::Native {
        amount_sun: 1_000_000,
    };

    // Both of `verify_transfer`'s checks are satisfied: the requested
    // address is present (in the decoy) and so is the amount's varint.
    // Neither is the field that will execute.
    assert!(
        verify_transfer(&raw, TO, &id, &transfer).is_ok(),
        "the positional-blind check is fooled by the decoy"
    );

    match verify_contract(&raw, TO, &id, &transfer, None).unwrap_err() {
        Error::UntrustedResponse { reason } => {
            assert!(reason.contains("does not pay the requested recipient"));
        }
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_trc20_call_dressed_as_a_native_transfer_is_rejected() {
    // Contract type is checked, so a token trigger cannot pass as TRX.
    let param = trc20_parameter(TO, 5);
    let raw = trc20_raw(TO, &param, None);
    let id = recompute_txid(&raw).unwrap();

    let transfer = TronTransfer::Native { amount_sun: 5 };
    match verify_contract(&raw, TO, &id, &transfer, None).unwrap_err() {
        Error::UntrustedResponse { reason } => {
            assert!(reason.contains("not a native transfer"));
        }
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_well_formed_trc20_transfer_verifies_structurally() {
    let param = trc20_parameter(TO, 5);
    let raw = trc20_raw(TO, &param, Some(150_000_000));
    let id = recompute_txid(&raw).unwrap();
    let transfer = TronTransfer::Trc20 {
        parameter_hex: param,
    };
    assert!(verify_contract(&raw, TO, &id, &transfer, Some(150_000_000)).is_ok());
}

#[test]
fn trc20_calldata_that_does_not_match_the_request_is_rejected() {
    let raw = trc20_raw(TO, &trc20_parameter(TO, 5), None);
    let id = recompute_txid(&raw).unwrap();
    // Same recipient, different amount inside the ABI parameters.
    let transfer = TronTransfer::Trc20 {
        parameter_hex: trc20_parameter(TO, 9_999),
    };
    match verify_contract(&raw, TO, &id, &transfer, None).unwrap_err() {
        Error::UntrustedResponse { reason } => {
            assert!(reason.contains("different TRC20 transfer data"));
        }
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_trc20_call_smuggling_native_value_is_rejected() {
    // call_value is field 3 of TriggerSmartContract. A token transfer
    // moves no TRX, so a non-zero value here is TRX leaving the wallet
    // alongside the transfer that was actually requested.
    let param = trc20_parameter(TO, 5);
    let mut data = hex_decode(TRC20_TRANSFER_SELECTOR_HEX);
    data.extend(hex_decode(&param));

    let mut payload = bytes_field(2, &to_bytes(TO));
    payload.extend(varint_field(3, 1_000_000)); // call_value
    payload.extend(bytes_field(4, &data));
    let raw = wrap(
        CONTRACT_TYPE_TRIGGER_SMART_CONTRACT,
        "type.googleapis.com/protocol.TriggerSmartContract",
        &payload,
        &[],
    );
    let id = recompute_txid(&raw).unwrap();

    let transfer = TronTransfer::Trc20 {
        parameter_hex: param,
    };
    match verify_contract(&raw, TO, &id, &transfer, None).unwrap_err() {
        Error::UntrustedResponse { reason } => {
            assert!(reason.contains("non-zero TRC20 call_value"));
        }
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_raised_fee_limit_is_rejected_when_the_request_pinned_one() {
    let param = trc20_parameter(TO, 5);
    let raw = trc20_raw(TO, &param, Some(9_000_000_000));
    let id = recompute_txid(&raw).unwrap();

    let transfer = TronTransfer::Trc20 {
        parameter_hex: param,
    };
    match verify_contract(&raw, TO, &id, &transfer, Some(150_000_000)).unwrap_err() {
        Error::UntrustedResponse { reason } => assert!(reason.contains("different fee_limit")),
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}

#[test]
fn a_second_contract_is_refused_rather_than_checked_once() {
    // Two contracts would mean signing something beyond what was verified,
    // so the singular read refuses the message outright.
    let mut payload = bytes_field(2, &to_bytes(TO));
    payload.extend(varint_field(3, 1_000_000));
    let mut any = bytes_field(1, b"type.googleapis.com/protocol.TransferContract");
    any.extend(bytes_field(2, &payload));
    let mut contract = varint_field(1, CONTRACT_TYPE_TRANSFER);
    contract.extend(bytes_field(2, &any));

    let mut raw = bytes_field(11, &contract);
    raw.extend(bytes_field(11, &contract));
    let raw = hex_lower(&raw);
    let id = recompute_txid(&raw).unwrap();

    let transfer = TronTransfer::Native {
        amount_sun: 1_000_000,
    };
    assert!(verify_contract(&raw, TO, &id, &transfer, None).is_err());
}

#[test]
fn a_tampered_raw_data_fails_the_structural_check_too() {
    let raw = native_raw(TO, 1_000_000);
    let id = recompute_txid(&raw).unwrap();
    let tampered = native_raw(TO, 1_000_001);
    let transfer = TronTransfer::Native {
        amount_sun: 1_000_000,
    };
    match verify_contract(&tampered, TO, &id, &transfer, None).unwrap_err() {
        Error::UntrustedResponse { reason } => assert!(reason.contains("altered")),
        other => panic!("expected UntrustedResponse, got {other:?}"),
    }
}
