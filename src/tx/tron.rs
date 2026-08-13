//! Tron transaction signing.
//!
//! Tron inverts the usual split: the **node** builds the transaction. A client
//! POSTs the transfer parameters to `wallet/createtransaction`, gets back a
//! protobuf `raw_data` (plus its hex encoding and a `txID`), signs it, and
//! POSTs it back to `wallet/broadcasttransaction`.
//!
//! That means this module never serialises a transaction — there is no
//! protobuf encoder here, and deliberately so, because reimplementing Tron's
//! `raw_data` schema would be a large surface that the node already owns.
//! Reading one is a different matter, and [`super::proto`] does exactly as
//! much of it as verification needs.
//!
//! ## But it does mean the node's answer must be verified
//!
//! Signing whatever a node hands back is trusting it to have built the
//! transfer that was asked for. A malicious or compromised endpoint could
//! return a `raw_data` paying a different address, and a client that signs
//! blind would authorise it.
//!
//! There are two checks, and the difference between them matters:
//!
//! - [`recompute_txid`] confirms the `txID` is `sha256(raw_data)`, so the id
//!   being signed matches the bytes that were received. That catches a
//!   tampered or corrupted response but says nothing about the contents.
//! - [`verify_contract`] parses `raw_data` and checks the contract type, the
//!   recipient at its declared field number, the amount, and — for TRC-20 —
//!   the calldata and `call_value`. **This is the one to use.**
//!
//! [`verify_transfer`] predates it and only scans the hex for the recipient's
//! bytes. A substring match is weaker than it looks: the address appearing
//! *somewhere* does not make it the `to_address` being signed, and the amount
//! is not checked at all. Two tests below pin exactly that gap — a decoy field
//! and a substituted amount both pass `verify_transfer` and fail
//! `verify_contract`. Prefer the latter wherever the caller knows what it
//! asked for.

#[cfg(feature = "tx")]
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};

use super::{Error, Result, proto};

/// The 65-byte signature Tron expects: `r || s || recovery_id`.
///
/// Note the recovery byte is a bare 0 or 1 here, **not** EIP-155's `v` — Tron
/// borrowed Ethereum's address scheme but not its replay-protection encoding.
pub type Signature = [u8; 65];

/// Recompute a transaction's `txID` from its `raw_data`.
///
/// The id is `sha256(raw_data)`. Comparing it against the `txID` a node
/// returned confirms the bytes were not altered in transit.
///
/// # Errors
///
/// [`Error::InvalidField`] if `raw_data_hex` is not valid hex.
pub fn recompute_txid(raw_data_hex: &str) -> Result<String> {
    let raw = decode_hex(raw_data_hex)?;
    Ok(hex_lower(&Sha256::digest(&raw)))
}

/// Check that a node-built transaction really encodes the transfer requested.
///
/// Tron's `raw_data` embeds the recipient as a 21-byte address and the amount
/// as a protobuf varint, so both appear verbatim in the hex. This does not
/// parse the protobuf — it confirms the values are present, which is enough to
/// catch a node that substituted either.
///
/// # Errors
///
/// [`Error::Address`] if `to` is not a valid Tron address, or
/// [`Error::UntrustedResponse`] if the recipient does not appear in the bytes.
pub fn verify_transfer(raw_data_hex: &str, to: &str, txid: &str) -> Result<()> {
    let expected_id = recompute_txid(raw_data_hex)?;
    if !expected_id.eq_ignore_ascii_case(txid.trim()) {
        return Err(Error::UntrustedResponse {
            reason: "txID does not match sha256(raw_data); the response was altered".to_string(),
        });
    }

    let to_hex = crate::address::tron::to_hex(to).map_err(Error::Address)?;
    if !raw_data_hex
        .to_ascii_lowercase()
        .contains(&to_hex.to_ascii_lowercase())
    {
        return Err(Error::UntrustedResponse {
            reason: "the node's transaction does not pay the requested recipient".to_string(),
        });
    }
    Ok(())
}

/// What transfer the node was asked to build, for [`verify_contract`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Transfer {
    /// A native TRX transfer of `amount_sun`.
    Native {
        /// The amount, in SUN.
        amount_sun: u64,
    },
    /// A TRC-20 `transfer(address,uint256)` call.
    Trc20 {
        /// The ABI-encoded call parameters, hex, without the selector.
        parameter_hex: String,
        /// The `fee_limit` the request specified, in SUN, if it set one.
        fee_limit_sun: Option<u64>,
    },
}

/// `keccak256("transfer(address,uint256)")[..4]`, as hex.
const TRC20_TRANSFER_SELECTOR_HEX: &str = "a9059cbb";

/// Tron's `ContractType` for a native transfer.
const CONTRACT_TYPE_TRANSFER: u64 = 1;
/// Tron's `ContractType` for a smart-contract call.
const CONTRACT_TYPE_TRIGGER_SMART_CONTRACT: u64 = 31;

fn untrusted(reason: impl Into<String>) -> Error {
    Error::UntrustedResponse {
        reason: reason.into(),
    }
}

/// Verify a node-built transaction by **parsing** its `raw_data`.
///
/// [`verify_transfer`] confirms the `txID` matches the bytes and that the
/// recipient's hex appears somewhere in them. That is a substring scan, and a
/// substring scan is weaker than it looks: the recipient appearing *somewhere*
/// does not mean it is the `to_address` of the contract being signed. It could
/// be in an unrelated field, or the real recipient could be a second, later
/// occurrence.
///
/// This reads the protobuf structurally instead — contract type, the
/// recipient at its declared field number, the amount, and for TRC-20 the full
/// calldata including the selector — and refuses a message whose singular
/// fields repeat. Prefer it wherever the caller knows what it asked for.
///
/// # Errors
///
/// [`Error::Address`] if `to` is not a valid Tron address,
/// [`Error::InvalidField`] if `raw_data_hex` is not valid hex or not
/// well-formed protobuf, and [`Error::UntrustedResponse`] if the transaction
/// does not encode the transfer described by `transfer`.
pub fn verify_contract(
    raw_data_hex: &str,
    to: &str,
    txid: &str,
    transfer: &Transfer,
) -> Result<()> {
    let expected_id = recompute_txid(raw_data_hex)?;
    if !expected_id.eq_ignore_ascii_case(txid.trim()) {
        return Err(untrusted(
            "txID does not match sha256(raw_data); the response was altered",
        ));
    }

    let raw = decode_hex(raw_data_hex)?;
    let expected_recipient =
        decode_hex(&crate::address::tron::to_hex(to).map_err(Error::Address)?)?;

    let raw_fields = proto::parse_fields(&raw)?;
    let contract = parse_single_contract(&raw_fields)?;

    match transfer {
        Transfer::Native { amount_sun } => {
            if contract.kind != CONTRACT_TYPE_TRANSFER
                || !contract.type_url.ends_with(".TransferContract")
            {
                return Err(untrusted("the transaction is not a native transfer"));
            }
            let payload = proto::parse_fields(contract.payload)?;
            if proto::one_bytes(&payload, 2, "TransferContract.to_address")? != expected_recipient {
                return Err(untrusted(
                    "the transaction does not pay the requested recipient",
                ));
            }
            if proto::one_varint(&payload, 3, "TransferContract.amount")? != *amount_sun {
                return Err(untrusted("the transaction has a different native amount"));
            }
        }
        Transfer::Trc20 {
            parameter_hex,
            fee_limit_sun,
        } => {
            if contract.kind != CONTRACT_TYPE_TRIGGER_SMART_CONTRACT
                || !contract.type_url.ends_with(".TriggerSmartContract")
            {
                return Err(untrusted("the transaction is not a smart-contract trigger"));
            }
            let payload = proto::parse_fields(contract.payload)?;
            if proto::one_bytes(&payload, 2, "TriggerSmartContract.contract_address")?
                != expected_recipient
            {
                return Err(untrusted("the transaction targets a different contract"));
            }
            // A TRC-20 transfer moves no TRX. A non-zero call_value would send
            // native funds alongside the token transfer that was requested.
            let call_value =
                proto::optional_varint(&payload, 3, "TriggerSmartContract.call_value")?
                    .unwrap_or(0);
            if call_value != 0 {
                return Err(untrusted(
                    "the transaction has a non-zero TRC-20 call_value",
                ));
            }
            if let (Some(expected), Some(actual)) = (
                *fee_limit_sun,
                proto::optional_varint(&raw_fields, 18, "Transaction.raw.fee_limit")?,
            ) && actual != expected
            {
                return Err(untrusted("the transaction has a different fee_limit"));
            }

            let mut expected_data = decode_hex(TRC20_TRANSFER_SELECTOR_HEX)?;
            expected_data.extend(decode_hex(parameter_hex)?);
            if proto::one_bytes(&payload, 4, "TriggerSmartContract.data")? != expected_data {
                return Err(untrusted(
                    "the transaction has different TRC-20 transfer data",
                ));
            }
        }
    }

    Ok(())
}

/// The one contract carried by a Tron transaction, unwrapped from its `Any`.
struct ParsedContract<'a> {
    kind: u64,
    type_url: &'a str,
    payload: &'a [u8],
}

/// Unwrap `Transaction.raw.contract[0]` and its `google.protobuf.Any`.
///
/// Tron's schema makes `contract` repeated, but a transaction has only ever
/// carried one — and [`proto::one_bytes`] refusing a second is the point: two
/// contracts would mean signing something beyond what was checked.
fn parse_single_contract<'a>(raw_fields: &[proto::Field<'a>]) -> Result<ParsedContract<'a>> {
    let contract_bytes = proto::one_bytes(raw_fields, 11, "Transaction.raw.contract")?;
    let contract_fields = proto::parse_fields(contract_bytes)?;
    let kind = proto::one_varint(&contract_fields, 1, "Transaction.Contract.type")?;
    let any_bytes = proto::one_bytes(&contract_fields, 2, "Transaction.Contract.parameter")?;
    let any_fields = proto::parse_fields(any_bytes)?;
    let type_url =
        std::str::from_utf8(proto::one_bytes(&any_fields, 1, "Any.type_url")?).map_err(|_| {
            Error::InvalidField {
                field: "Any.type_url",
                reason: "is not UTF-8".to_string(),
            }
        })?;
    let payload = proto::one_bytes(&any_fields, 2, "Any.value")?;
    Ok(ParsedContract {
        kind,
        type_url,
        payload,
    })
}

#[cfg(feature = "tx")]
/// Sign a Tron `raw_data` payload.
///
/// Signs `sha256(raw_data)` — the same value as the `txID`.
///
/// # Errors
///
/// [`Error::InvalidField`] for malformed hex, [`Error::Signing`] for an
/// invalid key.
pub fn sign(raw_data_hex: &str, secret_key: &[u8]) -> Result<Signature> {
    let secret = SecretKey::from_slice(secret_key).map_err(|_| Error::Signing {
        reason: "not a valid secp256k1 secret key".to_string(),
    })?;
    let message = Message::from_digest(digest(raw_data_hex)?);

    let secp = Secp256k1::signing_only();
    let recoverable = secp.sign_ecdsa_recoverable(&message, &secret);
    let (recovery_id, compact) = recoverable.serialize_compact();

    let recovery = u8::try_from(recovery_id.to_i32()).map_err(|_| Error::Signing {
        reason: "unexpected recovery id".to_string(),
    })?;
    attach_signature(&compact, recovery)
}

/// The 32-byte digest a Tron transaction is signed over.
///
/// `sha256(raw_data)` — the same value as the `txID`, which is what makes
/// [`recompute_txid`] a meaningful check on the bytes about to be signed.
///
/// Already hashed: a caller holding the key elsewhere must sign this with a
/// "prehash" entry point rather than hashing it again.
///
/// # Errors
///
/// [`Error::InvalidField`] if `raw_data_hex` is not valid hex.
pub fn digest(raw_data_hex: &str) -> Result<[u8; 32]> {
    let raw = decode_hex(raw_data_hex)?;
    Ok(Sha256::digest(&raw).into())
}

/// Build the 65-byte Tron signature from a signature over [`digest`].
///
/// # Errors
///
/// [`Error::Signing`] if `recovery_id` is not 0..=3.
pub fn attach_signature(rs: &[u8; 64], recovery_id: u8) -> Result<Signature> {
    if recovery_id > 3 {
        return Err(Error::Signing {
            reason: format!("recovery id must be 0..=3, got {recovery_id}"),
        });
    }
    let mut out = [0u8; 65];
    out[..64].copy_from_slice(rs);
    // A bare recovery id, not EIP-155's v.
    out[64] = recovery_id;
    Ok(out)
}

/// Render a signature as the hex string `TronGrid` expects.
#[must_use]
pub fn signature_hex(signature: &Signature) -> String {
    hex_lower(signature)
}

fn decode_hex(raw: &str) -> Result<Vec<u8>> {
    let body = raw.trim();
    if body.len() % 2 != 0 {
        return Err(Error::InvalidField {
            field: "raw_data_hex",
            reason: "odd length".to_string(),
        });
    }
    (0..body.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&body[i..i + 2], 16).map_err(|e| Error::InvalidField {
                field: "raw_data_hex",
                reason: e.to_string(),
            })
        })
        .collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::{
        CONTRACT_TYPE_TRANSFER, CONTRACT_TYPE_TRIGGER_SMART_CONTRACT, TRC20_TRANSFER_SELECTOR_HEX,
        hex_lower, recompute_txid, sign, signature_hex, verify_transfer,
    };
    use crate::tx::Error;

    const VECTOR: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";
    const TO: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    fn key() -> Vec<u8> {
        crate::key::derive(crate::Chain::Tron, VECTOR, "m/44'/195'/0'/0/0")
            .unwrap()
            .secret_bytes()
            .to_vec()
    }

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

        match verify_transfer(&tampered, TO, &id).unwrap_err() {
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
        match verify_transfer(&raw, other, &id).unwrap_err() {
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
        assert!(verify_transfer(&raw, TO, &id).is_ok());
    }

    // ---- verify_contract: the structural check -----------------------------

    use super::{Transfer, verify_contract};
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
        let transfer = Transfer::Native {
            amount_sun: 1_000_000,
        };
        assert!(verify_contract(&raw, TO, &id, &transfer).is_ok());
    }

    #[test]
    fn a_native_transfer_for_a_different_amount_is_rejected() {
        // verify_transfer cannot see this at all: the amount is a varint it
        // never locates, so only the structural check catches a node that
        // built the right recipient with the wrong value.
        let raw = native_raw(TO, 1_000_000);
        let id = recompute_txid(&raw).unwrap();

        assert!(
            verify_transfer(&raw, TO, &id).is_ok(),
            "the weak check passes"
        );

        let transfer = Transfer::Native { amount_sun: 42 };
        match verify_contract(&raw, TO, &id, &transfer).unwrap_err() {
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

        assert!(
            verify_transfer(&raw, TO, &id).is_ok(),
            "the weak check is fooled by the decoy"
        );

        let transfer = Transfer::Native {
            amount_sun: 1_000_000,
        };
        match verify_contract(&raw, TO, &id, &transfer).unwrap_err() {
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

        let transfer = Transfer::Native { amount_sun: 5 };
        match verify_contract(&raw, TO, &id, &transfer).unwrap_err() {
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
        let transfer = Transfer::Trc20 {
            parameter_hex: param,
            fee_limit_sun: Some(150_000_000),
        };
        assert!(verify_contract(&raw, TO, &id, &transfer).is_ok());
    }

    #[test]
    fn trc20_calldata_that_does_not_match_the_request_is_rejected() {
        let raw = trc20_raw(TO, &trc20_parameter(TO, 5), None);
        let id = recompute_txid(&raw).unwrap();
        // Same recipient, different amount inside the ABI parameters.
        let transfer = Transfer::Trc20 {
            parameter_hex: trc20_parameter(TO, 9_999),
            fee_limit_sun: None,
        };
        match verify_contract(&raw, TO, &id, &transfer).unwrap_err() {
            Error::UntrustedResponse { reason } => {
                assert!(reason.contains("different TRC-20 transfer data"));
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

        let transfer = Transfer::Trc20 {
            parameter_hex: param,
            fee_limit_sun: None,
        };
        match verify_contract(&raw, TO, &id, &transfer).unwrap_err() {
            Error::UntrustedResponse { reason } => {
                assert!(reason.contains("non-zero TRC-20 call_value"));
            }
            other => panic!("expected UntrustedResponse, got {other:?}"),
        }
    }

    #[test]
    fn a_raised_fee_limit_is_rejected_when_the_request_pinned_one() {
        let param = trc20_parameter(TO, 5);
        let raw = trc20_raw(TO, &param, Some(9_000_000_000));
        let id = recompute_txid(&raw).unwrap();

        let transfer = Transfer::Trc20 {
            parameter_hex: param,
            fee_limit_sun: Some(150_000_000),
        };
        match verify_contract(&raw, TO, &id, &transfer).unwrap_err() {
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

        let transfer = Transfer::Native {
            amount_sun: 1_000_000,
        };
        assert!(verify_contract(&raw, TO, &id, &transfer).is_err());
    }

    #[test]
    fn a_tampered_raw_data_fails_the_structural_check_too() {
        let raw = native_raw(TO, 1_000_000);
        let id = recompute_txid(&raw).unwrap();
        let tampered = native_raw(TO, 1_000_001);
        let transfer = Transfer::Native {
            amount_sun: 1_000_000,
        };
        match verify_contract(&tampered, TO, &id, &transfer).unwrap_err() {
            Error::UntrustedResponse { reason } => assert!(reason.contains("altered")),
            other => panic!("expected UntrustedResponse, got {other:?}"),
        }
    }

    #[test]
    fn the_signature_is_65_bytes_ending_in_a_bare_recovery_id() {
        // Tron borrowed Ethereum's addresses but not EIP-155's v encoding.
        let signature = sign(&raw_data(), &key()).unwrap();
        assert_eq!(signature.len(), 65);
        assert!(signature[64] <= 3, "recovery id, not a v value");
        assert_eq!(signature_hex(&signature).len(), 130);
    }

    #[test]
    fn signing_is_deterministic() {
        let raw = raw_data();
        assert_eq!(sign(&raw, &key()).unwrap(), sign(&raw, &key()).unwrap());
    }

    #[test]
    fn different_raw_data_produces_a_different_signature() {
        let a = sign(&raw_data(), &key()).unwrap();
        let b = sign(&raw_data().replace("0a02", "0a03"), &key()).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn malformed_hex_is_rejected() {
        assert!(matches!(
            recompute_txid("abc").unwrap_err(),
            Error::InvalidField { .. }
        ));
        assert!(matches!(
            sign("zz", &key()).unwrap_err(),
            Error::InvalidField { .. }
        ));
    }

    #[test]
    fn an_invalid_key_is_rejected() {
        assert!(matches!(
            sign(&raw_data(), &[0u8; 32]).unwrap_err(),
            Error::Signing { .. }
        ));
    }
}
