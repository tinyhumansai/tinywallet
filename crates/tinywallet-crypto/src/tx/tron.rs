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
//!
//! ## But it does mean the node's answer must be verified
//!
//! Signing whatever a node hands back is trusting it to have built the
//! transfer that was asked for. A malicious or compromised endpoint could
//! return a `raw_data` paying a different address, and a client that signs
//! blind would authorise it.
//!
//! [`recompute_txid`] is the defence: the `txID` is `sha256(raw_data)`, so a
//! client can confirm the id it signs actually matches the bytes it was given.
//! That catches a tampered or corrupted response, though it cannot by itself
//! prove the *contents* match the request — [`verify_transfer`] does that, by
//! checking the recipient and amount appear in the returned bytes.

use sha2::{Digest, Sha256};

use super::{Error, Result, proto};
use crate::TronTransfer;

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
pub fn verify_transfer(
    raw_data_hex: &str,
    to: &str,
    txid: &str,
    transfer: &TronTransfer,
) -> Result<()> {
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

    let raw = decode_hex(raw_data_hex)?;
    let expected = match transfer {
        TronTransfer::Native { amount_sun } => proto::encode_varint(*amount_sun),
        TronTransfer::Trc20 { parameter_hex } => decode_hex(parameter_hex)?,
    };
    if expected.is_empty() || !raw.windows(expected.len()).any(|window| window == expected) {
        let field = match transfer {
            TronTransfer::Native { .. } => "amount",
            TronTransfer::Trc20 { .. } => "TRC20 transfer parameter",
        };
        return Err(Error::UntrustedResponse {
            reason: format!("the node's transaction does not contain the requested {field}"),
        });
    }
    Ok(())
}

/// Tron's `ContractType` for a native transfer.
const CONTRACT_TYPE_TRANSFER: u64 = 1;
/// Tron's `ContractType` for a smart-contract call.
const CONTRACT_TYPE_TRIGGER_SMART_CONTRACT: u64 = 31;
/// `keccak256("transfer(address,uint256)")[..4]`, as hex.
const TRC20_TRANSFER_SELECTOR_HEX: &str = "a9059cbb";

fn untrusted(reason: impl Into<String>) -> Error {
    Error::UntrustedResponse {
        reason: reason.into(),
    }
}

/// Verify a node-built transaction by **parsing** its `raw_data`.
///
/// [`verify_transfer`] confirms the `txID` matches the bytes, then looks for
/// the recipient and the amount as byte runs somewhere inside them. That is a
/// positional-blind search, and the gap it leaves is real: a value appearing
/// *somewhere* does not make it the field that will be executed. A node can
/// pay someone else and leave the requested address in an unrelated field, and
/// the scan is satisfied.
///
/// This reads the protobuf structurally instead. It checks the contract type,
/// the recipient at its declared field number, the amount, and for TRC-20 the
/// full calldata including the selector, the `call_value` and the `fee_limit`
/// — and refuses a message whose singular fields repeat, because "last one
/// wins" is how a second recipient gets past a checker that reads the first.
///
/// `fee_limit_sun` is the limit the caller pinned in its request, if it pinned
/// one; it is not part of [`TronTransfer`] because only the caller knows it.
///
/// Prefer this wherever the caller knows what it asked for.
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
    transfer: &TronTransfer,
    fee_limit_sun: Option<u64>,
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
        TronTransfer::Native { amount_sun } => {
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
        TronTransfer::Trc20 { parameter_hex } => {
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
                return Err(untrusted("the transaction has a non-zero TRC20 call_value"));
            }
            if let (Some(expected), Some(actual)) = (
                fee_limit_sun,
                proto::optional_varint(&raw_fields, 18, "Transaction.raw.fee_limit")?,
            ) {
                if actual != expected {
                    return Err(untrusted("the transaction has a different fee_limit"));
                }
            }

            let mut expected_data = decode_hex(TRC20_TRANSFER_SELECTOR_HEX)?;
            expected_data.extend(decode_hex(parameter_hex)?);
            if proto::one_bytes(&payload, 4, "TriggerSmartContract.data")? != expected_data {
                return Err(untrusted(
                    "the transaction has different TRC20 transfer data",
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
#[path = "tron_test_tests.rs"]
mod test;
