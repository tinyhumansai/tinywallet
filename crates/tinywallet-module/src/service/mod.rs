//! `TinyBus` service boundary for the wallet surface.
//!
//! One object, `/ai/tinyhumans/tinywallet/Wallet`, exporting two methods:
//!
//! ```text
//! BuildUnsigned(SigningRequest) -> UnsignedTransaction
//! AttachSignature(AttachRequest) -> SignedTransaction
//! ```
//!
//! # Two methods, and no state between them
//!
//! The host holds the key. It asks what needs signing, signs it locally, and
//! hands back only a signature — so no method here takes key material, and
//! there is nothing in this module a leak could disclose.
//!
//! `AttachSignature` re-sends the transaction fields rather than a handle to
//! something remembered from `BuildUnsigned`. A module that held half-built
//! transactions between calls would need a store, a bound on it, and an expiry
//! for callers that never return — the whole apparatus `tinydocs` needs for
//! produced documents. Rebuilding avoids all of it, and is safe because
//! building is deterministic: the same fields yield the transaction the digests
//! were computed over.
//!
//! # Everything travels inline
//!
//! This is the significant difference from the `tinydocs` module, and it is
//! what makes this one small. A `TinyBus` frame is JSON capped at 16 MiB, where
//! a byte array costs about 3.5 bytes per byte — a real constraint for a
//! generated `.docx`, and irrelevant here. The largest thing that crosses is a
//! Bitcoin spend's UTXO list; a wallet with a thousand of them is still tens of
//! kilobytes. So there are no streams, no chunking, and no held outputs.
//!
//! # Errors are named, and the names are the contract
//!
//! A host maps them onto what a user or a model can act on: a rejected input it
//! can fix, against a failure it cannot. Anything unrecognised must be treated
//! as the second — telling a model its input was wrong when it was not sends it
//! into a rewrite loop over something that was already correct.

use tinybus::{Connection, Error as BusError, Result as BusResult};
use tinywallet::tx;
use tinywallet::wire::{
    AttachRequest, Scheme, Signature, SignedTransaction, SigningPayload, SigningRequest,
    TransactionSpec, UnsignedTransaction,
};

/// Well-known name and interface exported by the `TinyWallet` module.
pub const BUS_NAME: &str = "ai.tinyhumans.tinywallet.Wallet";

/// Object path exported by the `TinyWallet` module.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinywallet/Wallet";

/// The request was malformed or internally inconsistent. A caller can fix it.
const INVALID_INPUT_ERROR: &str = "ai.tinyhumans.tinywallet.Error.InvalidInput";
/// Building or assembling the transaction failed. A caller cannot fix it.
const BUILD_FAILED_ERROR: &str = "ai.tinyhumans.tinywallet.Error.BuildFailed";
// There is no `UnsupportedChain` error name. Every chain this build can name
// is compiled in, and a chain it cannot name arrives as a `TransactionSpec`
// variant it does not recognise — which is `InvalidInput`, because the request
// is one this module cannot act on rather than a capability that is missing.

/// The served object. Holds nothing: every call is self-contained.
struct Wallet;

// The interface macro rejects a non-async method, so both methods are async
// because the dispatch contract says so, not because they await anything. This
// module performs no I/O at all.
#[allow(
    clippy::unused_async,
    reason = "tinybus::interface requires every method to be `async fn`"
)]
#[tinybus::interface(name = "ai.tinyhumans.tinywallet.Wallet")]
impl Wallet {
    /// Report the bytes a caller must sign for `request`.
    async fn build_unsigned(&self, request: SigningRequest) -> BusResult<UnsignedTransaction> {
        build_unsigned(&request).map_err(into_bus_error)
    }

    /// Assemble the broadcast-ready transaction from the caller's signatures.
    async fn attach_signature(&self, request: AttachRequest) -> BusResult<SignedTransaction> {
        attach_signature(&request).map_err(into_bus_error)
    }
}

/// Why a call failed, before it becomes a wire error name.
#[derive(Debug)]
enum Failure {
    /// The caller's request was wrong.
    InvalidInput(String),
    /// Building or assembling failed for a reason the caller did not cause.
    BuildFailed(String),
}

/// Map a failure onto the wire name a host matches on.
fn into_bus_error(failure: Failure) -> BusError {
    let (name, message) = match failure {
        Failure::InvalidInput(message) => (INVALID_INPUT_ERROR, message),
        Failure::BuildFailed(message) => (BUILD_FAILED_ERROR, message),
    };
    BusError::MethodFailed {
        name: name.to_string(),
        message,
    }
}

/// Compute the signing payloads for `request`.
fn build_unsigned(request: &SigningRequest) -> Result<UnsignedTransaction, Failure> {
    // `chain_of` runs first so an unrecognised shape is refused before any
    // arm is tried; the chain itself then comes from the variant.
    let payloads = match &request.transaction {
        TransactionSpec::Btc {
            from,
            to,
            amount_sat,
            fee_sat,
            utxos,
        } => {
            let transfer = btc_transfer(from, to, *amount_sat, *fee_sat);
            let public = compressed_public_key(&request.public_key.key_hex)?;
            let (_, digests) = transfer
                .sighashes(&btc_utxos(utxos), &public)
                .map_err(|e| build_failed(&e))?;
            digests.into_iter().map(secp256k1_payload).collect()
        }
        spec @ TransactionSpec::Evm { .. } => {
            vec![secp256k1_payload(
                evm_transaction(spec)?
                    .digest()
                    .map_err(|e| build_failed(&e))?,
            )]
        }
        spec @ TransactionSpec::Solana { .. } => {
            // ed25519 signs the message itself — there is nothing to pre-hash,
            // so this payload is the whole serialized message, not a digest.
            vec![SigningPayload {
                bytes_hex: hex(&solana_transfer(spec)?
                    .message()
                    .map_err(|e| build_failed(&e))?),
                scheme: Scheme::Ed25519,
            }]
        }
        TransactionSpec::Tron {
            raw_data_hex,
            expected_to,
            expected_txid,
            transfer,
        } => {
            // Tron's node builds the transaction, so the only defence against a
            // compromised endpoint is checking that what came back is what was
            // asked for — before signing it, which is here.
            //
            // `verify_contract`, not `verify_transfer`: the latter searches for
            // the recipient and amount as byte runs anywhere in `raw_data`, so a
            // node can pay someone else and leave the requested address in an
            // unrelated field and still be signed. This parses the protobuf and
            // reads the fields that will actually execute.
            //
            // `fee_limit_sun` is `None` because the wire spec does not carry it
            // — only the host knows what it pinned in its `createtransaction`
            // request, and it checks that before handing the spec over. Every
            // other field is checked here, on the side that holds the key.
            tx::tron::verify_contract(raw_data_hex, expected_to, expected_txid, transfer, None)
                .map_err(|e| Failure::InvalidInput(e.to_string()))?;
            vec![secp256k1_payload(
                tx::tron::digest(raw_data_hex).map_err(|e| build_failed(&e))?,
            )]
        }
        // Required because `TransactionSpec` is `#[non_exhaustive]`: a shape
        // added after this build must be refused, never guessed at.
        _ => return Err(unknown_kind()),
    };
    Ok(UnsignedTransaction { payloads })
}

/// Assemble the signed transaction for `request`.
fn attach_signature(request: &AttachRequest) -> Result<SignedTransaction, Failure> {
    match &request.transaction {
        TransactionSpec::Btc {
            from,
            to,
            amount_sat,
            fee_sat,
            utxos,
        } => {
            let transfer = btc_transfer(from, to, *amount_sat, *fee_sat);
            let public = compressed_public_key(&request.public_key.key_hex)?;
            let signatures = request
                .signatures
                .iter()
                .map(secp256k1_rs)
                .collect::<Result<Vec<_>, _>>()?;
            let raw = transfer
                .attach_signatures(&btc_utxos(utxos), &public, &signatures)
                .map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                // A Bitcoin txid is the hash of the serialized transaction, but
                // reporting it would mean hashing here and in the host; the
                // node returns it on broadcast, so it is left unset rather than
                // computed twice.
                txid: None,
                raw,
            })
        }
        spec @ TransactionSpec::Evm { .. } => {
            let (rs, recovery) = single_secp256k1(&request.signatures)?;
            let signed = evm_transaction(spec)?
                .attach_signature(&rs, recovery)
                .map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                txid: Some(tx::evm::LegacyTransaction::hash_of(&signed)),
                raw: format!("0x{}", hex(&signed)),
            })
        }
        spec @ TransactionSpec::Solana { .. } => {
            let signature = single_ed25519(&request.signatures)?;
            let signed = solana_transfer(spec)?
                .attach_signature(&signature)
                .map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                // Solana's signature *is* its id, base58-encoded. Encoded
                // here rather than through `address::solana::encode`, which
                // takes a 32-byte address — a signature is 64.
                txid: Some(bs58::encode(signature).into_string()),
                raw: base64(&signed),
            })
        }
        TransactionSpec::Tron {
            raw_data_hex,
            expected_to,
            expected_txid,
            transfer,
        } => {
            // Verified again rather than trusted from the first call: the two
            // requests are independent, and a host could reach this one with
            // different bytes than the digest was computed over. Structurally,
            // for the same reason as the sign path above.
            tx::tron::verify_contract(raw_data_hex, expected_to, expected_txid, transfer, None)
                .map_err(|e| Failure::InvalidInput(e.to_string()))?;
            let (rs, recovery) = single_secp256k1(&request.signatures)?;
            let signature =
                tx::tron::attach_signature(&rs, recovery).map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                txid: Some(expected_txid.clone()),
                raw: tx::tron::signature_hex(&signature),
            })
        }
        _ => Err(unknown_kind()),
    }
}

/// The refusal for a transaction shape added after this build.
///
/// `TransactionSpec` is `#[non_exhaustive]`, so a peer built against a newer
/// revision can send a variant this module cannot name. Refusing beats
/// guessing: the alternative is building some other chain's transaction.
fn unknown_kind() -> Failure {
    Failure::InvalidInput("this build does not understand that transaction kind".to_string())
}

/// Collapse a `tinywallet` build error, which is never the caller's fault by
/// the time it is reached — inputs are checked before building.
fn build_failed(error: &tx::Error) -> Failure {
    Failure::BuildFailed(error.to_string())
}

/// A secp256k1 payload over an already-computed digest.
fn secp256k1_payload(digest: [u8; 32]) -> SigningPayload {
    SigningPayload {
        bytes_hex: hex(&digest),
        scheme: Scheme::Secp256k1Prehash,
    }
}

/// The one secp256k1 signature a single-signature chain expects.
fn single_secp256k1(signatures: &[Signature]) -> Result<([u8; 64], u8), Failure> {
    let [only] = signatures else {
        return Err(Failure::InvalidInput(format!(
            "expected exactly one signature, got {}",
            signatures.len()
        )));
    };
    secp256k1_rs(only).map(|rs| (rs, recovery_of(only)))
}

/// The 64-byte `r ‖ s` of a secp256k1 signature.
fn secp256k1_rs(signature: &Signature) -> Result<[u8; 64], Failure> {
    match signature {
        Signature::Secp256k1 { rs_hex, .. } => fixed_hex::<64>(rs_hex, "signature"),
        Signature::Ed25519 { .. } => Err(Failure::InvalidInput(
            "expected a secp256k1 signature, got an ed25519 one".to_string(),
        )),
        // `Signature` is `#[non_exhaustive]`: a scheme this build has never
        // heard of cannot be reassembled, and guessing would produce a
        // well-formed transaction carrying nonsense.
        _ => Err(Failure::InvalidInput(
            "unrecognised signature scheme".to_string(),
        )),
    }
}

/// The recovery id of a secp256k1 signature, or zero for the wrong variant.
///
/// Only ever called after [`secp256k1_rs`] has confirmed the variant, so the
/// fallback is unreachable; it exists so this cannot panic inside a wallet.
fn recovery_of(signature: &Signature) -> u8 {
    match signature {
        Signature::Secp256k1 { recovery_id, .. } => *recovery_id,
        Signature::Ed25519 { .. } | _ => 0,
    }
}

/// The one ed25519 signature Solana expects.
fn single_ed25519(signatures: &[Signature]) -> Result<[u8; 64], Failure> {
    let [Signature::Ed25519 { signature_hex }] = signatures else {
        return Err(Failure::InvalidInput(
            "expected exactly one ed25519 signature".to_string(),
        ));
    };
    fixed_hex::<64>(signature_hex, "signature")
}

/// A compressed SEC1 public key from its hex.
fn compressed_public_key(key_hex: &str) -> Result<[u8; 33], Failure> {
    fixed_hex::<33>(key_hex, "public key")
}

/// Decode hex into exactly `N` bytes.
fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N], Failure> {
    let body = value.strip_prefix("0x").unwrap_or(value);
    if body.len() != N * 2 {
        return Err(Failure::InvalidInput(format!(
            "{what} must be {N} bytes, got {} hex characters",
            body.len()
        )));
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = body
            .get(index * 2..index * 2 + 2)
            .ok_or_else(|| Failure::InvalidInput(format!("{what} is truncated")))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| Failure::InvalidInput(format!("{what} is not hex")))?;
    }
    Ok(out)
}

/// Rebuild the Bitcoin transfer from its wire fields.
fn btc_transfer(from: &str, to: &str, amount_sat: u64, fee_sat: u64) -> tx::btc::Transfer {
    tx::btc::Transfer {
        from: from.to_string(),
        to: to.to_string(),
        amount: amount_sat,
        fee: fee_sat,
    }
}

/// Rebuild the UTXO set from its wire form.
fn btc_utxos(utxos: &[tinywallet::wire::Utxo]) -> Vec<tx::btc::Utxo> {
    utxos
        .iter()
        .map(|utxo| tx::btc::Utxo {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            value: utxo.value,
        })
        .collect()
}

/// Rebuild the EVM transaction from its wire fields.
fn evm_transaction(spec: &TransactionSpec) -> Result<tx::evm::LegacyTransaction, Failure> {
    let TransactionSpec::Evm {
        to,
        value_wei,
        data_hex,
        nonce,
        gas_limit,
        gas_price_wei,
        chain_id,
    } = spec
    else {
        return Err(Failure::InvalidInput(
            "expected an EVM transaction".to_string(),
        ));
    };

    Ok(tx::evm::LegacyTransaction {
        nonce: u128::from(*nonce),
        gas_price: decimal_u128(gas_price_wei, "gas_price_wei")?,
        gas_limit: u128::from(*gas_limit),
        // An empty recipient is contract creation, which a wallet transfer
        // never is — but the field models it, so an empty string maps to it
        // rather than being silently treated as an address.
        to: if to.trim().is_empty() {
            None
        } else {
            Some(to.clone())
        },
        value: decimal_u128(value_wei, "value_wei")?,
        data: decode_hex(data_hex)?,
        chain_id: *chain_id,
    })
}

/// Rebuild the Solana transfer from its wire fields.
fn solana_transfer(spec: &TransactionSpec) -> Result<tx::solana::NativeTransfer, Failure> {
    let TransactionSpec::Solana {
        from,
        to,
        lamports,
        recent_blockhash,
    } = spec
    else {
        return Err(Failure::InvalidInput(
            "expected a Solana transaction".to_string(),
        ));
    };
    Ok(tx::solana::NativeTransfer {
        from: from.clone(),
        to: to.clone(),
        lamports: *lamports,
        recent_blockhash: recent_blockhash.clone(),
    })
}

/// Parse a base-10 wei amount.
///
/// `u128` rather than a 256-bit type because that is what
/// `LegacyTransaction` takes: wei amounts and gas prices live far below 2^128,
/// and the RLP encoder is written against it.
fn decimal_u128(value: &str, field: &str) -> Result<u128, Failure> {
    value.trim().parse().map_err(|_| {
        Failure::InvalidInput(format!(
            "{field} is not a base-10 integer that fits in 128 bits"
        ))
    })
}

/// Decode optionally-`0x`-prefixed hex of any length.
fn decode_hex(value: &str) -> Result<Vec<u8>, Failure> {
    let body = value.strip_prefix("0x").unwrap_or(value).trim();
    if body.is_empty() {
        return Ok(Vec::new());
    }
    if body.len() % 2 != 0 {
        return Err(Failure::InvalidInput(
            "call data has an odd number of hex characters".to_string(),
        ));
    }
    (0..body.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&body[index..index + 2], 16)
                .map_err(|_| Failure::InvalidInput("call data is not hex".to_string()))
        })
        .collect()
}

/// Lowercase hex, unprefixed.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Standard base64, which is what Solana's `sendTransaction` takes.
///
/// Hand-rolled rather than pulled in: it is one table and a three-byte loop,
/// and this module has no other use for an encoding crate.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(char::from(TABLE[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

async fn setup(connection: Connection) -> BusResult<()> {
    connection.serve_at(OBJECT_PATH.try_into()?, Wallet).await?;
    connection.request_name(BUS_NAME).await?;
    Ok(())
}

// Isolate the generated public C symbols so the lint exception cannot hide
// undocumented Rust API. Their contract is TinyBus ABI v1, and none is a
// Rust-callable export from this private module.
#[allow(
    missing_docs,
    unreachable_pub,
    reason = "generated C ABI symbols are documented by the TinyBus module SDK"
)]
mod exports {
    tinybus_module::module_export! {
        setup = super::setup,
        worker_threads = 2,
        provides = ["ai.tinyhumans.tinywallet.Wallet"],
        methods = ["BuildUnsigned", "AttachSignature"],
        signals = [],
        requires = [],
        optional = [],
        lazy = false,
    }
}

#[cfg(test)]
mod test;
