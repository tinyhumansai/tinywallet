//! `TinyBus` service boundary for the wallet surface.
//!
//! One object, `/ai/tinyhumans/tinywallet/Wallet`, exporting two flows:
//!
//! ```text
//! // The host holds the key.
//! BuildUnsigned(SigningRequest)   -> UnsignedTransaction
//! AttachSignature(AttachRequest)  -> SignedTransaction
//!
//! // This module holds the key. Confidential calls only.
//! DeriveAccount(SecretMaterial)   -> DerivedAccount
//! SignTransaction(SignRequest)    -> SignedTransaction
//! ExportKey(ExportRequest)        -> ExportedKey
//! SignMessage(SignMessageRequest) -> Signature
//! ```
//!
//! # Two flows, because there are two kinds of host
//!
//! The first pair keeps the key in the host: it asks what needs signing, signs
//! locally, and hands back only a signature. That is the right arrangement
//! whenever the backend is *reachable* — a service in its own process, across a
//! socket — and the only one available when the bus cannot say what is on the
//! other end.
//!
//! The second set exists because tinybus can now say. A confidential message is
//! delivered to a module whose artifact the host hashed against a digest an
//! operator asserted, or to nobody: never to a transport peer, never fanned out
//! to a subscriber, never printed by a monitor. For a host that loads this
//! module that is strictly better — it stops linking the derivation and signing
//! stack at all, and the key stops being reassembled in a process whose main job
//! is something else.
//!
//! **This is admission control, not isolation.** A loaded module shares the
//! host's address space and can read host memory directly; it never needed the
//! bus to reach a secret. What the rule buys is that the bus will not be the
//! delivery mechanism for code nobody allowlisted. Neither flow is deprecated,
//! and a backend whose compromise must not reach a key belongs in a separate
//! process — where it is ineligible for the second set by construction.
//!
//! # No state between calls, in either flow
//!
//! A confidential call is one method, not two, for the same reason
//! `AttachSignature` re-sends its fields: a module that held key material
//! between calls would need a store, a bound on it, and an expiry for callers
//! that never return. `SignTransaction` derives, builds, signs and assembles
//! before it returns, so there is no window to bound.
//!
//! Rebuilding rather than remembering is safe because building is
//! deterministic: the same fields yield the transaction the digests were
//! computed over.
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
use tinywallet::wire::{
    AttachRequest, DerivedAccount, ExportRequest, ExportedKey, PublicKey, Scheme, SecretMaterial,
    SignMessageRequest, SignRequest, Signature, SignedTransaction, SigningPayload, SigningRequest,
    TransactionSpec, UnsignedTransaction,
};
use tinywallet::{Chain, key, tx};

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

    /// Report the address and public key for a phrase, without disclosing a key.
    ///
    /// Confidential: the request carries a recovery phrase. The reply does not
    /// — both of its fields are public information.
    async fn derive_account(&self, mut secret: SecretMaterial) -> BusResult<DerivedAccount> {
        let result = derive_account(&secret);
        wipe(&mut secret);
        result.map_err(into_bus_error)
    }

    /// Derive, build, sign and assemble, without the key leaving this module.
    ///
    /// Confidential. This is the method a host should use for everything it
    /// can: the phrase arrives, is used, and is wiped inside one call.
    async fn sign_transaction(&self, mut request: SignRequest) -> BusResult<SignedTransaction> {
        let result = sign_transaction(&request);
        wipe(&mut request.secret);
        result.map_err(into_bus_error)
    }

    /// Hand back the raw derived key.
    ///
    /// Confidential in both directions. This is the one method that discloses
    /// key material, and it exists only for a host that must feed a signer it
    /// does not control. Anything that can use `SignTransaction` should.
    /// Sign opaque bytes with the key derived from a phrase.
    ///
    /// Confidential. Blind: nothing here can check what the bytes mean, so
    /// prefer `SignTransaction` wherever the request can be expressed as a
    /// `TransactionSpec`. See `SignMessageRequest` for when this is the right
    /// call and why it is still better than the alternative.
    async fn sign_message(&self, mut request: SignMessageRequest) -> BusResult<Signature> {
        let result = sign_message(&request);
        wipe(&mut request.secret);
        result.map_err(into_bus_error)
    }

    async fn export_key(&self, mut request: ExportRequest) -> BusResult<ExportedKey> {
        let result = export_key(&request);
        wipe(&mut request.secret);
        result.map_err(into_bus_error)
    }
}

/// Overwrite the recovery phrase once the call that needed it is done.
///
/// **What this achieves, precisely.** It shortens the window in which *this*
/// copy of the phrase is legible in the module's heap. It does not make the
/// module safe against something reading its address space — nothing can, since
/// a loaded module and its host share one — and it does not reach the copies it
/// does not own: the JSON frame the bus decoded from, and any reallocation
/// `String` performed while that decoding grew it. Both are outside this
/// function's reach and neither is claimed to be handled.
///
/// It is still worth doing. A phrase that stays resident for the process
/// lifetime ends up in core dumps and swap; one wiped at the end of the call
/// mostly does not. The bound is real even though it is partial, and the
/// alternative to a partial bound here is no bound at all.
///
/// `SecretMaterial` cannot simply implement `Drop` itself: it lives in
/// `tinywallet::wire`, which is deliberately dependency-free so a host can take
/// the contract without linking anything, and `zeroize` is a dependency.
fn wipe(secret: &mut SecretMaterial) {
    use zeroize::Zeroize;
    secret.mnemonic.zeroize();
}

/// Derive the key for `secret`, wiping it when the guard drops.
///
/// Every confidential entry point goes through here, so there is one place that
/// knows how a phrase becomes a key and one place that decides what a failure
/// says. The error deliberately names neither the phrase nor the path: a
/// rejected mnemonic that echoed itself into a log would defeat the point of
/// having carried it confidentially.
fn derive(secret: &SecretMaterial) -> Result<key::DerivedKey, Failure> {
    key::derive(secret.chain, &secret.mnemonic, &secret.derivation_path).map_err(|error| {
        // `key::Error`'s Display is written not to quote the phrase; this maps
        // by variant anyway rather than trusting that to stay true.
        Failure::InvalidInput(match error {
            key::Error::InvalidMnemonic => "recovery phrase is not valid BIP-39".to_string(),
            key::Error::InvalidPath { .. } => "derivation path is malformed".to_string(),
            key::Error::UnhardenedSolanaPath { .. } => {
                "Solana derivation path must be fully hardened".to_string()
            }
            other => format!("key derivation failed: {}", failure_kind(&other)),
        })
    })
}

/// A stable, phrase-free label for a derivation failure this build did not map.
fn failure_kind(error: &key::Error) -> &'static str {
    match error {
        key::Error::ChainNotCompiled { .. } => "chain not compiled into this module",
        _ => "unsupported",
    }
}

fn derive_account(secret: &SecretMaterial) -> Result<DerivedAccount, Failure> {
    let derived = derive(secret)?;
    Ok(DerivedAccount {
        address: derived.address().to_string(),
        public_key: PublicKey {
            key_hex: public_key_hex(secret.chain, derived.secret_bytes())?,
        },
    })
}

fn sign_transaction(request: &SignRequest) -> Result<SignedTransaction, Failure> {
    let derived = derive(&request.secret)?;

    // The chain the caller asked to derive for and the chain the transaction is
    // for must agree. Without this a Solana phrase could be walked with EVM
    // rules and sign an EVM transaction from an address the user never saw —
    // the request would look consistent and the money would be gone.
    if request.secret.chain != request.transaction.chain() {
        return Err(Failure::InvalidInput(
            "derivation chain does not match the transaction's chain".to_string(),
        ));
    }

    let public_key = PublicKey {
        key_hex: public_key_hex(request.secret.chain, derived.secret_bytes())?,
    };

    // Built, signed and reassembled through exactly the paths the split flow
    // uses. Sharing them is what makes `the_one_shot_path_agrees_with_the_split_path`
    // a real assertion rather than two implementations agreeing by luck.
    let unsigned = build_unsigned(&SigningRequest {
        transaction: request.transaction.clone(),
        public_key: public_key.clone(),
    })?;
    let signatures = unsigned
        .payloads
        .iter()
        .map(|payload| sign_payload(payload, derived.secret_bytes()))
        .collect::<Result<Vec<_>, Failure>>()?;
    attach_signature(&AttachRequest {
        transaction: request.transaction.clone(),
        public_key,
        signatures,
    })
}

fn sign_message(request: &SignMessageRequest) -> Result<Signature, Failure> {
    let derived = derive(&request.secret)?;
    // Routed through the same `sign_payload` the transaction paths use, so the
    // prehash-vs-whole-message distinction is decided in exactly one place. A
    // second implementation here is how the two would eventually disagree, and
    // a signature over the wrong bytes is still a valid signature.
    sign_payload(
        &SigningPayload {
            bytes_hex: request.message_hex.clone(),
            scheme: request.scheme,
        },
        derived.secret_bytes(),
    )
}

fn export_key(request: &ExportRequest) -> Result<ExportedKey, Failure> {
    let derived = derive(&request.secret)?;
    Ok(ExportedKey {
        secret_key_hex: hex(derived.secret_bytes()),
        address: derived.address().to_string(),
    })
}

/// The compressed public key a chain's builder expects, as lowercase hex.
fn public_key_hex(chain: Chain, secret: &[u8]) -> Result<String, Failure> {
    // Solana is the ed25519 chain; the other three are secp256k1. Written as a
    // two-way split rather than a match because `Chain` is `#[non_exhaustive]`,
    // so a match would need a wildcard that silently treated a future chain as
    // secp256k1 — which is what the `else` does too, but visibly.
    if chain == Chain::Solana {
        let key = ed25519_signing_key(secret)?;
        Ok(hex(&key.verifying_key().to_bytes()))
    } else {
        {
            use bitcoin::secp256k1::{PublicKey as SecpPublic, Secp256k1, SecretKey};
            let secret = SecretKey::from_slice(secret).map_err(|_| {
                Failure::BuildFailed("derived key is not a valid scalar".to_string())
            })?;
            Ok(hex(&SecpPublic::from_secret_key(
                &Secp256k1::new(),
                &secret,
            )
            .serialize()))
        }
    }
}

/// Sign one payload with the scheme it names.
///
/// The scheme comes from the payload rather than from the chain, so this cannot
/// drift from what the builder actually produced: a builder that starts
/// emitting a different scheme is followed here automatically.
fn sign_payload(payload: &SigningPayload, secret: &[u8]) -> Result<Signature, Failure> {
    let bytes = decode_hex(&payload.bytes_hex)?;
    match payload.scheme {
        Scheme::Secp256k1Prehash => {
            use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
            // `Message::from_digest` takes exactly 32 bytes. The builder always
            // emits that, and a payload that is not is a bug worth failing on
            // rather than padding into something signable.
            let digest: [u8; 32] = bytes.try_into().map_err(|_| {
                Failure::BuildFailed("secp256k1 payload is not a 32-byte digest".to_string())
            })?;
            let secret = SecretKey::from_slice(secret).map_err(|_| {
                Failure::BuildFailed("derived key is not a valid scalar".to_string())
            })?;
            let recoverable = Secp256k1::signing_only()
                .sign_ecdsa_recoverable(&Message::from_digest(digest), &secret);
            let (recovery_id, compact) = recoverable.serialize_compact();
            Ok(Signature::Secp256k1 {
                rs_hex: hex(&compact),
                recovery_id: u8::try_from(recovery_id.to_i32())
                    .map_err(|_| Failure::BuildFailed("recovery id out of range".to_string()))?,
            })
        }
        Scheme::Ed25519 => {
            use ed25519_dalek::Signer;
            let key = ed25519_signing_key(secret)?;
            Ok(Signature::Ed25519 {
                signature_hex: hex(&key.sign(&bytes).to_bytes()),
            })
        }
        // `Scheme` is `#[non_exhaustive]`, so a future variant compiles against
        // this build and arrives here. Refuse it. Falling back to either arm
        // would sign real bytes with the wrong scheme — the one outcome that
        // must never be reachable by adding a variant somewhere else.
        _ => Err(Failure::BuildFailed(
            "signing scheme is not supported by this module build".to_string(),
        )),
    }
}

fn ed25519_signing_key(secret: &[u8]) -> Result<ed25519_dalek::SigningKey, Failure> {
    let bytes: [u8; 32] = secret
        .try_into()
        .map_err(|_| Failure::BuildFailed("derived ed25519 key is not 32 bytes".to_string()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
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
        // Hand-maintained, and the compiler cannot check it against the
        // `#[tinybus::interface]` block above — a method missing here is
        // simply not advertised. `the_manifest_advertises_every_method` in
        // `tests/module_e2e.rs` is the guard; keep the two in step.
        methods = [
            "BuildUnsigned",
            "AttachSignature",
            "DeriveAccount",
            "SignTransaction",
            "ExportKey",
            "SignMessage",
        ],
        signals = [],
        requires = [],
        optional = [],
        lazy = false,
    }
}

#[cfg(test)]
mod test;
