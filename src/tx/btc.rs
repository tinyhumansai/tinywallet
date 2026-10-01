//! Bitcoin P2WPKH transaction building and BIP-143 signing.
//!
//! Native segwit only — the same restriction
//! `address::btc::validate_sender` enforces, and for the same reason: this is
//! the one script type the signing path below implements.
//!
//! ## Bitcoin is the one chain where the fee is implicit
//!
//! On every other chain the fee is a field. Here it is
//! `sum(inputs) - sum(outputs)`, which means **a forgotten change output is
//! not a rounding error — it is the entire remaining balance paid to miners.**
//! [`Transfer::build`] therefore computes change explicitly and returns
//! [`Error::InvalidField`] rather than ever silently letting a surplus fall
//! through into the fee.
//!
//! ## Dust
//!
//! A change output below the dust threshold cannot be economically spent, so
//! nodes reject the transaction outright. Change under [`DUST_THRESHOLD`] is
//! dropped into the fee instead — the one case where an implicit fee increase
//! is correct, because the alternative is an unrelayable transaction.
//!
//! ## BIP-143 signs the input's value, and that is the security property
//!
//! Legacy sighash did not commit to the amount being spent, which let a
//! hardware wallet be lied to about input values and tricked into paying an
//! enormous fee. BIP-143 fixes it by including each input's value in its
//! sighash — which is why [`Utxo::value`] must be the *real* on-chain value.
//! A wrong one produces an invalid signature rather than a wrong transfer, so
//! this fails safe, but it fails.

use std::str::FromStr;

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::{CompressedPublicKey, PrivateKey};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

use super::{Error, Result};

/// Outputs below this many satoshis are unspendable dust and get folded into
/// the fee. 546 is the standard relay threshold for a P2WPKH output.
pub const DUST_THRESHOLD: u64 = 546;

/// An unspent output available to fund a transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// Transaction id holding the output.
    pub txid: String,
    /// Index of the output within that transaction.
    pub vout: u32,
    /// Value in satoshis.
    ///
    /// Must be the real on-chain value: BIP-143 signs it, so a wrong value
    /// yields a signature that will not verify. See the module docs.
    pub value: u64,
}

/// A P2WPKH transfer, before coin selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Sender's `bc1q…` address. Must be P2WPKH.
    pub from: String,
    /// Recipient's address. Any mainnet type is fine.
    pub to: String,
    /// Amount to send, in satoshis.
    pub amount: u64,
    /// Absolute fee to pay, in satoshis.
    pub fee: u64,
}

/// The coins chosen to fund a transfer, and the change they leave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selection {
    /// The UTXOs to spend.
    pub inputs: Vec<Utxo>,
    /// Change returning to the sender, in satoshis. Zero when the surplus was
    /// below [`DUST_THRESHOLD`] and folded into the fee.
    pub change: u64,
}

/// Choose UTXOs to cover `target`, largest first.
///
/// Largest-first keeps the input count — and so the transaction size and the
/// fee — small. It is not privacy-optimal, but a wallet that consolidates
/// predictably is easier to reason about than one that does not.
///
/// # Errors
///
/// [`Error::InsufficientFunds`] when the available total cannot cover
/// `target`.
pub fn select_coins(utxos: &[Utxo], target: u64) -> Result<Selection> {
    let mut sorted = utxos.to_vec();
    sorted.sort_by_key(|u| std::cmp::Reverse(u.value));

    let mut total: u64 = 0;
    let mut chosen = Vec::new();
    for utxo in sorted {
        total = total
            .checked_add(utxo.value)
            .ok_or_else(|| Error::InvalidField {
                field: "utxos",
                reason: "total value overflows".to_string(),
            })?;
        chosen.push(utxo);
        if total >= target {
            let surplus = total - target;
            // Dust change would make the transaction unrelayable, so it goes
            // to the fee instead. The only correct implicit fee increase here.
            let change = if surplus > DUST_THRESHOLD { surplus } else { 0 };
            return Ok(Selection {
                inputs: chosen,
                change,
            });
        }
    }
    Err(Error::InsufficientFunds {
        available: total,
        required: target,
    })
}

impl Transfer {
    /// Select coins and build the unsigned transaction.
    ///
    /// # Errors
    ///
    /// [`Error::Address`] for an invalid or non-P2WPKH sender,
    /// [`Error::InsufficientFunds`] if the UTXOs cannot cover amount plus fee,
    /// [`Error::InvalidField`] for a malformed txid or an arithmetic overflow.
    pub fn build(&self, utxos: &[Utxo]) -> Result<(Transaction, Selection)> {
        // Sender must be P2WPKH — the only type signed below.
        let from = crate::address::btc::validate_sender(&self.from).map_err(Error::Address)?;
        let to = crate::address::btc::validate(&self.to).map_err(Error::Address)?;

        let target = self
            .amount
            .checked_add(self.fee)
            .ok_or_else(|| Error::InvalidField {
                field: "amount",
                reason: "amount + fee overflows".to_string(),
            })?;
        let selection = select_coins(utxos, target)?;

        let from_spk = script_pubkey(&from)?;
        let to_spk = script_pubkey(&to)?;

        let mut input = Vec::with_capacity(selection.inputs.len());
        for utxo in &selection.inputs {
            let txid = bitcoin::Txid::from_str(&utxo.txid).map_err(|e| Error::InvalidField {
                field: "utxo.txid",
                reason: format!("{}: {e}", utxo.txid),
            })?;
            input.push(TxIn {
                previous_output: OutPoint {
                    txid,
                    vout: utxo.vout,
                },
                script_sig: ScriptBuf::new(),
                // Opt into RBF so a transfer stuck at a low fee can be bumped
                // rather than sitting in the mempool until it expires.
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::default(),
            });
        }

        let mut output = vec![TxOut {
            value: Amount::from_sat(self.amount),
            script_pubkey: to_spk,
        }];
        if selection.change > 0 {
            output.push(TxOut {
                value: Amount::from_sat(selection.change),
                script_pubkey: from_spk,
            });
        }

        Ok((
            Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input,
                output,
            },
            selection,
        ))
    }

    /// Build and sign, returning the raw transaction hex for broadcast.
    ///
    /// # Errors
    ///
    /// As [`Transfer::build`], plus [`Error::Signing`] if the key is invalid
    /// or does not control `from`.
    pub fn sign(&self, utxos: &[Utxo], secret_key: &[u8]) -> Result<String> {
        let secret =
            bitcoin::secp256k1::SecretKey::from_slice(secret_key).map_err(|_| Error::Signing {
                reason: "not a valid secp256k1 secret key".to_string(),
            })?;
        let secp = Secp256k1::new();
        let private = PrivateKey::new(secret, Network::Bitcoin);
        let public =
            CompressedPublicKey::from_private_key(&secp, &private).map_err(|_| Error::Signing {
                reason: "could not derive the public key".to_string(),
            })?;

        // Catch a key/address mismatch here rather than after broadcasting an
        // unspendable transaction.
        let derived = Address::p2wpkh(&public, Network::Bitcoin).to_string();
        if derived != self.from.trim() {
            return Err(Error::Signing {
                reason: "secret key does not control the `from` address".to_string(),
            });
        }

        let compressed = public.to_bytes();
        let signatures = self
            .sighashes(utxos, &compressed)?
            .1
            .into_iter()
            .map(|sighash| {
                let message = Message::from_digest(sighash);
                secp.sign_ecdsa(&message, &private.inner)
                    .serialize_compact()
            })
            .collect::<Vec<_>>();

        // Routed through the same reassembly the split-signing path uses, so
        // witness layout and input ordering have exactly one implementation.
        self.attach_signatures(utxos, &compressed, &signatures)
    }

    /// The per-input digests to sign, without needing the key.
    ///
    /// Returns the coin selection alongside them because the caller needs to
    /// know how many signatures to produce and in which order: **one per
    /// selected input, in input order**. Bitcoin is the only chain here that
    /// needs more than one signature for a single transaction.
    ///
    /// Each digest is a BIP-143 P2WPKH sighash, already hashed — sign it with a
    /// "prehash" entry point.
    ///
    /// # Errors
    ///
    /// As [`Transfer::build`], plus [`Error::Signing`] if `public_key` does not
    /// control `from`.
    pub fn sighashes(
        &self,
        utxos: &[Utxo],
        public_key: &[u8; 33],
    ) -> Result<(Selection, Vec<[u8; 32]>)> {
        self.check_controls_from(public_key)?;

        let (mut tx, selection) = self.build(utxos)?;
        let from_spk = script_pubkey(
            &crate::address::btc::validate_sender(&self.from).map_err(Error::Address)?,
        )?;

        let mut cache = SighashCache::new(&mut tx);
        let mut digests = Vec::with_capacity(selection.inputs.len());
        for (index, utxo) in selection.inputs.iter().enumerate() {
            // BIP-143 commits to this input's value — see the module docs.
            let sighash = cache
                .p2wpkh_signature_hash(
                    index,
                    &from_spk,
                    Amount::from_sat(utxo.value),
                    EcdsaSighashType::All,
                )
                .map_err(|e| Error::Signing {
                    reason: format!("sighash failed: {e}"),
                })?;
            digests.push(sighash.to_byte_array());
        }
        Ok((selection, digests))
    }

    /// Assemble the raw transaction from signatures over [`Self::sighashes`].
    ///
    /// `signatures` must hold one 64-byte compact signature per selected input,
    /// in the same order [`Self::sighashes`] returned the digests.
    ///
    /// # Errors
    ///
    /// As [`Transfer::build`], plus [`Error::Signing`] if `public_key` does not
    /// control `from`, if the signature count does not match the input count,
    /// or if a signature is not a valid secp256k1 `(r, s)` pair.
    pub fn attach_signatures(
        &self,
        utxos: &[Utxo],
        public_key: &[u8; 33],
        signatures: &[[u8; 64]],
    ) -> Result<String> {
        self.check_controls_from(public_key)?;

        let (mut tx, selection) = self.build(utxos)?;
        if signatures.len() != selection.inputs.len() {
            return Err(Error::Signing {
                reason: format!(
                    "expected {} signatures for {} inputs, got {}",
                    selection.inputs.len(),
                    selection.inputs.len(),
                    signatures.len()
                ),
            });
        }

        for (input, compact) in tx.input.iter_mut().zip(signatures) {
            let mut signature = bitcoin::secp256k1::ecdsa::Signature::from_compact(compact)
                .map_err(|_| Error::Signing {
                    reason: "signature is not a valid secp256k1 (r, s) pair".to_string(),
                })?;
            // Bitcoin enforces low-`s` as a relay policy rule (BIP-146), so a
            // high-`s` signature yields a transaction nodes refuse to relay.
            // Normalizing here means a caller that signed with a library which
            // does not normalize still produces a broadcastable transaction,
            // and one that does is unaffected — the operation is idempotent.
            signature.normalize_s();

            let mut witness = Witness::new();
            let mut der = signature.serialize_der().to_vec();
            der.push(EcdsaSighashType::All as u8);
            witness.push(der);
            witness.push(public_key);
            input.witness = witness;
        }

        Ok(bitcoin::consensus::encode::serialize_hex(&tx))
    }

    /// Refuse early if `public_key` does not control `from`.
    ///
    /// Caught here rather than after broadcasting an unspendable transaction —
    /// which is unrecoverable, because the fee is paid either way.
    fn check_controls_from(&self, public_key: &[u8; 33]) -> Result<()> {
        let public = CompressedPublicKey::from_slice(public_key).map_err(|_| Error::Signing {
            reason: "not a valid compressed secp256k1 public key".to_string(),
        })?;
        let derived = Address::p2wpkh(&public, Network::Bitcoin).to_string();
        if derived != self.from.trim() {
            return Err(Error::Signing {
                reason: "public key does not control the `from` address".to_string(),
            });
        }
        Ok(())
    }
}

/// The scriptPubKey that pays to `address`.
fn script_pubkey(address: &str) -> Result<ScriptBuf> {
    Ok(Address::from_str(address)
        .map_err(|e| Error::InvalidField {
            field: "address",
            reason: e.to_string(),
        })?
        .assume_checked()
        .script_pubkey())
}

#[cfg(test)]
#[path = "btc_test_tests.rs"]
mod test;
