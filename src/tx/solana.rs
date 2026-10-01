//! Solana legacy transaction building and ed25519 signing.
//!
//! A Solana transaction is not RLP or protobuf — it is a hand-rolled binary
//! format built on **shortvec**, a compact little-endian varint used for every
//! length prefix. There is no schema and no framing beyond position, so a
//! single byte in the wrong place shifts everything after it and yields a
//! transaction that is still signable and completely wrong.
//!
//! ## The message layout
//!
//! ```text
//! signatures      shortvec count, then 64 bytes each
//! message:
//!   header        num_required_signatures, num_readonly_signed,
//!                 num_readonly_unsigned          (3 bytes)
//!   accounts      shortvec count, then 32 bytes each
//!   blockhash     32 bytes
//!   instructions  shortvec count, then per instruction:
//!                   program_id_index  (1 byte, index into accounts)
//!                   account indices   (shortvec count, then 1 byte each)
//!                   data              (shortvec length, then bytes)
//! ```
//!
//! ## Account ordering is load-bearing, not cosmetic
//!
//! Instructions reference accounts *by index into the message's account list*,
//! and the header describes that list positionally: the first
//! `num_required_signatures` entries must sign, and the last
//! `num_readonly_unsigned` are read-only. So reordering the accounts silently
//! changes which account signs and which is writable — the transfer would
//! still sign cleanly and either fail on-chain or debit the wrong account.
//! [`NativeTransfer::message`] builds the list in exactly one order for that
//! reason.

use ed25519_dalek::{Signer as _, SigningKey};

use super::{Error, Result};

/// The System program id: 32 zero bytes.
const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// System program instruction index for `Transfer`.
const SYSTEM_TRANSFER_INDEX: u32 = 2;

/// A native SOL transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeTransfer {
    /// Sender's base58 address. Signs the transaction and pays the fee.
    pub from: String,
    /// Recipient's base58 address.
    pub to: String,
    /// Amount in lamports.
    pub lamports: u64,
    /// A recent blockhash, base58. Solana uses this both as a nonce and as an
    /// expiry — a transaction is rejected once the hash is too old, which is
    /// what stops an intercepted transaction being replayed later.
    pub recent_blockhash: String,
}

impl NativeTransfer {
    /// Serialise the message — the bytes that get signed.
    ///
    /// # Errors
    ///
    /// [`Error::Address`] if either address is invalid, or
    /// [`Error::InvalidField`] if the blockhash is not 32 base58 bytes.
    pub fn message(&self) -> Result<Vec<u8>> {
        let from = crate::address::solana::decode(&self.from).map_err(Error::Address)?;
        let to = crate::address::solana::decode(&self.to).map_err(Error::Address)?;
        let blockhash = decode_blockhash(&self.recent_blockhash)?;

        let mut out = Vec::new();

        // Header. Exactly one signer (the sender), no read-only signers, and
        // one read-only unsigned account (the System program, which is last).
        out.push(1); // num_required_signatures
        out.push(0); // num_readonly_signed
        out.push(1); // num_readonly_unsigned

        // Accounts, in the order the header describes: signer first,
        // read-only last. See the module docs — this order is the contract.
        out.extend(encode_shortvec(3));
        out.extend_from_slice(&from);
        out.extend_from_slice(&to);
        out.extend_from_slice(&SYSTEM_PROGRAM_ID);

        out.extend_from_slice(&blockhash);

        // One instruction: System::Transfer, referencing accounts 0 and 1 and
        // the program at index 2.
        out.extend(encode_shortvec(1));
        out.push(2); // program_id_index
        out.extend(encode_shortvec(2));
        out.push(0); // from
        out.push(1); // to
        let mut data = Vec::with_capacity(12);
        data.extend_from_slice(&SYSTEM_TRANSFER_INDEX.to_le_bytes());
        data.extend_from_slice(&self.lamports.to_le_bytes());
        out.extend(encode_shortvec(
            u16::try_from(data.len()).unwrap_or(u16::MAX),
        ));
        out.extend_from_slice(&data);

        Ok(out)
    }

    /// Sign the message and return the wire-format transaction, ready to be
    /// base64-encoded for `sendTransaction`.
    ///
    /// # Errors
    ///
    /// As [`NativeTransfer::message`], plus [`Error::Signing`] if the key is
    /// not 32 bytes or does not match `from`.
    pub fn sign(&self, secret_key: &[u8]) -> Result<Vec<u8>> {
        let key: [u8; 32] = secret_key.try_into().map_err(|_| Error::Signing {
            reason: "ed25519 secret key must be 32 bytes".to_string(),
        })?;
        let signing = SigningKey::from_bytes(&key);

        // A signature from the wrong key is structurally valid and rejected
        // only on-chain, so the mismatch is caught here where it is cheap and
        // the error can say what actually went wrong.
        let derived = crate::address::solana::encode(&signing.verifying_key().to_bytes());
        if derived != self.from.trim() {
            return Err(Error::Signing {
                reason: "secret key does not control the `from` address".to_string(),
            });
        }

        let message = self.message()?;
        let signature = signing.sign(&message);
        // Shares the assembly below rather than repeating it: see the note on
        // the EVM path for why a second copy of a wire encoding is a hazard.
        self.attach_signature(&signature.to_bytes())
    }

    /// Assemble the wire transaction from a signature over [`Self::message`].
    ///
    /// For a caller that holds the ed25519 key elsewhere. Note the signature is
    /// over the **whole message**, not a digest — ed25519 hashes internally, so
    /// there is nothing to pre-hash and a caller must not.
    ///
    /// # Errors
    ///
    /// As [`NativeTransfer::message`].
    pub fn attach_signature(&self, signature: &[u8; 64]) -> Result<Vec<u8>> {
        let message = self.message()?;
        let mut out = Vec::with_capacity(1 + 64 + message.len());
        out.extend(encode_shortvec(1));
        out.extend_from_slice(signature);
        out.extend_from_slice(&message);
        Ok(out)
    }
}

/// Decode a base58 blockhash into its 32 bytes.
fn decode_blockhash(raw: &str) -> Result<[u8; 32]> {
    let decoded = bs58::decode(raw.trim())
        .into_vec()
        .map_err(|e| Error::InvalidField {
            field: "recent_blockhash",
            reason: format!("not base58: {e}"),
        })?;
    decoded
        .try_into()
        .map_err(|v: Vec<u8>| Error::InvalidField {
            field: "recent_blockhash",
            reason: format!("expected 32 bytes, got {}", v.len()),
        })
}

/// Solana's compact-u16 (shortvec) length encoding.
///
/// Seven bits per byte, little-endian, with the high bit marking
/// continuation — so lengths under 128 are a single byte, which is every
/// length in a simple transfer. Not the same as a protobuf varint despite the
/// resemblance: this one is capped at `u16`.
fn encode_shortvec(value: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut remaining = value;
    loop {
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining == 0 {
            out.push(byte);
            return out;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

#[cfg(test)]
#[path = "solana_test_tests.rs"]
mod test;
