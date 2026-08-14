//! The wire contract between a host and a signing backend.
//!
//! # Why this module exists, and why it has no dependencies
//!
//! A host can run this crate's transaction building in-process, or it can run
//! it somewhere else — most usefully in a loadable module, so the chain
//! libraries that building requires (`bitcoin` and its native `secp256k1`
//! build, above all) are absent from the host binary entirely.
//!
//! For that second arrangement both sides must agree on a set of types, and
//! **only the host side may be free of the heavy dependencies**. So these types
//! live outside every format gate and pull in nothing but `serde`: a host can
//! take this crate with `default-features = false`, get the whole contract, and
//! still not link a single chain library. It is the same carve-out
//! `tinydocs::spec` makes for documents.
//!
//! # The split: building is not signing
//!
//! Every type here exists to serve one rule — **key material never crosses this
//! boundary**. A backend receives transaction fields and returns the bytes that
//! need signing; the host signs them; the backend reassembles. Two round trips
//! instead of one, in exchange for a private key that never leaves the process
//! that owns it.
//!
//! That constraint is what shapes the API. A [`SigningRequest`] carries no
//! secret, and an [`AttachRequest`] carries the original fields **again**
//! alongside the signatures, rather than a handle to something the backend
//! remembered. A backend holding half-built transactions between calls would
//! need a store, bounds on that store, and an expiry policy for callers that
//! never come back — all of which is avoided by rebuilding. Building is
//! deterministic, so rebuilding from the same fields yields the same
//! transaction the digests were computed over.
//!
//! # Signature shapes
//!
//! Three of the four chains sign a 32-byte digest with secp256k1 ECDSA and need
//! the recovery id; Solana signs the message itself with ed25519 and does not.
//! [`Signature`] is an enum over exactly those two cases rather than a bag of
//! bytes, so a host cannot hand back an ed25519 signature for an EVM
//! transaction and have it fail somewhere deep in reassembly.

use serde::{Deserialize, Serialize};

use crate::chain::Chain;

/// Bytes a host must sign, and how.
///
/// For secp256k1 chains this is a 32-byte digest that is signed directly —
/// **already hashed**, so a host must use a "sign prehash" entry point and must
/// not hash it again. For Solana it is the full serialized message, because
/// ed25519 hashes internally as part of signing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningPayload {
    /// Lowercase hex of the bytes to sign.
    pub bytes_hex: String,
    /// Which signing scheme these bytes expect.
    pub scheme: Scheme,
}

/// How a [`SigningPayload`] must be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Scheme {
    /// secp256k1 ECDSA over an already-computed 32-byte digest, low-`s`
    /// normalized, with the recovery id retained.
    ///
    /// Low-`s` is not optional: Bitcoin enforces it as a relay policy rule
    /// (BIP-146) and Ethereum as a consensus rule (EIP-2), so a high-`s`
    /// signature produces a transaction that is rejected rather than one that
    /// merely looks different. Both `k256` and `secp256k1` normalize by
    /// default; a host that implements signing itself must not skip it.
    Secp256k1Prehash,
    /// ed25519 over the full message, which the scheme hashes itself.
    Ed25519,
}

/// A signature handed back to a backend for reassembly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Signature {
    /// secp256k1 ECDSA: 32-byte `r`, 32-byte `s`, and the recovery id.
    Secp256k1 {
        /// Lowercase hex of `r || s`, exactly 64 bytes.
        rs_hex: String,
        /// Recovery id, 0..=3.
        ///
        /// Carried even for Bitcoin, which does not use it, so one variant
        /// serves all three secp256k1 chains. EVM folds it into EIP-155 `v`
        /// and Tron appends it directly.
        recovery_id: u8,
    },
    /// ed25519: the 64-byte signature.
    Ed25519 {
        /// Lowercase hex of the signature, exactly 64 bytes.
        signature_hex: String,
    },
}

/// The public key controlling the account a transaction spends from.
///
/// Public by definition, so unlike the secret it may cross the boundary freely.
/// A backend needs it for two things: Bitcoin puts it in the witness, and every
/// chain uses it to check that the key the host is about to sign with actually
/// controls the `from` address — a mismatch that would otherwise surface as an
/// unspendable broadcast transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicKey {
    /// Lowercase hex. Compressed SEC1 (33 bytes) for secp256k1 chains, the
    /// 32-byte public key for ed25519.
    pub key_hex: String,
}

/// Ask a backend what needs signing for a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningRequest {
    /// The transaction to build, which names its own chain.
    ///
    /// There is deliberately no separate `chain` field. Carrying one alongside
    /// this would let a request say `btc` while holding an EVM transaction —
    /// a state the backend would have to detect and reject at runtime. Reading
    /// the chain off the variant instead makes that disagreement unrepresentable.
    pub transaction: TransactionSpec,
    /// The public key that will sign.
    pub public_key: PublicKey,
}

/// Hand signatures back so a backend can assemble the final transaction.
///
/// Carries `transaction` again rather than a handle: see the module docs on why
/// a backend deliberately keeps no state between the two calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachRequest {
    /// The same fields passed to the matching [`SigningRequest`].
    ///
    /// As there, the chain comes from the variant rather than a parallel field.
    pub transaction: TransactionSpec,
    /// The public key that signed.
    pub public_key: PublicKey,
    /// One signature per [`SigningPayload`] returned, in the same order.
    ///
    /// Bitcoin needs one per selected input; the other three need exactly one.
    pub signatures: Vec<Signature>,
}

/// What a backend answers a [`SigningRequest`] with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsignedTransaction {
    /// Everything that needs a signature, in the order the signatures must be
    /// returned.
    pub payloads: Vec<SigningPayload>,
}

/// What a backend answers an [`AttachRequest`] with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedTransaction {
    /// The broadcast-ready transaction, in whatever encoding the chain's RPC
    /// expects: hex for Bitcoin, EVM and Tron, base64 for Solana.
    pub raw: String,
    /// The transaction id or hash a node will report, when the chain lets it be
    /// computed locally.
    pub txid: Option<String>,
}

/// A transaction to build, per chain.
///
/// One enum rather than four methods so a host holds a single value and the
/// chain tag cannot disagree with the fields — the mismatch a pair of parallel
/// arguments would allow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum TransactionSpec {
    /// A Bitcoin P2WPKH spend.
    Btc {
        /// Sender address; must be P2WPKH.
        from: String,
        /// Recipient address; any mainnet type.
        to: String,
        /// Amount in satoshis.
        amount_sat: u64,
        /// Absolute fee in satoshis.
        ///
        /// Bitcoin's fee is implicit — `sum(inputs) - sum(outputs)` — so it is
        /// stated here rather than derived from a rate. A caller that thinks
        /// in sat/vB converts before sending.
        fee_sat: u64,
        /// Every spendable output held by `from`.
        utxos: Vec<Utxo>,
    },
    /// An EVM legacy transaction.
    Evm {
        /// Recipient — the token contract for an ERC-20 transfer.
        to: String,
        /// Value in wei.
        value_wei: String,
        /// Call data, `0x`-prefixed hex. Empty for a native transfer.
        data_hex: String,
        /// Sender nonce.
        nonce: u64,
        /// Gas limit.
        gas_limit: u64,
        /// Gas price in wei.
        gas_price_wei: String,
        /// EIP-155 chain id.
        chain_id: u64,
    },
    /// A Solana native SOL transfer.
    Solana {
        /// Sender address.
        from: String,
        /// Recipient address.
        to: String,
        /// Amount in lamports.
        lamports: u64,
        /// A recent blockhash, base58.
        recent_blockhash: String,
    },
    /// A Tron transfer, already assembled by the node.
    ///
    /// Tron is the odd one out: `createtransaction` builds the transaction
    /// server-side and returns it, so there is nothing for this crate to build
    /// — only a payload to verify and sign. The verification is the point, and
    /// it is why the recipient and amount are carried alongside: a node that
    /// returned a transaction paying somebody else would otherwise be signed
    /// without complaint.
    Tron {
        /// The node's `raw_data_hex`.
        raw_data_hex: String,
        /// The recipient the caller intended, base58check.
        expected_to: String,
        /// The txid the node reported, to be recomputed and compared.
        expected_txid: String,
        /// Transfer-specific fields that must be present in the node-built
        /// transaction before it is signed.
        transfer: TronTransfer,
    },
}

/// Transfer-specific verification for a node-built Tron transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum TronTransfer {
    /// A native TRX transfer; the amount is encoded as a protobuf varint.
    Native {
        /// Requested amount in sun.
        amount_sun: u64,
    },
    /// A TRC20 transfer; the ABI parameter binds both recipient and amount.
    Trc20 {
        /// Unprefixed ABI-encoded transfer arguments.
        parameter_hex: String,
    },
}

impl TransactionSpec {
    /// Which chain this transaction belongs to.
    ///
    /// The single source of truth for the chain, which is why neither request
    /// type carries it separately.
    ///
    /// Infallible, and deliberately so despite `#[non_exhaustive]`. That
    /// attribute binds only *downstream* crates, and a downstream crate calls
    /// this method rather than matching the enum itself — so there is no
    /// wildcard arm to write here, and adding a variant is a compile error in
    /// this file, which is where it should be caught.
    #[must_use]
    pub fn chain(&self) -> Chain {
        match self {
            Self::Btc { .. } => Chain::Btc,
            Self::Evm { .. } => Chain::Evm,
            Self::Solana { .. } => Chain::Solana,
            Self::Tron { .. } => Chain::Tron,
        }
    }
}

/// One spendable Bitcoin output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Utxo {
    /// Transaction id holding this output.
    pub txid: String,
    /// Output index within that transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub value: u64,
}

#[cfg(test)]
mod test;

// ---------------------------------------------------------------------------
// The confidential half of the contract
// ---------------------------------------------------------------------------
//
// Everything above exists so that key material never crosses this boundary.
// Everything below deliberately carries it, and the two coexist rather than one
// replacing the other, because they answer different questions.
//
// The split above is right whenever the backend is *reachable*: a service in
// its own process, across a socket, on another host. It is also the only option
// when the bus cannot say what is on the other end.
//
// tinybus can now say. A confidential message is delivered to a module whose
// artifact the host hashed against a digest an operator asserted, or to nobody
// at all — never to a transport peer, never fanned out to a subscriber, never
// printed by a monitor. That makes a second arrangement possible for a *loaded*
// backend, and it is strictly better where it applies: the host stops linking
// the derivation and signing stack at all, and the key stops being reassembled
// in a process whose job is the user interface.
//
// It is worth being exact about what this does and does not buy, because the
// temptation is to read it as isolation. A loaded module shares the host's
// address space and can read host memory directly — it never needed the bus to
// reach a secret. What the rule buys is that the bus will not be the *delivery
// mechanism* for code nobody allowlisted. A backend whose compromise must not
// reach a key belongs in a separate process, where this design makes it
// ineligible to receive one, and where the types above are the ones to use.

/// A recovery phrase and the derivation to apply to it.
///
/// This is the only type in this crate that carries key material, and it may
/// only travel as the body of a confidential call.
///
/// `Debug` is implemented by hand and prints `<redacted>` for the phrase. A
/// derived one would put a live recovery phrase into every log line, panic
/// message and error report that ever formatted a request — which is the
/// failure this whole module is arranged to prevent, arriving through the back
/// door. `DerivedKey` in `crate::key` redacts for the same reason.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretMaterial {
    /// The BIP-39 phrase, already decrypted by the host.
    pub mnemonic: String,
    /// BIP-32 style derivation path, e.g. `m/44'/60'/0'/0/0`.
    pub derivation_path: String,
    /// Which chain's derivation rules and address format to apply.
    pub chain: Chain,
}

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretMaterial")
            .field("mnemonic", &"<redacted>")
            .field("derivation_path", &self.derivation_path)
            .field("chain", &self.chain)
            .finish()
    }
}

/// What a host learns about an account without learning its key.
///
/// The reply to `DeriveAccount`. Both fields are public information, so this
/// carries nothing the host could not have computed itself had it kept the
/// derivation stack — which is the point: it no longer has to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedAccount {
    /// The address, in the chain's canonical text form.
    pub address: String,
    /// The compressed public key, lowercase hex.
    pub public_key: PublicKey,
}

/// Derive, build, sign and assemble in one call.
///
/// The single-round-trip counterpart to [`SigningRequest`] + [`AttachRequest`].
/// There is no intermediate state and nothing for the caller to hold, because
/// the secret arrives, is used, and goes out of scope inside one method — a
/// two-step confidential flow would mean a module holding key material between
/// calls, with a store to bound and an expiry to get right.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignRequest {
    /// The phrase and derivation to sign with.
    pub secret: SecretMaterial,
    /// The transaction to build and sign.
    pub transaction: TransactionSpec,
}

/// Ask for the raw derived key itself.
///
/// This exists for one real case: a host that must hand the key to a signer it
/// does not control — an embedded library with its own `from_seed` entry point,
/// or a user exporting their key deliberately. Every other operation should use
/// [`SignRequest`], which never lets the key out.
///
/// It is a separate type from [`SignRequest`] rather than a flag on it so the
/// two cannot be confused at a call site, and so a reviewer grepping for the
/// paths that extract a key finds exactly this one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    /// The phrase and derivation to export.
    pub secret: SecretMaterial,
}

/// The raw derived key.
///
/// Returned only from a confidential call, so it inherits the confidential flag
/// on the way back and is delivered to the connection that asked — never fanned
/// out, never monitored.
///
/// `Debug` redacts, for the same reason [`SecretMaterial`] does.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportedKey {
    /// The 32-byte secret key, lowercase hex.
    pub secret_key_hex: String,
    /// The address it controls, so a caller can check it got the key it meant.
    pub address: String,
}

impl std::fmt::Debug for ExportedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExportedKey")
            .field("secret_key_hex", &"<redacted>")
            .field("address", &self.address)
            .finish()
    }
}
