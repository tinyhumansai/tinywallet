//! A [`WalletSigner`] backed by the root crate's real derivation, so the
//! addresses tests pin are the real ones.
//!
//! Accounts and Solana message signatures are genuine (a test can verify the
//! signature the engine broadcast); transaction signing is canned, because what
//! the engine is responsible for is the spec it hands over, which the fake
//! records.

use async_trait::async_trait;
use ed25519_dalek::Signer as _;
use parking_lot::Mutex;
use tinywallet_bus::wire::{
    DerivedAccount, PublicKey, Scheme, Signature, SignedTransaction, TransactionSpec,
};

use crate::crypto::seams::WalletSigner;
use crate::crypto::wallet::WalletChain;

use super::samples::{TEST_MNEMONIC, derivation_path};

/// One call the engine made to the signer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SignerCall {
    Derive(WalletChain),
    Transaction(WalletChain, TransactionSpec),
    Message(WalletChain, Vec<u8>),
}

/// Records calls; can be told to fail or to answer oddly.
pub(crate) struct FakeSigner {
    calls: Mutex<Vec<SignerCall>>,
    raw: Mutex<String>,
    fail_derive: Mutex<Option<String>>,
    fail_transaction: Mutex<Option<String>>,
    fail_message: Mutex<Option<String>>,
    message_reply: Mutex<Option<Signature>>,
    derived_override: Mutex<Option<String>>,
}

impl FakeSigner {
    /// A signer that succeeds.
    pub(crate) fn new() -> Self {
        Self {
            calls: Mutex::new(vec![]),
            raw: Mutex::new("0xsigned".to_string()),
            fail_derive: Mutex::new(None),
            fail_transaction: Mutex::new(None),
            fail_message: Mutex::new(None),
            message_reply: Mutex::new(None),
            derived_override: Mutex::new(None),
        }
    }

    /// What `sign_transaction` reports as the broadcast-ready `raw`.
    pub(crate) fn set_raw(&self, raw: &str) {
        *self.raw.lock() = raw.to_string();
    }

    /// Make `derive_account` fail with `message`.
    pub(crate) fn fail_derive(&self, message: &str) {
        *self.fail_derive.lock() = Some(message.to_string());
    }

    /// Make `sign_transaction` fail with `message`.
    pub(crate) fn fail_transaction(&self, message: &str) {
        *self.fail_transaction.lock() = Some(message.to_string());
    }

    /// Make `sign_message` fail with `message`.
    pub(crate) fn fail_message(&self, message: &str) {
        *self.fail_message.lock() = Some(message.to_string());
    }

    /// Make `sign_message` answer with `signature` instead of signing.
    pub(crate) fn reply_message(&self, signature: Signature) {
        *self.message_reply.lock() = Some(signature);
    }

    /// Make `derive_account` report `address` instead of the real one.
    pub(crate) fn derive_as(&self, address: &str) {
        *self.derived_override.lock() = Some(address.to_string());
    }

    /// Every call made so far.
    pub(crate) fn calls(&self) -> Vec<SignerCall> {
        self.calls.lock().clone()
    }

    /// The transaction specs handed over so far.
    pub(crate) fn transactions(&self) -> Vec<TransactionSpec> {
        self.calls()
            .into_iter()
            .filter_map(|c| match c {
                SignerCall::Transaction(_, spec) => Some(spec),
                _ => None,
            })
            .collect()
    }

    /// The Solana signing key the test mnemonic derives.
    pub(crate) fn solana_key() -> ed25519_dalek::SigningKey {
        let derived = tinywallet::key::derive(
            tinywallet::Chain::Solana,
            TEST_MNEMONIC,
            derivation_path(WalletChain::Solana),
        )
        .unwrap();
        let bytes: [u8; 32] = derived.secret_bytes().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    }
}

#[async_trait]
impl WalletSigner for FakeSigner {
    async fn derive_account(&self, chain: WalletChain) -> Result<DerivedAccount, String> {
        self.calls.lock().push(SignerCall::Derive(chain));
        if let Some(message) = self.fail_derive.lock().clone() {
            return Err(message);
        }
        let derived =
            tinywallet::key::derive(chain.to_chain(), TEST_MNEMONIC, derivation_path(chain))
                .map_err(|e| e.to_string())?;
        let address = self
            .derived_override
            .lock()
            .clone()
            .unwrap_or_else(|| derived.address().to_string());
        Ok(DerivedAccount {
            address,
            // The engine never reads the public key; the module reports it.
            public_key: PublicKey {
                key_hex: String::new(),
            },
        })
    }

    async fn sign_transaction(
        &self,
        chain: WalletChain,
        transaction: &TransactionSpec,
    ) -> Result<SignedTransaction, String> {
        self.calls
            .lock()
            .push(SignerCall::Transaction(chain, transaction.clone()));
        if let Some(message) = self.fail_transaction.lock().clone() {
            return Err(message);
        }
        Ok(SignedTransaction {
            raw: self.raw.lock().clone(),
            txid: None,
        })
    }

    async fn sign_message(
        &self,
        chain: WalletChain,
        message: &[u8],
        _scheme: Scheme,
    ) -> Result<Signature, String> {
        self.calls
            .lock()
            .push(SignerCall::Message(chain, message.to_vec()));
        if let Some(error) = self.fail_message.lock().clone() {
            return Err(error);
        }
        if let Some(reply) = self.message_reply.lock().clone() {
            return Ok(reply);
        }
        let signature = Self::solana_key().sign(message);
        Ok(Signature::Ed25519 {
            signature_hex: hex::encode(signature.to_bytes()),
        })
    }
}
