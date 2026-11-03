//! Typed host calls to the `TinyWallet` `TinyBus` module.
//!
//! `WalletClient` is a transport facade over a host configured
//! `tinybus::module::ModuleClient`. It owns no loader, endpoint policy, approval
//! flow, provider configuration, or wallet implementation. Confidential calls
//! use `call_attested`, which checks the host registry's archive and extracted
//! library pins against the same unique peer before serializing a request.

use std::fmt;

use serde::{Serialize, de::DeserializeOwned};
use tinybus::module::{ModuleCallFailure, ModuleClient};
pub use tinywallet_bus::Chain;
use tinywallet_bus::names::CONFIDENTIAL_METHODS;
pub use tinywallet_bus::names::methods;
pub use tinywallet_bus::wire::{
    DeriveMnemonicSeedRequest, DeriveMnemonicSeedResponse, DerivedAccount,
    EncodeErc20TransferRequest, EncodeErc20TransferResponse, ExportRequest, ExportedKey,
    GenerateMnemonicRequest, GenerateMnemonicResponse, Scheme, SecretMaterial, SignMessageRequest,
    SignRequest, Signature, SignedTransaction, TransactionSpec,
};
use zeroize::Zeroize;

const MODULE_ID: &str = "tinywallet";

/// Failure from a typed `TinyWallet` module call.
///
/// Detailed remote failure data is available through `Remote`. Its `Debug` and
/// `Display` renderings redact untrusted wire names and prose through `TinyBus`;
/// callers that need those raw fields must apply their own redaction policy.
#[derive(Debug)]
pub enum ClientError {
    /// An ordinary call was attempted for a member declared confidential.
    ConfidentialRequired,
    /// An attested call was attempted for a public member.
    NotConfidential,
    /// An ordinary module call failed.
    Remote(ModuleCallFailure),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConfidentialRequired => f.write_str("wallet member requires attested delivery"),
            Self::NotConfidential => f.write_str("wallet member is not confidential"),
            Self::Remote(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ClientError {}

/// Typed call facade over the host's configured `TinyBus` module client.
#[derive(Clone)]
pub struct WalletClient {
    client: ModuleClient,
}

impl fmt::Debug for WalletClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WalletClient").finish_non_exhaustive()
    }
}

impl WalletClient {
    /// Create a wallet facade from host-owned module access and release pins.
    #[must_use]
    pub fn new(client: ModuleClient) -> Self {
        Self { client }
    }

    /// Make a typed ordinary call with exactly one request argument.
    ///
    /// Members declared confidential by tinywallet-bus are refused before the
    /// request is serialized. The request is borrowed, so the caller retains
    /// ownership and is responsible for wiping any secret fields after refusal
    /// or completion. Confidential typed wrappers provide an RAII mnemonic
    /// guard.
    ///
    /// Secret-bearing requests cannot be consumed by this ordinary-call API:
    ///
    /// ```compile_fail
    /// use tinywallet_client::{WalletClient, methods, SecretMaterial};
    ///
    /// fn pass_owned_secret(wallet: &WalletClient, secret: SecretMaterial) {
    ///     let _future = wallet.call::<_, serde_json::Value>(
    ///         methods::DERIVE_ACCOUNT,
    ///         secret,
    ///     );
    /// }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns `ConfidentialRequired` for a confidential member, or `Remote` for
    /// a failed module call.
    pub async fn call<Request, Reply>(
        &self,
        member: &str,
        request: &Request,
    ) -> Result<Reply, ClientError>
    where
        Request: Serialize + Sync + ?Sized,
        Reply: DeserializeOwned,
    {
        if is_confidential(member) {
            return Err(ClientError::ConfidentialRequired);
        }
        self.client
            .call_detailed(MODULE_ID, member, (request,))
            .await
            .map_err(ClientError::Remote)
    }

    /// Make a typed call using strict peer and release-library attestation.
    ///
    /// The request is borrowed so the caller retains ownership and remains
    /// responsible for wiping any secret fields after the call completes or is
    /// cancelled. Typed wallet wrappers provide an RAII mnemonic guard.
    ///
    /// Secret-bearing DTOs cannot be passed by value:
    ///
    /// ```compile_fail
    /// use tinywallet_client::{WalletClient, methods, SecretMaterial};
    ///
    /// fn pass_owned_secret(wallet: &WalletClient, secret: SecretMaterial) {
    ///     let _future = wallet.call_attested::<_, serde_json::Value>(
    ///         methods::SIGN_TRANSACTION,
    ///         secret,
    ///     );
    /// }
    /// ```
    ///
    /// `TinyBus` validates archive and extracted-library pins in the host's
    /// `ReleaseRecord`, then proves both against the same unique peer before it
    /// serializes the request. There is no ordinary-delivery fallback.
    ///
    /// # Errors
    ///
    /// Returns `NotConfidential` for a public member, or `Remote` with the
    /// detailed failure if the strict call fails.
    pub async fn call_attested<Request, Reply>(
        &self,
        member: &str,
        request: &Request,
    ) -> Result<Reply, ClientError>
    where
        Request: Serialize + Sync + ?Sized,
        Reply: DeserializeOwned,
    {
        if !is_confidential(member) {
            return Err(ClientError::NotConfidential);
        }
        self.client
            .call_attested_detailed(MODULE_ID, member, (request,))
            .await
            .map_err(ClientError::Remote)
    }

    /// Derive an account through an attested wallet module.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable, unattested, or rejects
    /// the request.
    pub async fn derive_account(
        &self,
        secret: SecretMaterial,
    ) -> Result<DerivedAccount, ClientError> {
        let request = MnemonicRequestGuard(secret);
        self.call_attested(methods::DERIVE_ACCOUNT, &request.0)
            .await
    }

    /// Sign a transaction inside the attested wallet module.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable, unattested, or rejects
    /// the transaction.
    pub async fn sign_transaction(
        &self,
        secret: SecretMaterial,
        transaction: TransactionSpec,
    ) -> Result<SignedTransaction, ClientError> {
        let request = MnemonicRequestGuard(SignRequest {
            secret,
            transaction,
        });
        self.call_attested(methods::SIGN_TRANSACTION, &request.0)
            .await
    }

    /// Sign opaque bytes inside the attested wallet module.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable, unattested, or rejects
    /// the request.
    pub async fn sign_message(
        &self,
        secret: SecretMaterial,
        message: &[u8],
        scheme: Scheme,
    ) -> Result<Signature, ClientError> {
        let request = MnemonicRequestGuard(SignMessageRequest {
            secret,
            message_hex: hex(message),
            scheme,
        });
        self.call_attested(methods::SIGN_MESSAGE, &request.0).await
    }

    /// Export a derived key through the attested wallet module.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable, unattested, or rejects
    /// the request.
    pub async fn export_key(&self, secret: SecretMaterial) -> Result<ExportedKey, ClientError> {
        let request = MnemonicRequestGuard(ExportRequest { secret });
        self.call_attested(methods::EXPORT_KEY, &request.0).await
    }

    /// Generate a recovery phrase in the attested wallet module.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable, unattested, or rejects
    /// the requested word count.
    pub async fn generate_mnemonic(
        &self,
        word_count: u8,
    ) -> Result<GenerateMnemonicResponse, ClientError> {
        let request = GenerateMnemonicRequest { word_count };
        self.call_attested(methods::GENERATE_MNEMONIC, &request)
            .await
    }

    /// Derive a BIP-39 seed through the attested wallet module.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable, unattested, or rejects
    /// the phrase.
    pub async fn derive_mnemonic_seed(
        &self,
        mnemonic: String,
    ) -> Result<DeriveMnemonicSeedResponse, ClientError> {
        let request = MnemonicRequestGuard(DeriveMnemonicSeedRequest { mnemonic });
        self.call_attested(methods::DERIVE_MNEMONIC_SEED, &request.0)
            .await
    }

    /// Encode ERC-20 transfer calldata with the module-owned ABI implementation.
    ///
    /// # Errors
    ///
    /// Returns an error if the module is unavailable or rejects the recipient
    /// or amount.
    pub async fn encode_erc20_transfer(
        &self,
        to_address: String,
        amount_raw: String,
    ) -> Result<String, ClientError> {
        let request = EncodeErc20TransferRequest {
            to_address,
            amount_raw,
        };
        let response: EncodeErc20TransferResponse =
            self.call(methods::ENCODE_ERC20_TRANSFER, &request).await?;
        Ok(response.calldata)
    }
}

fn is_confidential(member: &str) -> bool {
    CONFIDENTIAL_METHODS.contains(&member)
}

struct MnemonicRequestGuard<T: ZeroizeMnemonic>(T);

impl<T: ZeroizeMnemonic> Drop for MnemonicRequestGuard<T> {
    fn drop(&mut self) {
        self.0.zeroize_mnemonic();
    }
}

trait ZeroizeMnemonic {
    fn zeroize_mnemonic(&mut self);
}

impl ZeroizeMnemonic for SecretMaterial {
    fn zeroize_mnemonic(&mut self) {
        self.mnemonic.zeroize();
    }
}

impl ZeroizeMnemonic for DeriveMnemonicSeedRequest {
    fn zeroize_mnemonic(&mut self) {
        self.mnemonic.zeroize();
    }
}

impl ZeroizeMnemonic for SignRequest {
    fn zeroize_mnemonic(&mut self) {
        self.secret.mnemonic.zeroize();
        #[cfg(test)]
        crate::tests::observe_mnemonic_wipe("sign_transaction", self.secret.mnemonic.is_empty());
    }
}

impl ZeroizeMnemonic for SignMessageRequest {
    fn zeroize_mnemonic(&mut self) {
        self.secret.mnemonic.zeroize();
        #[cfg(test)]
        crate::tests::observe_mnemonic_wipe("sign_message", self.secret.mnemonic.is_empty());
    }
}

impl ZeroizeMnemonic for ExportRequest {
    fn zeroize_mnemonic(&mut self) {
        self.secret.mnemonic.zeroize();
        #[cfg(test)]
        crate::tests::observe_mnemonic_wipe("export_key", self.secret.mnemonic.is_empty());
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
