//! Fakes and fixtures shared by the unit tests of `crypto`, `protocol` and
//! `tools`: a wallet, a chain transport, a proxy policy and challenge builders.
//!
//! The wallet is backed by the root `tinywallet` crate's `key` gate, so a test
//! signs as exactly the account a real wallet derives from the same mnemonic,
//! with no broker and no environment.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use tinywallet_crypto::rpc::{NetworkId, Transport, TransportError, TransportResult};

use crate::crypto::{PaymentAccount, PaymentSigner, SignScheme};
use crate::wire::{
    BASE_MAINNET_CAIP2, PaymentChain, PaymentExtra, PaymentRequired, PaymentRequirements,
    ResourceInfo, SOLANA_MAINNET_CAIP2, USDC_BASE_MAINNET, USDC_MINT_MAINNET, X402_VERSION,
};

/// The BIP-39 vector mnemonic. Never use it for real funds.
pub(crate) const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon \
                                   abandon abandon abandon abandon abandon about";
/// The vector mnemonic's EVM account at `m/44'/60'/0'/0/0`.
pub(crate) const EVM_ADDRESS: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
/// A recipient on Base, as the twit.sh challenge names it.
pub(crate) const EVM_RECIPIENT: &str = "0x9DBA414637c611a16BEa6f0796BFcbcBdc410df8";
/// A Solana recipient.
pub(crate) const SOLANA_RECIPIENT: &str = "2wKupLR9q6wXYppw8Gr2NvWxKBUqm4PPJKkQfoxHDBg4";
/// The facilitator that co-signs Solana payments as fee payer.
pub(crate) const FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";
/// A recent blockhash, as base58 of 32 bytes.
pub(crate) const BLOCKHASH: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

/// A wallet that signs locally, with switches for each way a real one fails.
#[derive(Debug, Default)]
pub(crate) struct FakePaymentSigner {
    /// Fail `account` with this message.
    pub(crate) account_error: Option<String>,
    /// Fail `sign` with this message.
    pub(crate) sign_error: Option<String>,
    /// Truncate every signature to this many bytes.
    pub(crate) signature_len: Option<usize>,
    /// Replace the secp256k1 recovery id with this value.
    pub(crate) recovery_id: Option<u8>,
    /// Report the raw Solana public key rather than only the address.
    pub(crate) report_pubkey: bool,
    /// Every `(chain, scheme, message length)` passed to `sign`.
    pub(crate) sign_calls: Mutex<Vec<(PaymentChain, SignScheme, usize)>>,
}

impl FakePaymentSigner {
    fn derived(chain: tinywallet::Chain, path: &str) -> tinywallet::key::DerivedKey {
        tinywallet::key::derive(chain, MNEMONIC, path).unwrap()
    }

    fn evm() -> tinywallet::key::DerivedKey {
        Self::derived(tinywallet::Chain::Evm, "m/44'/60'/0'/0/0")
    }

    fn solana() -> tinywallet::key::DerivedKey {
        Self::derived(tinywallet::Chain::Solana, "m/44'/501'/0'/0'")
    }

    /// The Solana account's address, as base58.
    pub(crate) fn solana_address() -> String {
        Self::solana().address().to_string()
    }

    /// The raw 32-byte EVM secret, for recovering the signer in tests.
    pub(crate) fn evm_secret() -> Vec<u8> {
        Self::evm().secret_bytes().to_vec()
    }

    /// The Solana ed25519 verifying key.
    pub(crate) fn solana_verifying_key() -> ed25519_dalek::VerifyingKey {
        let secret: [u8; 32] = Self::solana().secret_bytes().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&secret).verifying_key()
    }
}

#[async_trait]
impl PaymentSigner for FakePaymentSigner {
    async fn account(&self, chain: PaymentChain) -> Result<PaymentAccount, String> {
        if let Some(error) = &self.account_error {
            return Err(error.clone());
        }
        Ok(match chain {
            PaymentChain::Evm => PaymentAccount {
                address: Self::evm().address().to_string(),
                pubkey: None,
            },
            PaymentChain::Solana => PaymentAccount {
                address: Self::solana().address().to_string(),
                pubkey: self
                    .report_pubkey
                    .then(|| Self::solana_verifying_key().to_bytes()),
            },
        })
    }

    async fn sign(
        &self,
        chain: PaymentChain,
        message: &[u8],
        scheme: SignScheme,
    ) -> Result<Vec<u8>, String> {
        self.sign_calls
            .lock()
            .unwrap()
            .push((chain, scheme, message.len()));
        if let Some(error) = &self.sign_error {
            return Err(error.clone());
        }
        let mut signature = match scheme {
            SignScheme::Secp256k1Digest => {
                let key = k256::ecdsa::SigningKey::from_slice(&Self::evm_secret()).unwrap();
                let (sig, recovery) = key.sign_prehash_recoverable(message).unwrap();
                let mut out = sig.to_bytes().to_vec();
                out.push(self.recovery_id.unwrap_or_else(|| recovery.to_byte()));
                out
            }
            SignScheme::Ed25519 => {
                use ed25519_dalek::Signer;
                let secret: [u8; 32] = Self::solana().secret_bytes().try_into().unwrap();
                ed25519_dalek::SigningKey::from_bytes(&secret)
                    .sign(message)
                    .to_bytes()
                    .to_vec()
            }
        };
        if let Some(len) = self.signature_len {
            signature.truncate(len);
        }
        Ok(signature)
    }
}

/// A chain transport with canned answers and a call log.
#[derive(Debug, Default)]
pub(crate) struct FakeTransport {
    /// Answers handed out in order; once empty, a healthy blockhash reply.
    pub(crate) responses: Mutex<VecDeque<TransportResult<Value>>>,
    /// Every `(network, method)` requested.
    pub(crate) calls: Mutex<Vec<(NetworkId, String)>>,
}

impl FakeTransport {
    /// A transport whose next answer is `response`.
    pub(crate) fn answering(response: TransportResult<Value>) -> Self {
        let transport = Self::default();
        transport.responses.lock().unwrap().push_back(response);
        transport
    }

    /// A healthy `getLatestBlockhash` reply.
    pub(crate) fn blockhash_reply() -> Value {
        json!({"context": {"slot": 1}, "value": {"blockhash": BLOCKHASH, "lastValidBlockHeight": 9}})
    }
}

#[async_trait]
impl Transport for FakeTransport {
    async fn json_rpc(
        &self,
        network: NetworkId,
        method: &str,
        _params: Value,
    ) -> TransportResult<Value> {
        self.calls
            .lock()
            .unwrap()
            .push((network, method.to_string()));
        self.responses
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Ok(Self::blockhash_reply()))
    }

    async fn rest_get(&self, network: NetworkId, path: &str) -> TransportResult<String> {
        Err(TransportError::Unreachable {
            network,
            message: path.to_string(),
        })
    }

    async fn rest_post(
        &self,
        network: NetworkId,
        path: &str,
        _body: String,
        _content_type: &str,
    ) -> TransportResult<String> {
        Err(TransportError::Unreachable {
            network,
            message: path.to_string(),
        })
    }
}

/// A proxy policy that records the services it was applied for.
#[cfg(feature = "tools")]
#[derive(Debug, Default)]
pub(crate) struct FakeProxyPolicy {
    /// Every `service` label `apply` saw.
    pub(crate) services: Mutex<Vec<String>>,
}

#[cfg(feature = "tools")]
impl crate::protocol::ProxyPolicy for FakeProxyPolicy {
    fn apply(&self, builder: reqwest::ClientBuilder, service: &str) -> reqwest::ClientBuilder {
        self.services.lock().unwrap().push(service.to_string());
        builder
    }

    fn allows_direct_connection(&self, _service: &str) -> bool {
        true
    }
}

/// An EVM `exact` requirement on Base for 2500 atomic USDC.
pub(crate) fn evm_requirement() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".into(),
        network: BASE_MAINNET_CAIP2.into(),
        amount: "2500".into(),
        asset: USDC_BASE_MAINNET.into(),
        pay_to: EVM_RECIPIENT.into(),
        max_timeout_seconds: 300,
        extra: Some(PaymentExtra {
            fee_payer: None,
            memo: None,
            name: Some("USD Coin".into()),
            version: Some("2".into()),
        }),
    }
}

/// A Solana `exact` requirement for 10000 atomic USDC, with a fee payer.
pub(crate) fn solana_requirement() -> PaymentRequirements {
    PaymentRequirements {
        scheme: "exact".into(),
        network: SOLANA_MAINNET_CAIP2.into(),
        amount: "10000".into(),
        asset: USDC_MINT_MAINNET.into(),
        pay_to: SOLANA_RECIPIENT.into(),
        max_timeout_seconds: 60,
        extra: Some(PaymentExtra {
            fee_payer: Some(FEE_PAYER.into()),
            memo: Some("pi_3abc123".into()),
            name: None,
            version: None,
        }),
    }
}

/// A challenge offering `accepts`.
pub(crate) fn challenge(accepts: Vec<PaymentRequirements>) -> PaymentRequired {
    PaymentRequired {
        x402_version: X402_VERSION,
        error: Some("Payment required".into()),
        resource: ResourceInfo {
            url: "https://x402.example.test/thing".into(),
            description: Some("A thing".into()),
            mime_type: Some("application/json".into()),
        },
        accepts,
        extensions: serde_json::Map::new(),
    }
}

/// The `PAYMENT-REQUIRED` header value for `challenge`.
pub(crate) fn challenge_header(challenge: &PaymentRequired) -> String {
    B64.encode(serde_json::to_vec(challenge).unwrap())
}

mod server;
pub(crate) use server::{RecordedRequest, ServerConfig, TestServer};
