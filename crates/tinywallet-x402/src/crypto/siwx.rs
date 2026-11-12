//! The x402 `sign-in-with-x` extension on EVM: an EIP-4361 (SIWE) message
//! built from the server's challenge, signed with EIP-191 `personal_sign` by
//! the wallet's EVM key.
//!
//! This signs a *sign-in*, not arbitrary text. Every line of the message comes
//! from the challenge and is checked first: the domain must be the requested
//! host, the URI and every resource must be HTTPS on the requested origin,
//! the message must carry an expiry still in the future and no field may
//! carry a line break that would forge another line of the message. A
//! challenge that fails any of these is refused before the wallet is asked.
//!
//! The message text matches the reference client's `formatSIWEMessage` (the
//! `@signinwithethereum/siwe` library's `prepareMessage`) byte for byte, and
//! the header is its `encodeSIWxHeader`: standard base64 of the JSON payload.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Duration, Utc};
use log::debug;
use sha3::{Digest, Keccak256};

use super::LOG_PREFIX;
use super::evm_payment::eip712_signature;
use super::signer::{PaymentSigner, SignScheme};
use crate::protocol::X402Error;
use crate::wire::{
    PaymentChain, PaymentRequired, SIGN_IN_WITH_X, SiwxExtension, SiwxInfo, SiwxPayload,
};

/// The chain preferred when the server accepts several: Base mainnet.
const PREFERRED_CHAIN_ID: u64 = 8453;

/// How far ahead of this clock a server's `issuedAt` may be.
const MAX_CLOCK_SKEW_SECS: i64 = 300;

/// The signed answer to a `sign-in-with-x` challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiwxProof {
    /// The `SIGN-IN-WITH-X` request header value.
    pub header_value: String,
    /// The account that signed in, EIP-55 checksummed.
    pub address: String,
    /// The CAIP-2 chain the sign-in names, such as `eip155:8453`.
    pub chain_id: String,
}

/// Sign the `sign-in-with-x` challenge in `challenge`, which answered a request
/// to `request_url`, with the wallet's EVM account.
///
/// # Errors
///
/// [`X402Error::SignInRefused`] when the challenge has no usable
/// `sign-in-with-x` extension or breaks one of the rules in the module docs;
/// nothing is signed then. [`X402Error::Wallet`] when the wallet cannot sign.
pub async fn sign_in_with_x(
    signer: &dyn PaymentSigner,
    challenge: &PaymentRequired,
    request_url: &str,
) -> Result<SiwxProof, X402Error> {
    sign_in_with_x_at(signer, challenge, request_url, Utc::now()).await
}

/// [`sign_in_with_x`] as of `now`.
pub(super) async fn sign_in_with_x_at(
    signer: &dyn PaymentSigner,
    challenge: &PaymentRequired,
    request_url: &str,
    now: DateTime<Utc>,
) -> Result<SiwxProof, X402Error> {
    let extension = challenge
        .extensions
        .get(SIGN_IN_WITH_X)
        .ok_or_else(|| refused("the challenge does not ask for sign-in-with-x"))?;
    let extension: SiwxExtension = serde_json::from_value(extension.clone())
        .map_err(|e| refused(&format!("unreadable sign-in-with-x extension: {e}")))?;
    let info = extension.info;
    check_origin(&info, request_url)?;
    check_fields(&info, now)?;
    let chain_id = choose_chain(&extension.supported_chains)?;

    let account = signer
        .account(PaymentChain::Evm)
        .await
        .map_err(X402Error::Wallet)?;
    let address = tinywallet_crypto::address::evm::to_checksummed(&account.address)
        .map_err(|e| X402Error::Wallet(format!("invalid wallet address: {e}")))?;
    let message = siwe_message(&info, chain_id, &address);
    let signature = signer
        .sign(
            PaymentChain::Evm,
            &eip191_digest(&message),
            SignScheme::Secp256k1Digest,
        )
        .await
        .map_err(|e| X402Error::Wallet(format!("sign sign-in-with-x: {e}")))?;
    let signature = format!("0x{}", hex::encode(eip712_signature(&signature)?));

    let chain_id = format!("eip155:{chain_id}");
    let payload = SiwxPayload {
        domain: info.domain,
        address: address.clone(),
        statement: info.statement,
        uri: info.uri,
        version: info.version,
        chain_id: chain_id.clone(),
        kind: "eip191".to_string(),
        nonce: info.nonce,
        issued_at: info.issued_at,
        expiration_time: info.expiration_time,
        not_before: info.not_before,
        request_id: info.request_id,
        resources: info.resources,
        signature,
    };
    let json = serde_json::to_vec(&payload)
        .map_err(|e| X402Error::Protocol(format!("serialize sign-in-with-x: {e}")))?;
    debug!(
        "{LOG_PREFIX} signed sign-in-with-x for {} on {chain_id}",
        payload.domain
    );
    Ok(SiwxProof {
        header_value: B64.encode(json),
        address,
        chain_id,
    })
}

/// The EIP-4361 message, laid out exactly as `SiweMessage.prepareMessage()`.
pub(super) fn siwe_message(info: &SiwxInfo, chain_id: u64, address: &str) -> String {
    let mut lines = vec![
        format!("URI: {}", info.uri),
        format!("Version: {}", info.version),
        format!("Chain ID: {chain_id}"),
        format!("Nonce: {}", info.nonce),
        format!("Issued At: {}", info.issued_at),
    ];
    if let Some(expiration) = &info.expiration_time {
        lines.push(format!("Expiration Time: {expiration}"));
    }
    if let Some(not_before) = &info.not_before {
        lines.push(format!("Not Before: {not_before}"));
    }
    if let Some(request_id) = &info.request_id {
        lines.push(format!("Request ID: {request_id}"));
    }
    if let Some(resources) = &info.resources {
        lines.push("Resources:".to_string());
        lines.extend(resources.iter().map(|resource| format!("- {resource}")));
    }
    let header = format!(
        "{} wants you to sign in with your Ethereum account:\n{address}",
        info.domain
    );
    let prefix = match &info.statement {
        None => format!("{header}\n\n"),
        Some(statement) => format!("{header}\n\n{statement}\n"),
    };
    format!("{prefix}\n{}", lines.join("\n"))
}

/// The EIP-191 `personal_sign` digest of `message`.
pub(super) fn eip191_digest(message: &str) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(format!("\x19Ethereum Signed Message:\n{}", message.len()).as_bytes());
    hasher.update(message.as_bytes());
    hasher.finalize().into()
}

fn refused(reason: &str) -> X402Error {
    X402Error::SignInRefused {
        reason: reason.to_string(),
    }
}

/// The domain must be the requested host (and non-default port), and the URI
/// and every resource must be HTTPS on the requested origin.
fn check_origin(info: &SiwxInfo, request_url: &str) -> Result<(), X402Error> {
    let request =
        reqwest::Url::parse(request_url).map_err(|_| refused("the requested URL is not a URL"))?;
    if request.scheme() != "https" {
        return Err(refused("sign-in is only answered for an https request"));
    }
    let host = request.host_str().unwrap_or_default();
    let authority = match request.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    if info.domain != authority {
        return Err(refused(&format!(
            "domain {} is not the requested host {authority}",
            info.domain
        )));
    }
    let same_origin = |uri: &str| {
        reqwest::Url::parse(uri)
            .is_ok_and(|url| url.scheme() == "https" && url.origin() == request.origin())
    };
    if !same_origin(&info.uri) {
        return Err(refused(&format!(
            "uri {} is not https on the requested origin",
            info.uri
        )));
    }
    for resource in info.resources.iter().flatten() {
        if !same_origin(resource) {
            return Err(refused(&format!(
                "resource {resource} is not https on the requested origin"
            )));
        }
    }
    Ok(())
}

/// The fields that are copied into the message must be well formed: a known
/// version, an EIP-4361 nonce, RFC 3339 times, an expiry in the future, an
/// issue time not ahead of this clock, and no line breaks.
fn check_fields(info: &SiwxInfo, now: DateTime<Utc>) -> Result<(), X402Error> {
    if info.version != "1" {
        return Err(refused(&format!("unsupported version {}", info.version)));
    }
    if info.nonce.len() < 8 || !info.nonce.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(refused(
            "the nonce is not at least 8 alphanumeric characters",
        ));
    }
    let instant = |field: &str, value: &str| {
        DateTime::parse_from_rfc3339(value)
            .map(|at| at.with_timezone(&Utc))
            .map_err(|_| refused(&format!("{field} is not an RFC 3339 time")))
    };
    if instant("issuedAt", &info.issued_at)? > now + Duration::seconds(MAX_CLOCK_SKEW_SECS) {
        return Err(refused("issuedAt is in the future"));
    }
    let expiration = info
        .expiration_time
        .as_deref()
        .ok_or_else(|| refused("the challenge has no expirationTime"))?;
    if instant("expirationTime", expiration)? <= now {
        return Err(refused("the challenge has expired"));
    }
    if let Some(not_before) = &info.not_before {
        instant("notBefore", not_before)?;
    }
    let one_line = |value: &Option<String>| {
        value
            .as_deref()
            .is_none_or(|text| !text.contains(['\n', '\r']))
    };
    if !one_line(&info.statement) || !one_line(&info.request_id) {
        return Err(refused("statement and requestId must be a single line"));
    }
    Ok(())
}

/// The EIP-155 chain id to sign for: an `eip155` chain with `eip191`
/// signatures, Base when offered.
fn choose_chain(chains: &[crate::wire::SiwxSupportedChain]) -> Result<u64, X402Error> {
    let candidates: Vec<u64> = chains
        .iter()
        .filter(|chain| chain.kind == "eip191")
        .filter_map(|chain| chain.chain_id.strip_prefix("eip155:")?.parse().ok())
        .collect();
    candidates
        .iter()
        .copied()
        .find(|id| *id == PREFERRED_CHAIN_ID)
        .or_else(|| candidates.first().copied())
        .ok_or_else(|| refused("no eip155 chain with eip191 signatures is offered"))
}

#[cfg(test)]
#[path = "siwx_tests.rs"]
mod tests;
