//! EVM `exact` scheme payment construction: EIP-3009
//! `transferWithAuthorization`, signed over its EIP-712 digest by the wallet's
//! EVM key. The facilitator submits the signed authorization on-chain.

use log::debug;

use super::signer::{PaymentSigner, SignScheme};
use super::{LOG_PREFIX, fresh_nonce};
use crate::eip712;
use crate::protocol::X402Error;
use crate::wire::{
    EvmAuthorization, EvmPaymentProof, PaymentChain, PaymentPayload, PaymentProof, PaymentRequired,
    PaymentRequirements, X402_VERSION,
};

/// Build an EVM payment using EIP-3009 `transferWithAuthorization`.
///
/// Signs the typed data with the wallet's EVM key and returns the proof for the
/// facilitator to submit on-chain.
pub(super) async fn build_evm_payment(
    signer: &dyn PaymentSigner,
    challenge: &PaymentRequired,
    req: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    let account = signer
        .account(PaymentChain::Evm)
        .await
        .map_err(X402Error::Wallet)?;
    let authorization = evm_payment_authorization(&account.address, req)?;

    // Signed behind the seam over the prehashed EIP-712 digest. This process
    // never holds the EVM key.
    let signature = signer
        .sign(
            PaymentChain::Evm,
            &authorization.digest,
            SignScheme::Secp256k1Digest,
        )
        .await
        .map_err(|e| X402Error::Wallet(format!("sign EIP-3009: {e}")))?;
    let sig_bytes = eip712_signature(&signature)?;

    evm_payment_payload(&authorization, sig_bytes, &account.address, challenge, req)
}

/// Turn the seam's `r ‖ s ‖ recovery_id` into the `r ‖ s ‖ v` an EIP-712
/// signature carries, where `v` is the recovery id offset by 27.
fn eip712_signature(signature: &[u8]) -> Result<[u8; 65], X402Error> {
    let Ok(raw) = <[u8; 65]>::try_from(signature) else {
        return Err(X402Error::Wallet(
            "the wallet module returned a malformed signature".to_string(),
        ));
    };
    let mut sig_bytes = raw;
    sig_bytes[64] = raw[64]
        .checked_add(27)
        .ok_or_else(|| X402Error::Wallet("recovery id out of range".to_string()))?;
    Ok(sig_bytes)
}

/// The EIP-712 digest to sign, and the fields the payload needs alongside it.
///
/// Split out from signing so production (which signs behind the seam) and the
/// tests (which recover the signer from the result) share one implementation of
/// the part that can be wrong. Only *who holds the key* differs between them.
#[derive(Debug)]
pub(super) struct EvmPaymentAuthorization {
    /// The 32-byte EIP-712 digest.
    pub(super) digest: [u8; 32],
    /// The EIP-3009 nonce, echoed into the payload.
    pub(super) nonce: [u8; 32],
    valid_after_secs: u64,
    valid_before_secs: u64,
}

/// Compute the EIP-3009 authorization and its EIP-712 digest.
pub(super) fn evm_payment_authorization(
    from_address: &str,
    req: &PaymentRequirements,
) -> Result<EvmPaymentAuthorization, X402Error> {
    let chain_id = req
        .evm_chain_id()
        .ok_or_else(|| X402Error::Protocol(format!("not an EVM network: {}", req.network)))?;

    let amount = eip712::u256_from_decimal(&req.amount)
        .map_err(|e| X402Error::Protocol(format!("invalid amount '{}': {e}", req.amount)))?;

    let from_bytes = evm_address_bytes(from_address)?;
    let pay_to = evm_address_bytes(&req.pay_to)?;
    let token_address = evm_address_bytes(&req.asset)?;

    // EIP-3009 parameters.
    let valid_after = eip712::u256_from_u64(0);
    let valid_before_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .saturating_add(req.max_timeout_seconds);
    let valid_before = eip712::u256_from_u64(valid_before_secs);
    let nonce = fresh_nonce();

    // EIP-712 typed data for `transferWithAuthorization`.
    let domain_name = req
        .extra
        .as_ref()
        .and_then(|e| e.name.as_deref())
        .unwrap_or("USD Coin");
    let domain_version = req
        .extra
        .as_ref()
        .and_then(|e| e.version.as_deref())
        .unwrap_or("2");
    let domain_separator =
        eip712::domain_separator(token_address, chain_id, domain_name, domain_version);
    let struct_hash = eip712::transfer_with_authorization_hash(
        from_bytes,
        pay_to,
        amount,
        valid_after,
        valid_before,
        nonce,
    );
    let digest = eip712::signing_digest(domain_separator, struct_hash);

    Ok(EvmPaymentAuthorization {
        digest,
        nonce,
        valid_after_secs: 0,
        valid_before_secs,
    })
}

/// Assemble the payload from an authorization and its signature.
///
/// An EIP-712 signature is `r ‖ s ‖ v` where `v` is the recovery id offset by
/// 27 — not EIP-155's chain-mixed `v`, because typed data is not a transaction.
pub(super) fn evm_payment_payload(
    authorization: &EvmPaymentAuthorization,
    sig_bytes: [u8; 65],
    from_address: &str,
    challenge: &PaymentRequired,
    req: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    let chain_id = req
        .evm_chain_id()
        .ok_or_else(|| X402Error::Protocol(format!("not an EVM network: {}", req.network)))?;

    let sig_hex = format!("0x{}", hex::encode(sig_bytes));
    let nonce_hex = format!("0x{}", hex::encode(authorization.nonce));

    debug!(
        "{LOG_PREFIX} built EVM payment chain_id={chain_id} amount={} asset={} from={} to={}",
        req.amount, req.asset, from_address, req.pay_to
    );

    Ok(PaymentPayload {
        x402_version: X402_VERSION,
        resource: Some(challenge.resource.clone()),
        accepted: req.clone(),
        payload: PaymentProof::Evm(EvmPaymentProof {
            signature: sig_hex,
            authorization: EvmAuthorization {
                from: from_address.to_string(),
                to: req.pay_to.clone(),
                value: req.amount.clone(),
                valid_after: authorization.valid_after_secs.to_string(),
                valid_before: authorization.valid_before_secs.to_string(),
                nonce: nonce_hex,
            },
        }),
        extensions: serde_json::Map::new(),
    })
}

/// The 20 raw bytes of an EVM address.
fn evm_address_bytes(address: &str) -> Result<[u8; 20], X402Error> {
    let validated = tinywallet_crypto::address::evm::validate(address)
        .map_err(|e| X402Error::Protocol(format!("invalid EVM address '{address}': {e}")))?;
    // `validate` guarantees 40 hex digits, so the decode cannot fail; one arm
    // keeps a hypothetical failure a protocol error instead of a panic.
    let body = validated.strip_prefix("0x").unwrap_or(&validated);
    hex::decode(body)
        .ok()
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        .ok_or_else(|| X402Error::Protocol(format!("invalid EVM address '{address}'")))
}
