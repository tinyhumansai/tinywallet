//! EVM `upto` scheme payment construction: a Permit2
//! `PermitWitnessTransferFrom` whose spender is the `x402UptoPermit2Proxy`,
//! signed over its EIP-712 digest by the wallet's EVM key, plus the optional
//! EIP-2612 `Permit` the `eip2612GasSponsoring` extension asks for.
//!
//! The payer signs a ceiling (`permitted.amount`); the facilitator later
//! settles the amount actually used, which may be anything up to it.
//!
//! Matches the x402 reference client (`createUptoPermit2Payload` and
//! `trySignEip2612PermitExtension` in coinbase/x402), with one deliberate
//! difference: the deadline is capped at [`MAX_AUTHORIZATION_SECS`] as for an
//! EIP-3009 authorization, rather than taken from `maxTimeoutSeconds` as is.

use log::debug;
use serde_json::{Map, Value, json};
use tinywallet_crypto::rpc::{NetworkId, Transport};

use super::evm_payment::{MAX_AUTHORIZATION_SECS, eip712_signature, evm_address_bytes};
use super::signer::{PaymentSigner, SignScheme};
use super::{LOG_PREFIX, fresh_nonce};
use crate::abi;
use crate::eip712::{self, U256Bytes, UptoPermit};
use crate::protocol::X402Error;
use crate::wire::{
    EIP2612_GAS_SPONSORING, PERMIT2_ADDRESS, PaymentChain, PaymentPayload, PaymentProof,
    PaymentRequired, PaymentRequirements, Permit2Authorization, Permit2PaymentProof,
    TokenPermissions, UPTO_PERMIT2_PROXY_ADDRESS, UptoWitness, X402_VERSION,
};

/// The `eip2612GasSponsoring` info schema version the reference client sends.
const EIP2612_INFO_VERSION: &str = "1";

/// Build and sign an `upto` payment with a fresh nonce at the current time.
pub(super) async fn build_upto_payment(
    signer: &dyn PaymentSigner,
    transport: &dyn Transport,
    challenge: &PaymentRequired,
    requirement: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    build_upto_payment_at(
        signer,
        transport,
        challenge,
        requirement,
        fresh_nonce(),
        now,
    )
    .await
}

/// [`build_upto_payment`] with the nonce and the clock given.
pub(super) async fn build_upto_payment_at(
    signer: &dyn PaymentSigner,
    transport: &dyn Transport,
    challenge: &PaymentRequired,
    requirement: &PaymentRequirements,
    nonce: U256Bytes,
    now_secs: u64,
) -> Result<PaymentPayload, X402Error> {
    let account = signer
        .account(PaymentChain::Evm)
        .await
        .map_err(X402Error::Wallet)?;
    let terms = upto_terms(&account.address, requirement, nonce, now_secs)?;
    let signature = sign_digest(signer, terms.digest(), "Permit2").await?;

    let mut client_extensions = Map::new();
    if let Some(info) =
        eip2612_permit_info(signer, transport, challenge, requirement, &terms).await?
    {
        client_extensions.insert(EIP2612_GAS_SPONSORING.to_string(), json!({ "info": info }));
    }

    debug!(
        "{LOG_PREFIX} built EVM upto payment chain_id={} max_amount={} asset={} to={} sponsored_permit={}",
        terms.chain_id,
        requirement.amount,
        requirement.asset,
        requirement.pay_to,
        !client_extensions.is_empty()
    );

    Ok(PaymentPayload {
        x402_version: X402_VERSION,
        resource: Some(challenge.resource.clone()),
        accepted: requirement.clone(),
        payload: PaymentProof::Permit2(Permit2PaymentProof {
            signature,
            permit2_authorization: terms.authorization(),
        }),
        extensions: merge_extensions(&challenge.extensions, client_extensions),
    })
}

/// Everything an `upto` permit binds, in both its hashed and its wire form.
#[derive(Debug)]
pub(super) struct UptoTerms {
    permit: UptoPermit,
    chain_id: u64,
    from: String,
    token: String,
    amount: String,
    to: String,
    facilitator: String,
    nonce: String,
    deadline_secs: u64,
}

impl UptoTerms {
    /// The 32-byte EIP-712 digest to sign, under Permit2's domain.
    pub(super) fn digest(&self) -> [u8; 32] {
        eip712::signing_digest(
            eip712::permit2_domain_separator(self.chain_id),
            self.permit.struct_hash(),
        )
    }

    fn authorization(&self) -> Permit2Authorization {
        Permit2Authorization {
            from: self.from.clone(),
            permitted: TokenPermissions {
                token: self.token.clone(),
                amount: self.amount.clone(),
            },
            spender: UPTO_PERMIT2_PROXY_ADDRESS.to_string(),
            nonce: self.nonce.clone(),
            deadline: self.deadline_secs.to_string(),
            witness: UptoWitness {
                to: self.to.clone(),
                facilitator: self.facilitator.clone(),
                valid_after: "0".to_string(),
            },
        }
    }
}

/// Read the permit terms out of `requirement`: valid from time zero, void
/// after `maxTimeoutSeconds` (capped), for at most `amount`.
pub(super) fn upto_terms(
    from_address: &str,
    requirement: &PaymentRequirements,
    nonce: U256Bytes,
    now_secs: u64,
) -> Result<UptoTerms, X402Error> {
    let chain_id = requirement.evm_chain_id().ok_or_else(|| {
        X402Error::Protocol(format!("not an EVM network: {}", requirement.network))
    })?;
    // `upto` allows Permit2 only; an absent method means Permit2.
    if let Some(method) = requirement
        .extra
        .as_ref()
        .and_then(|extra| extra.asset_transfer_method.as_deref())
        .filter(|method| *method != "permit2")
    {
        return Err(X402Error::Protocol(format!(
            "upto requirement asks for assetTransferMethod {method}; only permit2 is supported"
        )));
    }
    let facilitator = requirement
        .extra
        .as_ref()
        .and_then(|extra| extra.facilitator_address.as_deref())
        .ok_or_else(|| {
            X402Error::Protocol("upto requirement has no extra.facilitatorAddress".to_string())
        })?;
    let amount = eip712::u256_from_decimal(&requirement.amount).map_err(|e| {
        X402Error::Protocol(format!("invalid amount '{}': {e}", requirement.amount))
    })?;
    let deadline_secs = now_secs.saturating_add(
        requirement
            .max_timeout_seconds
            .clamp(1, MAX_AUTHORIZATION_SECS),
    );

    let permit = UptoPermit {
        token: evm_address_bytes(&requirement.asset)?,
        amount,
        spender: eip712::UPTO_PERMIT2_PROXY,
        nonce,
        deadline: eip712::u256_from_u64(deadline_secs),
        to: evm_address_bytes(&requirement.pay_to)?,
        facilitator: evm_address_bytes(facilitator)?,
        valid_after: eip712::u256_from_u64(0),
    };
    Ok(UptoTerms {
        permit,
        chain_id,
        from: checksummed(from_address)?,
        token: checksummed(&requirement.asset)?,
        amount: requirement.amount.trim().to_string(),
        to: checksummed(&requirement.pay_to)?,
        facilitator: checksummed(facilitator)?,
        nonce: eip712::u256_to_decimal(&nonce),
        deadline_secs,
    })
}

/// The `eip2612GasSponsoring` info, when the server sponsors it and the payer's
/// Permit2 allowance does not already cover the permit. `None` otherwise.
///
/// As in the reference client: no token domain (`extra.name` and
/// `extra.version`) means no permit; an allowance that cannot be read is
/// treated as insufficient; a token nonce that cannot be read fails the
/// payment, because a permit over a guessed nonce is rejected on chain. The
/// permit approves exactly `permitted.amount`, which is what the proxy's
/// `settleWithPermit` requires, and shares the Permit2 deadline.
async fn eip2612_permit_info(
    signer: &dyn PaymentSigner,
    transport: &dyn Transport,
    challenge: &PaymentRequired,
    requirement: &PaymentRequirements,
    terms: &UptoTerms,
) -> Result<Option<Value>, X402Error> {
    if !challenge.extensions.contains_key(EIP2612_GAS_SPONSORING) {
        return Ok(None);
    }
    let extra = requirement.extra.as_ref();
    let (Some(name), Some(version)) = (
        extra.and_then(|extra| extra.name.as_deref()),
        extra.and_then(|extra| extra.version.as_deref()),
    ) else {
        return Ok(None);
    };
    let network = NetworkId::evm(terms.chain_id);

    let allowance_call = abi::encode_erc20_allowance(&terms.from, PERMIT2_ADDRESS)
        .map_err(|e| X402Error::Protocol(format!("encode allowance call: {e}")))?;
    match read_uint256(transport, network, &terms.token, &allowance_call).await {
        Ok(allowance) if allowance >= terms.permit.amount => {
            debug!("{LOG_PREFIX} Permit2 allowance covers the upto amount; no EIP-2612 permit");
            return Ok(None);
        }
        Ok(_) => {}
        Err(error) => {
            debug!(
                "{LOG_PREFIX} Permit2 allowance unreadable ({error}); signing an EIP-2612 permit"
            );
        }
    }

    let nonce_call = abi::encode_eip2612_nonces(&terms.from)
        .map_err(|e| X402Error::Protocol(format!("encode nonces call: {e}")))?;
    let nonce = read_uint256(transport, network, &terms.token, &nonce_call)
        .await
        .map_err(|error| X402Error::Wallet(format!("read EIP-2612 nonce: {error}")))?;

    let permit = eip712::Eip2612Permit {
        owner: evm_address_bytes(&terms.from)?,
        spender: eip712::PERMIT2,
        value: terms.permit.amount,
        nonce,
        deadline: terms.permit.deadline,
    };
    let domain = eip712::domain_separator(terms.permit.token, terms.chain_id, name, version);
    let digest = eip712::signing_digest(domain, permit.struct_hash());
    let signature = sign_digest(signer, digest, "EIP-2612").await?;

    Ok(Some(json!({
        "from": terms.from,
        "asset": terms.token,
        "spender": PERMIT2_ADDRESS,
        "amount": terms.amount,
        "nonce": eip712::u256_to_decimal(&nonce),
        "deadline": terms.deadline_secs.to_string(),
        "signature": signature,
        "version": EIP2612_INFO_VERSION,
    })))
}

/// `eth_call` a view function on `contract` that returns one `uint256`.
async fn read_uint256(
    transport: &dyn Transport,
    network: NetworkId,
    contract: &str,
    calldata: &str,
) -> Result<U256Bytes, String> {
    let reply = transport
        .json_rpc(
            network,
            "eth_call",
            json!([{ "to": contract, "data": calldata }, "latest"]),
        )
        .await
        .map_err(|error| error.to_string())?;
    let reply = reply
        .as_str()
        .ok_or_else(|| format!("eth_call returned a non-string result: {reply}"))?;
    abi::decode_uint256(reply).map_err(|error| error.to_string())
}

/// Sign an EIP-712 digest behind the seam and return `0x` + `r ‖ s ‖ v`.
async fn sign_digest(
    signer: &dyn PaymentSigner,
    digest: [u8; 32],
    what: &str,
) -> Result<String, X402Error> {
    let signature = signer
        .sign(PaymentChain::Evm, &digest, SignScheme::Secp256k1Digest)
        .await
        .map_err(|e| X402Error::Wallet(format!("sign {what}: {e}")))?;
    Ok(format!("0x{}", hex::encode(eip712_signature(&signature)?)))
}

/// The EIP-55 form of an address, as the reference client's `getAddress`.
fn checksummed(address: &str) -> Result<String, X402Error> {
    tinywallet_crypto::address::evm::to_checksummed(address)
        .map_err(|e| X402Error::Protocol(format!("invalid EVM address '{address}': {e}")))
}

/// The payload's `extensions`: the server's declarations with the client's
/// entries merged over them, objects recursively and anything else replaced,
/// as the reference client's `mergeExtensions` does.
fn merge_extensions(server: &Map<String, Value>, client: Map<String, Value>) -> Map<String, Value> {
    let mut merged = server.clone();
    for (key, value) in client {
        match merged.get_mut(&key) {
            Some(existing) => merge_value(existing, value),
            None => {
                merged.insert(key, value);
            }
        }
    }
    merged
}

fn merge_value(target: &mut Value, source: Value) {
    match (target, source) {
        (Value::Object(target), Value::Object(source)) => {
            for (key, value) in source {
                match target.get_mut(&key) {
                    Some(existing) => merge_value(existing, value),
                    None => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, source) => *target = source,
    }
}

#[cfg(test)]
#[path = "upto_payment_tests.rs"]
mod tests;
