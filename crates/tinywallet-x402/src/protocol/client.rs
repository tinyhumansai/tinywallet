//! The high-level x402 client (intercept 402, pay, retry) and the lower-level
//! `handle_402*` entry points the HTTP tool layer drives directly.

use log::{debug, warn};
use reqwest::header::{HeaderMap, HeaderValue};
use std::sync::Arc;

use super::LOG_PREFIX;
use super::builder::PaymentBuilder;
use super::error::X402Error;
use super::headers::{encode_payment, parse_402_headers, parse_settlement_response};
use crate::ledger::{self, BudgetRefusal, Reservation};
use crate::wire::{
    HEADER_PAYMENT_RESPONSE, HEADER_PAYMENT_SIGNATURE, PaymentChain, PaymentRequired,
    PaymentRequirements,
};

/// High-level x402 client. Wraps a `reqwest::Client` and knows how to intercept
/// 402 responses, have them paid through a [`PaymentBuilder`], and retry
/// transparently.
#[derive(Clone)]
pub struct X402Client {
    http: reqwest::Client,
    builder: Arc<dyn PaymentBuilder>,
}

impl std::fmt::Debug for X402Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Client").finish_non_exhaustive()
    }
}

impl X402Client {
    /// A client that sends through `http` and pays through `builder`.
    #[must_use]
    pub fn new(http: reqwest::Client, builder: Arc<dyn PaymentBuilder>) -> Self {
        Self { http, builder }
    }

    /// Send a request. If the server returns 402 with a `PAYMENT-REQUIRED`
    /// header, pay it and retry.
    ///
    /// `max_amount` is an optional ceiling in atomic units; a challenge above it
    /// is rejected to prevent runaway spending.
    ///
    /// # Errors
    ///
    /// Any [`X402Error`]: a transport failure, an unreadable or unpayable
    /// challenge, an amount above `max_amount`, or a wallet failure.
    pub async fn try_paid_request(
        &self,
        request: reqwest::Request,
        max_amount: Option<u64>,
    ) -> Result<reqwest::Response, X402Error> {
        // The paid retry is a second copy of the request. A streaming body cannot
        // be copied, and the copy is taken before the first send consumes the
        // request, so the answer is known up front.
        let replay = request.try_clone();
        let method = request.method().clone();
        let url = request.url().clone();

        debug!("{LOG_PREFIX} initial request {method} {url}");
        let response = self
            .http
            .execute(request)
            .await
            .map_err(X402Error::Transport)?;

        if response.status() != reqwest::StatusCode::PAYMENT_REQUIRED {
            return Ok(response);
        }

        // Refuse before reading the challenge, let alone signing: paying for a
        // request that cannot be replayed would spend money for nothing.
        let Some(mut retry_req) = replay else {
            warn!("{LOG_PREFIX} 402 for a request with a streaming body; refusing to pay {url}");
            return Err(X402Error::NonReplayableBody);
        };

        let challenge = parse_402_headers(response.headers())?;
        debug!(
            "{LOG_PREFIX} got 402 challenge version={} accepts={}",
            challenge.x402_version,
            challenge.accepts.len()
        );

        let (requirement, chain) = challenge
            .best_exact_requirement()
            .ok_or(X402Error::NoPaymentOption)?;

        let amount = parse_amount(requirement)?;
        if let Some(cap) = max_amount {
            if amount > cap {
                return Err(X402Error::AmountExceedsCap {
                    requested: amount,
                    cap,
                });
            }
        }

        debug!(
            "{LOG_PREFIX} paying {} atomic units of {} to {} chain={:?} (fee_payer={:?})",
            amount,
            requirement.asset,
            requirement.pay_to,
            chain,
            requirement.fee_payer_pubkey(),
        );

        let payment = self.builder.build(&challenge, requirement, chain).await?;
        let encoded = encode_payment(&payment)?;

        let proof = HeaderValue::from_str(&encoded)
            .map_err(|e| X402Error::Protocol(format!("payment proof is not a valid header: {e}")))?;
        retry_req
            .headers_mut()
            .insert(HEADER_PAYMENT_SIGNATURE, proof);

        debug!("{LOG_PREFIX} retrying with payment proof");
        let paid_response = self
            .http
            .execute(retry_req)
            .await
            .map_err(X402Error::Transport)?;

        if let Some(receipt_header) = paid_response.headers().get(HEADER_PAYMENT_RESPONSE) {
            match parse_settlement_response(receipt_header.to_str().unwrap_or("")) {
                Ok(receipt) if receipt.success => debug!(
                    "{LOG_PREFIX} payment settled tx={} network={}",
                    receipt.transaction, receipt.network
                ),
                Ok(receipt) => warn!(
                    "{LOG_PREFIX} payment settlement failed reason={:?}",
                    receipt.error_reason
                ),
                Err(e) => warn!("{LOG_PREFIX} could not parse settlement response: {e}"),
            }
        }

        Ok(paid_response)
    }
}

/// Parse a 402 response's headers and return the challenge with the index of the
/// best payment option and its chain family.
///
/// Solana is preferred (lower fees, faster finality); EVM is the fallback.
///
/// # Errors
///
/// [`X402Error::NoPaymentHeader`] / [`X402Error::Protocol`] from reading the
/// header, and [`X402Error::NoPaymentOption`] when nothing in it is payable.
pub fn handle_402(
    headers: &HeaderMap,
) -> Result<(PaymentRequired, usize, PaymentChain), X402Error> {
    let challenge = parse_402_headers(headers)?;
    let (idx, chain) = challenge
        .accepts
        .iter()
        .enumerate()
        .find(|(_, r)| r.scheme == "exact" && r.network.starts_with("solana:"))
        .map(|(i, _)| (i, PaymentChain::Solana))
        .or_else(|| {
            challenge
                .accepts
                .iter()
                .enumerate()
                .find(|(_, r)| r.scheme == "exact" && r.network.starts_with("eip155:"))
                .map(|(i, _)| (i, PaymentChain::Evm))
        })
        .ok_or(X402Error::NoPaymentOption)?;
    Ok((challenge, idx, chain))
}

/// Build a payment and return the encoded header value ready to attach.
///
/// Separated from [`X402Client::try_paid_request`] so callers that manage their
/// own HTTP layer can still use the payment construction.
///
/// # Errors
///
/// Whatever `builder` reports, or [`X402Error::Protocol`] if the proof cannot be
/// serialised.
pub async fn pay_challenge_header(
    builder: &dyn PaymentBuilder,
    challenge: &PaymentRequired,
    requirement: &PaymentRequirements,
) -> Result<String, X402Error> {
    let chain = if requirement.network.starts_with("eip155:") {
        PaymentChain::Evm
    } else {
        PaymentChain::Solana
    };
    let payment = builder.build(challenge, requirement, chain).await?;
    encode_payment(&payment)
}

/// Result of a successful x402 payment: the header value to attach and the
/// metadata for the ledger.
///
/// Not `Clone`: it owns the [`Reservation`] that keeps the payment's amount
/// counted against the budget.
#[derive(Debug)]
pub struct X402PaymentResult {
    /// The `PAYMENT-SIGNATURE` header value.
    pub header_value: String,
    /// The amount, in atomic units of `asset`.
    pub amount_atomic: u64,
    /// The asset paid in.
    pub asset: String,
    /// Who is being paid.
    pub recipient: String,
    /// The CAIP-2 network the payment is on.
    pub network: String,
    /// The URL the payment is for.
    pub url: String,
    /// The budget held for this payment. Keep it alive until the outcome is
    /// recorded, then [`commit`](Reservation::commit) it with the final record;
    /// dropping it releases the hold without recording anything.
    pub reservation: Reservation,
}

/// End-to-end 402 handler for the HTTP tool layer. Given a 402 response's
/// headers and the original URL:
///
/// 1. parses the `PAYMENT-REQUIRED` challenge,
/// 2. checks the spending budget in the process-wide ledger and reserves the
///    amount in the same critical section, so concurrent payments cannot
///    overspend,
/// 3. has `builder` construct and sign the payment (Solana preferred, EVM
///    fallback), and
/// 4. returns the encoded `PAYMENT-SIGNATURE` header value.
///
/// The caller retries the original request with this header attached and
/// records the payment outcome in the ledger, committing the
/// [`X402PaymentResult::reservation`] with that record. If signing fails the
/// reservation is released before this returns.
///
/// # Errors
///
/// Any [`X402Error`], including [`X402Error::AmountExceedsCap`] and
/// [`X402Error::BudgetExceeded`] when the ledger refuses the amount, and
/// [`X402Error::Wallet`] when the ledger has not been initialised.
pub async fn handle_402_and_pay(
    builder: &dyn PaymentBuilder,
    response_headers: &HeaderMap,
    request_url: &str,
) -> Result<X402PaymentResult, X402Error> {
    let (challenge, idx, chain) = handle_402(response_headers)?;
    let requirement = &challenge.accepts[idx];
    let amount = parse_amount(requirement)?;

    // Check the budget and hold the amount in one critical section, before
    // anything is signed: a check on its own would let concurrent payments that
    // each fit overspend together.
    let reservation = match ledger::reserve(amount).map_err(X402Error::Wallet)? {
        Ok(reservation) => reservation,
        Err(BudgetRefusal::PerRequest { requested, cap }) => {
            return Err(X402Error::AmountExceedsCap { requested, cap });
        }
        Err(BudgetRefusal::Daily { current, cap }) => {
            return Err(X402Error::BudgetExceeded {
                period: "daily",
                current,
                cap,
            });
        }
        Err(BudgetRefusal::Monthly { current, cap }) => {
            return Err(X402Error::BudgetExceeded {
                period: "monthly",
                current,
                cap,
            });
        }
    };

    debug!(
        "{LOG_PREFIX} paying {} atomic {} to {} for {} chain={:?}",
        amount, requirement.asset, requirement.pay_to, request_url, chain
    );

    let payment = builder.build(&challenge, requirement, chain).await?;
    let header_value = encode_payment(&payment)?;

    Ok(X402PaymentResult {
        header_value,
        amount_atomic: amount,
        asset: requirement.asset.clone(),
        recipient: requirement.pay_to.clone(),
        network: requirement.network.clone(),
        url: request_url.to_string(),
        reservation,
    })
}

fn parse_amount(requirement: &PaymentRequirements) -> Result<u64, X402Error> {
    requirement
        .amount
        .parse()
        .map_err(|e| X402Error::Protocol(format!("invalid amount '{}': {e}", requirement.amount)))
}
