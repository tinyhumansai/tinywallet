//! `TinyBus` bridge for the module-owned x402 payment and ledger algorithms.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use chrono::Utc;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use tinywallet_bus::wire::{
    AuthorizeX402PaymentRequest, SecretMaterial, X402ConfigResponse, X402DetailedSpendingSummary,
    X402ListPaymentsRequest, X402ListPaymentsResponse, X402PaymentRecord, X402PaymentStatus,
    X402PreparePaymentRequest, X402PreparePaymentResponse, X402RecordPaymentRequest,
    X402ServiceHandle, X402SpendingSummary, X402SummaryRequest, X402UpdateBudgetRequest,
};
use tinywallet_x402::crypto::{CryptoPayments, PaymentAccount, PaymentSigner, SignScheme};
use tinywallet_x402::ledger::{self, PaymentRecord, PaymentStatus, SpendingBudget};
use tinywallet_x402::protocol::{
    handle_402_and_pay_authorized, parse_settlement_response, settles,
};
use tinywallet_x402::wire::PaymentChain;

use super::host::HostCallbacks;
use super::web3::{HostTransport, with_x402_execution_context};

const MAX_PENDING: usize = 64;

/// Stateful module-owned x402 ledger and outstanding payment reservations.
pub(crate) struct X402Runtime {
    callbacks: HostCallbacks,
    preparing: Mutex<usize>,
    #[cfg(test)]
    commit_handoff: Option<(
        Arc<std::sync::atomic::AtomicBool>,
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Notify>,
    )>,
    config: X402ConfigResponse,
    handle: X402ServiceHandle,
    /// Extends the lease on this runtime's budget holds while it lives.
    lease: Option<tokio::task::JoinHandle<()>>,
}

struct PendingAdmission<'a> {
    preparing: &'a Mutex<usize>,
}

impl PendingAdmission<'_> {
    fn ensure_capacity(&self) -> Result<(), String> {
        let preparing = self
            .preparing
            .lock()
            .map_err(|_| "x402 pending-payment admission is unavailable".to_string())?;
        let pending = ledger::with_ledger(|ledger| ledger.usable_pending_count(Utc::now()))?;
        if pending.saturating_add(*preparing) > MAX_PENDING {
            return Err("x402 pending-payment capacity reached".to_string());
        }
        Ok(())
    }
}

impl Drop for PendingAdmission<'_> {
    fn drop(&mut self) {
        if let Ok(mut preparing) = self.preparing.lock() {
            *preparing = preparing.saturating_sub(1);
        }
    }
}

impl Drop for X402Runtime {
    fn drop(&mut self) {
        self.stop_lease();
    }
}

/// Renew the process-wide ledger's budget holds every
/// [`ledger::HOLD_RENEW_EVERY`], so a payment still in flight when the hold
/// TTL passes keeps its budget charged. `None` outside a tokio runtime.
fn spawn_lease_renewal() -> Option<tokio::task::JoinHandle<()>> {
    let runtime = tokio::runtime::Handle::try_current().ok()?;
    Some(runtime.spawn(async {
        let mut tick = tokio::time::interval(ledger::HOLD_RENEW_EVERY);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate; nothing is held yet.
        tick.tick().await;
        loop {
            tick.tick().await;
            renew_holds_once().await;
        }
    }))
}

/// One lease renewal, off the async workers because the ledger's storage calls
/// block.
async fn renew_holds_once() {
    let outcome =
        tokio::task::spawn_blocking(|| ledger::with_ledger_mut(ledger::PaymentLedger::renew_holds))
            .await;
    match outcome {
        Ok(Ok(Ok(renewed))) => log::debug!("[x402::lease] renewed {renewed} holds"),
        Ok(Ok(Err(error)) | Err(error)) => log::warn!("[x402::lease] renewal failed: {error}"),
        Err(error) => log::warn!("[x402::lease] renewal task failed: {error}"),
    }
}

impl std::fmt::Debug for X402Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X402Runtime")
            .field(
                "preparing",
                &self.preparing.lock().map(|preparing| *preparing).ok(),
            )
            .finish_non_exhaustive()
    }
}

impl X402Runtime {
    /// Initialize the module's ledger over `storage` and the spending policy.
    /// This is called only by the explicit host lifecycle operation, never
    /// during artifact setup.
    ///
    /// # Errors
    ///
    /// The storage cannot be opened or read, or the ledger's own migration
    /// cannot complete. The previous process-wide ledger, if any, is left in
    /// place. The host must ensure the wallet collections in this module's
    /// scope before calling this operation.
    pub(crate) fn new(
        callbacks: HostCallbacks,
        config: X402ConfigResponse,
        storage: ledger::LedgerStorage,
    ) -> Result<Self, String> {
        let budget = SpendingBudget {
            per_request_max_atomic: config.per_request_max_atomic,
            daily_max_atomic: config.daily_max_atomic,
            monthly_max_atomic: config.monthly_max_atomic,
        };
        ledger::init_global(storage, &config.session_id, budget)?;
        let lease = spawn_lease_renewal();
        Ok(Self {
            lease,
            callbacks,
            preparing: Mutex::new(0),
            #[cfg(test)]
            commit_handoff: None,
            config,
            handle: X402ServiceHandle {
                handle: uuid::Uuid::new_v4().to_string(),
            },
        })
    }

    fn stop_lease(&mut self) {
        if let Some(lease) = self.lease.take() {
            lease.abort();
        }
    }

    pub(crate) fn handle(&self) -> X402ServiceHandle {
        self.handle.clone()
    }

    fn require_handle(&self, handle: &X402ServiceHandle) -> Result<(), String> {
        if handle != &self.handle {
            return Err("x402 service handle is unavailable".to_string());
        }
        Ok(())
    }

    pub(crate) fn close(&mut self, handle: &X402ServiceHandle) -> Result<(), String> {
        self.require_handle(handle)?;
        self.stop_lease();
        ledger::clear_global();
        Ok(())
    }

    /// Parse a challenge, reserve its budget, and build the proof inside the
    /// wallet module. The host receives only the retry header and a pending id.
    pub(crate) async fn prepare(
        &self,
        mut request: X402PreparePaymentRequest,
    ) -> Result<X402PreparePaymentResponse, String> {
        if let Err(error) = self.require_handle(&request.service) {
            wipe_request_secrets(&mut request);
            return Err(error);
        }
        let mut secrets = take_request_secrets(&mut request)?;
        let header = HeaderValue::from_str(&request.payment_required)
            .map_err(|error| format!("invalid payment challenge header: {error}"));
        let header = match header {
            Ok(header) => header,
            Err(error) => {
                wipe_secrets(&mut secrets);
                return Err(error);
            }
        };
        let mut headers = HeaderMap::new();
        let header_name = HeaderName::from_static("payment-required");
        headers.insert(header_name, header);
        let thread_id = request.owner.as_ref().map(|owner| owner.thread_id.clone());
        let owner = request.owner.clone();
        let url = request.url.clone();
        let callbacks = self.callbacks.clone();
        let (proof, _admission) = with_x402_execution_context(request.owner, secrets, async {
            let signer: Arc<dyn PaymentSigner> = Arc::new(ModulePaymentSigner);
            let transport = Arc::new(HostTransport::new(self.callbacks.clone()));
            let builder = CryptoPayments::new(signer, transport);
            // Bound concurrent chain refreshes before the first network await.
            // Capacity is checked again after refresh so finalized expiry
            // evidence can free slots before new authorizations are admitted.
            let admission = self.begin_pending()?;
            tinywallet_x402::protocol::refresh_solana_authorizations(&builder)
                .await
                .map_err(|error| error.to_string())?;
            admission.ensure_capacity()?;
            let proof = handle_402_and_pay_authorized(
                &builder,
                &headers,
                &url,
                move |url, requirement, _chain, amount_atomic| async move {
                    let authorization = callbacks
                        .authorize_x402_payment(AuthorizeX402PaymentRequest {
                            url,
                            network: requirement.network,
                            asset: requirement.asset,
                            recipient: requirement.pay_to,
                            amount_atomic,
                            owner: owner.clone(),
                        })
                        .await?;
                    if authorization.approved {
                        Ok(())
                    } else {
                        Err(authorization
                            .reason
                            .unwrap_or_else(|| "x402 payment was not approved".to_string()))
                    }
                },
            )
            .await
            .map_err(|error| error.to_string())?;
            Ok::<_, String>((proof, admission))
        })
        .await?;
        #[cfg(test)]
        if let Some((pause_once, reached, release)) = &self.commit_handoff
            && pause_once.swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            reached.notify_one();
            release.notified().await;
        }
        let payment_id = format!("x402_{}", uuid::Uuid::new_v4());
        let response = X402PreparePaymentResponse {
            payment_id: payment_id.clone(),
            payment_header: proof.header_value.clone(),
            amount_atomic: proof.amount_atomic,
            asset: proof.asset.clone(),
            recipient: proof.recipient.clone(),
            network: proof.network.clone(),
        };
        let record = PaymentRecord {
            id: payment_id,
            url: proof.url.clone(),
            asset: proof.asset.clone(),
            amount_atomic: proof.amount_atomic,
            amount_display: tinywallet_x402::ledger::format_usdc(proof.amount_atomic),
            recipient: proof.recipient.clone(),
            network: proof.network.clone(),
            tx_signature: None,
            status: PaymentStatus::Pending,
            timestamp: Utc::now(),
            authorization_valid_until: proof.authorization_valid_until,
            solana_last_valid_block_height: proof.solana_last_valid_block_height,
            authorization_expired_at: None,
            authorization_expiry_observed_height: None,
            session_id: self.config.session_id.clone(),
            thread_id,
        };
        proof
            .reservation
            .commit_durable(record)
            .map_err(|_| "x402 payment budget could not be durably recorded".to_string())?;
        Ok(response)
    }

    #[cfg(test)]
    fn admit_pending(&self) -> Result<PendingAdmission<'_>, String> {
        let admission = self.begin_pending()?;
        admission.ensure_capacity()?;
        Ok(admission)
    }

    fn begin_pending(&self) -> Result<PendingAdmission<'_>, String> {
        let mut preparing = self
            .preparing
            .lock()
            .map_err(|_| "x402 pending-payment admission is unavailable".to_string())?;
        if *preparing >= MAX_PENDING {
            return Err("x402 pending-payment capacity reached".to_string());
        }
        *preparing += 1;
        Ok(PendingAdmission {
            preparing: &self.preparing,
        })
    }

    /// Commit the reserved amount to the module-owned ledger after the host
    /// retries the paid request.
    pub(crate) fn record(&self, request: X402RecordPaymentRequest) -> Result<(), String> {
        self.require_handle(&request.service)?;
        let pending = ledger::with_ledger(|ledger| ledger.payment(&request.payment_id).cloned())?
            .ok_or_else(|| "x402 payment handle was missing".to_string())?;
        if pending.status == PaymentStatus::Settled {
            // A reply may be lost after the durable transition; replaying the
            // same receipt is an idempotent acknowledgment.
            return Ok(());
        }
        let legacy_expired =
            pending.status == PaymentStatus::Failed && pending.authorization_valid_until.is_some();
        if pending.status != PaymentStatus::Pending && !legacy_expired {
            return Err("x402 payment handle was missing or expired".to_string());
        }
        let receipt = request
            .settlement_response
            .as_deref()
            .and_then(|value| parse_settlement_response(value).ok())
            .filter(|receipt| settles(receipt, &pending.network, pending.amount_atomic));
        let status = if receipt.is_some() {
            PaymentStatus::Settled
        } else {
            // Neither a failed HTTP response nor an elapsed authorization
            // deadline proves that a previously returned proof did not settle.
            PaymentStatus::Pending
        };
        let tx_signature = receipt
            .filter(|receipt| !receipt.transaction.is_empty())
            .map(|receipt| receipt.transaction);
        if status == pending.status {
            return Ok(());
        }
        let record = PaymentRecord {
            id: request.payment_id,
            url: pending.url,
            asset: pending.asset,
            amount_atomic: pending.amount_atomic,
            amount_display: pending.amount_display,
            recipient: pending.recipient,
            network: pending.network,
            tx_signature,
            status,
            timestamp: chrono::Utc::now(),
            authorization_valid_until: pending.authorization_valid_until,
            solana_last_valid_block_height: pending.solana_last_valid_block_height,
            authorization_expired_at: pending.authorization_expired_at,
            authorization_expiry_observed_height: pending.authorization_expiry_observed_height,
            session_id: pending.session_id,
            thread_id: pending.thread_id,
        };
        ledger::with_ledger_mut(|ledger| ledger.try_record_payment(record))??;
        Ok(())
    }

    /// Read the module-owned budget totals and currently held reservations.
    pub(crate) fn summary(
        &self,
        service: &X402ServiceHandle,
    ) -> Result<X402SpendingSummary, String> {
        self.require_handle(service)?;
        ledger::with_ledger(|ledger| {
            let summary = ledger.summary();
            let budget = ledger.budget();
            X402SpendingSummary {
                session_total_atomic: summary.session_total_atomic,
                daily_total_atomic: summary.daily_total_atomic,
                monthly_total_atomic: summary.monthly_total_atomic,
                reserved_atomic: ledger.outstanding_atomic(),
                per_request_max_atomic: budget.per_request_max_atomic,
                daily_max_atomic: budget.daily_max_atomic,
                monthly_max_atomic: budget.monthly_max_atomic,
            }
        })
    }

    /// Return recent ledger records in the stable host-facing wire vocabulary.
    pub(crate) fn list_payments(
        &self,
        request: &X402ListPaymentsRequest,
    ) -> Result<X402ListPaymentsResponse, String> {
        self.require_handle(&request.service)?;
        let limit = request.limit.min(500) as usize;
        ledger::with_ledger(|ledger| X402ListPaymentsResponse {
            payments: ledger
                .recent_payments(limit)
                .into_iter()
                .map(payment_record_to_wire)
                .collect(),
        })
    }

    /// Change the live limits without replacing the ledger or releasing holds.
    pub(crate) fn update_budget(
        &self,
        request: &X402UpdateBudgetRequest,
    ) -> Result<X402SpendingSummary, String> {
        self.require_handle(&request.service)?;
        ledger::with_ledger_mut(|ledger| {
            let mut budget = ledger.budget().clone();
            if let Some(value) = request.per_request_max_atomic {
                budget.per_request_max_atomic = value;
            }
            if let Some(value) = request.daily_max_atomic {
                budget.daily_max_atomic = value;
            }
            if let Some(value) = request.monthly_max_atomic {
                budget.monthly_max_atomic = value;
            }
            ledger.update_budget(budget);
        })?;
        self.summary(&request.service)
    }

    /// Include payment counts while retaining the older summary operation's
    /// wire representation for hosts that still use it.
    pub(crate) fn detailed_summary(
        &self,
        request: &X402SummaryRequest,
    ) -> Result<X402DetailedSpendingSummary, String> {
        self.require_handle(&request.service)?;
        ledger::with_ledger(|ledger| {
            let summary = ledger.summary();
            let budget = ledger.budget();
            X402DetailedSpendingSummary {
                session_total_atomic: summary.session_total_atomic,
                daily_total_atomic: summary.daily_total_atomic,
                monthly_total_atomic: summary.monthly_total_atomic,
                session_count: summary.session_count.try_into().unwrap_or(u64::MAX),
                daily_count: summary.daily_count.try_into().unwrap_or(u64::MAX),
                monthly_count: summary.monthly_count.try_into().unwrap_or(u64::MAX),
                reserved_atomic: ledger.outstanding_atomic(),
                per_request_max_atomic: budget.per_request_max_atomic,
                daily_max_atomic: budget.daily_max_atomic,
                monthly_max_atomic: budget.monthly_max_atomic,
            }
        })
    }
}

fn payment_record_to_wire(record: PaymentRecord) -> X402PaymentRecord {
    let timestamp = |value: chrono::DateTime<chrono::Utc>| {
        value.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
    };
    let status = match record.status {
        PaymentStatus::Pending => X402PaymentStatus::Pending,
        PaymentStatus::Settled => X402PaymentStatus::Settled,
        PaymentStatus::Failed => X402PaymentStatus::Failed,
        PaymentStatus::Denied => X402PaymentStatus::Denied,
    };
    X402PaymentRecord {
        id: record.id,
        url: record.url,
        asset: record.asset,
        amount_atomic: record.amount_atomic,
        amount_display: record.amount_display,
        recipient: record.recipient,
        network: record.network,
        tx_signature: record.tx_signature,
        status,
        timestamp: timestamp(record.timestamp),
        authorization_valid_until: record.authorization_valid_until.map(timestamp),
        solana_last_valid_block_height: record.solana_last_valid_block_height,
        authorization_expired_at: record.authorization_expired_at.map(timestamp),
        authorization_expiry_observed_height: record.authorization_expiry_observed_height,
        session_id: record.session_id,
        thread_id: record.thread_id,
    }
}

struct ModulePaymentSigner;

#[async_trait]
impl PaymentSigner for ModulePaymentSigner {
    async fn account(&self, chain: PaymentChain) -> Result<PaymentAccount, String> {
        let expected_chain = match chain {
            PaymentChain::Evm => tinywallet_bus::Chain::Evm,
            PaymentChain::Solana => tinywallet_bus::Chain::Solana,
        };
        let mut secret = super::web3::clone_x402_secret(expected_chain)?;
        let derived = super::derive_account(&secret).map_err(super::failure_message);
        wipe(&mut secret);
        let derived = derived?;
        let pubkey = if chain == PaymentChain::Solana {
            Some(
                hex::decode(&derived.public_key.key_hex)
                    .map_err(|error| format!("invalid derived Solana public key: {error}"))?
                    .try_into()
                    .map_err(|_| "derived Solana public key was not 32 bytes".to_string())?,
            )
        } else {
            None
        };
        Ok(PaymentAccount {
            address: derived.address,
            pubkey,
        })
    }

    async fn sign(
        &self,
        chain: PaymentChain,
        message: &[u8],
        scheme: SignScheme,
    ) -> Result<Vec<u8>, String> {
        let (expected_chain, scheme) = match (chain, scheme) {
            (PaymentChain::Evm, SignScheme::Secp256k1Digest) => (
                tinywallet_bus::Chain::Evm,
                tinywallet_bus::wire::Scheme::Secp256k1Prehash,
            ),
            (PaymentChain::Solana, SignScheme::Ed25519) => (
                tinywallet_bus::Chain::Solana,
                tinywallet_bus::wire::Scheme::Ed25519,
            ),
            _ => {
                return Err("x402 payment requested an unsupported signing scheme".to_string());
            }
        };
        let secret = super::web3::clone_x402_secret(expected_chain)?;
        let mut request = tinywallet_bus::wire::SignMessageRequest {
            secret,
            message_hex: hex::encode(message),
            scheme,
        };
        let signature = super::sign_message(&request).map_err(super::failure_message);
        wipe(&mut request.secret);
        match signature? {
            tinywallet_bus::wire::Signature::Secp256k1 {
                rs_hex,
                recovery_id,
            } => {
                let mut signature = hex::decode(rs_hex)
                    .map_err(|error| format!("invalid module secp256k1 signature: {error}"))?;
                signature.push(recovery_id);
                Ok(signature)
            }
            tinywallet_bus::wire::Signature::Ed25519 { signature_hex } => {
                hex::decode(signature_hex)
                    .map_err(|error| format!("invalid module Ed25519 signature: {error}"))
            }
            _ => Err("module returned an unsupported signature variant".to_string()),
        }
    }
}

fn wipe(secret: &mut SecretMaterial) {
    zeroize::Zeroize::zeroize(&mut secret.mnemonic);
    zeroize::Zeroize::zeroize(&mut secret.derivation_path);
}

fn wipe_secrets(secrets: &mut [SecretMaterial]) {
    for secret in secrets {
        wipe(secret);
    }
}

fn wipe_request_secrets(request: &mut X402PreparePaymentRequest) {
    wipe(&mut request.secret);
    wipe_secrets(&mut request.additional_secrets);
}

fn take_request_secrets(
    request: &mut X402PreparePaymentRequest,
) -> Result<Vec<SecretMaterial>, String> {
    let mut secrets = vec![std::mem::replace(
        &mut request.secret,
        SecretMaterial {
            mnemonic: String::new(),
            derivation_path: String::new(),
            chain: tinywallet_bus::Chain::Evm,
        },
    )];
    secrets.append(&mut request.additional_secrets);
    if secrets.iter().enumerate().any(|(index, secret)| {
        secrets[..index]
            .iter()
            .any(|prior| prior.chain == secret.chain)
    }) {
        wipe_secrets(&mut secrets);
        return Err("x402 request contains duplicate secrets for one chain".to_string());
    }
    Ok(secrets)
}

#[cfg(test)]
static LEDGER_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
#[allow(clippy::expect_used)]
fn memory_ledger_storage() -> ledger::LedgerStorage {
    let scope = tinystoragedrivers_types::Scope::new("tinywallet.module-test")
        .expect("the test scope is valid");
    ledger::LedgerStorage::from_storage(&tinystoragedrivers_testkit::memory_storage(&scope))
}

#[cfg(test)]
#[path = "x402_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "x402_lifecycle_tests.rs"]
mod lifecycle_tests;

#[cfg(test)]
#[path = "x402_storage_bus_tests.rs"]
mod storage_bus_tests;

#[cfg(test)]
#[path = "x402_record_tests.rs"]
mod record_tests;
