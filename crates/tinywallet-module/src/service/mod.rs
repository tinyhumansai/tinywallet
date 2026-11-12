//! `TinyBus` service boundary for the wallet surface.
//!
//! One object, `/ai/tinyhumans/tinywallet/Wallet`, serves the established
//! stateless build/sign API and the module-owned Web3/x402 services. Legacy
//! `BuildUnsigned` and `AttachSignature` keep key custody in a host that signs
//! outside the module. Confidential `DeriveAccount`, `SignTransaction`,
//! `ExportKey`, and `SignMessage` keep their existing wire forms and arities.
//!
//! The added Web3 flow stores bounded, expiring quotes inside this module,
//! obtains account facts, authenticated service responses, endpoint transport,
//! and explicit approval through typed Host callbacks, then constructs and
//! signs in the module. EVM approval happens at the signer seam with nonce,
//! gas, chain, and transaction fields from the exact transaction being signed.
//! Solana approval receives the complete unsigned transaction bytes.
//!
//! The x402 flow parses and validates a challenge, reserves the module-owned
//! spending budget before host approval, signs only after approval, and retains
//! the reservation under a bounded pending handle until the host reports the
//! paid retry result. Budget policy and workspace location come from the host;
//! quote/payment algorithms, reservation state, signing, and ledger storage
//! remain in this module and its implementation crates.
//!
//! Secret material enters only on confidential calls to an attested artifact.
//! This is bus admission control, not process isolation: a loaded module shares
//! the host's address space. A backend whose compromise must not reach a key
//! belongs in a separate process and cannot use the confidential path.
//!
//! # Everything travels inline
//!
//! This is the significant difference from the `tinydocs` module, and it is
//! what makes this one small. A `TinyBus` frame is JSON capped at 16 MiB, where
//! a byte array costs about 3.5 bytes per byte — a real constraint for a
//! generated `.docx`, and irrelevant here. The largest thing that crosses is a
//! Bitcoin spend's UTXO list; a wallet with a thousand of them is still tens of
//! kilobytes. So there are no streams, no chunking, and no held outputs.
//!
//! # Errors are named, and the names are the contract
//!
//! A host maps them onto what a user or a model can act on: a rejected input it
//! can fix, against a failure it cannot. Anything unrecognised must be treated
//! as the second — telling a model its input was wrong when it was not sends it
//! into a rewrite loop over something that was already correct.

use tinybus::{Connection, Error as BusError, Result as BusResult};
use tinywallet::wire::{
    AttachRequest, DerivedAccount, ExportRequest, ExportedKey, PublicKey, Scheme, SecretMaterial,
    SignMessageRequest, SignRequest, Signature, SignedTransaction, SigningPayload, SigningRequest,
    TransactionSpec, UnsignedTransaction,
};
use tinywallet::{Chain, key, tx};

mod host;
mod native_wallet;
mod web3;
mod x402;

/// Well-known name and object path exported by the `TinyWallet` module.
///
/// Re-exported from the contract crate rather than declared here: a host reads
/// them from `tinywallet-bus`, and two independent spellings of the same string
/// fail as a `NameHasNoOwner` at call time rather than as a compile error.
pub use tinywallet_bus::{BUS_NAME, OBJECT_PATH};
pub use tinywallet_bus::{HOST_INTERFACE, HOST_OBJECT_PATH};

/// The request was malformed or internally inconsistent. A caller can fix it.
const INVALID_INPUT_ERROR: &str = "ai.tinyhumans.tinywallet.Error.InvalidInput";
/// Building or assembling the transaction failed. A caller cannot fix it.
const BUILD_FAILED_ERROR: &str = "ai.tinyhumans.tinywallet.Error.BuildFailed";
// There is no `UnsupportedChain` error name. Every chain this build can name
// is compiled in, and a chain it cannot name arrives as a `TransactionSpec`
// variant it does not recognise — which is `InvalidInput`, because the request
// is one this module cannot act on rather than a capability that is missing.

/// The served object. User-scoped services are explicitly opened and closed;
/// lifecycle writes wait for active operations to finish before replacing them.
#[derive(Default)]
struct Wallet {
    callbacks: Option<host::HostCallbacks>,
    web3: tokio::sync::RwLock<Option<web3::Web3Runtime>>,
    native: tokio::sync::RwLock<Option<native_wallet::NativeWalletRuntime>>,
    x402: tokio::sync::RwLock<Option<x402::X402Runtime>>,
}

mod construction;

// The interface macro rejects a non-async method, so both methods are async
// because the dispatch contract says so, not because they await anything. This
// module performs no I/O at all.
#[allow(
    clippy::unused_async,
    reason = "tinybus::interface requires every method to be `async fn`"
)]
#[tinybus::interface(name = "ai.tinyhumans.tinywallet.Wallet")]
#[expect(
    clippy::unused_async_trait_impl,
    reason = "the generated TinyBus async trait requires async methods for synchronous cryptographic operations"
)]
impl Wallet {
    /// Encode standard ERC-20 transfer calldata inside the module.
    async fn encode_erc20_transfer(
        &self,
        request: tinywallet_bus::wire::EncodeErc20TransferRequest,
    ) -> BusResult<tinywallet_bus::wire::EncodeErc20TransferResponse> {
        let calldata =
            tinywallet_x402::abi::encode_erc20_transfer(&request.to_address, &request.amount_raw)
                .map_err(|error| invalid_input(error.to_string()))?;
        Ok(tinywallet_bus::wire::EncodeErc20TransferResponse { calldata })
    }

    /// List swap and bridge routes through the host's authenticated backend
    /// transport. Route parsing and all follow-on quote behavior stay here.
    async fn web3_routes(&self, _request: ()) -> BusResult<serde_json::Value> {
        let web3 = self.web3.read().await;
        let Some(web3) = web3.as_ref() else {
            return Err(host_unavailable());
        };
        web3.service
            .routes()
            .await
            .map_err(host_call_failed)
            .and_then(|value| {
                serde_json::to_value(value).map_err(|error| host_build_failed(error.to_string()))
            })
    }

    /// Prepare a module-owned single-chain swap quote.
    async fn web3_swap_quote(
        &self,
        request: tinywallet_bus::wire::Web3QuoteRequest,
    ) -> BusResult<tinywallet_bus::wire::Web3QuoteResponse> {
        let web3 = self.web3.read().await;
        let Some(web3) = web3.as_ref() else {
            return Err(host_unavailable());
        };
        web3.require_handle(&request.service)
            .map_err(web3_operation_failed)?;
        web3::with_quote_owner(request.owner, async {
            let params =
                serde_json::from_value::<tinywallet_web3::crypto::service::SwapQuoteParams>(
                    request.params,
                )
                .map_err(|error| invalid_input(error.to_string()))?;
            web3.service
                .quote_swap(params)
                .await
                .map_err(web3_operation_failed)
        })
        .await
        .map(web3::quote_response)
    }

    /// Prepare a module-owned cross-chain bridge quote.
    async fn web3_bridge_quote(
        &self,
        request: tinywallet_bus::wire::Web3QuoteRequest,
    ) -> BusResult<tinywallet_bus::wire::Web3QuoteResponse> {
        let web3 = self.web3.read().await;
        let Some(web3) = web3.as_ref() else {
            return Err(host_unavailable());
        };
        web3.require_handle(&request.service)
            .map_err(web3_operation_failed)?;
        web3::with_quote_owner(request.owner, async {
            let params = serde_json::from_value::<
                tinywallet_web3::crypto::service::BridgeQuoteParams,
            >(request.params)
            .map_err(|error| invalid_input(error.to_string()))?;
            web3.service
                .quote_bridge(params)
                .await
                .map_err(web3_operation_failed)
        })
        .await
        .map(web3::quote_response)
    }

    /// Prepare a module-owned EVM dapp-call quote.
    async fn web3_dapp_quote(
        &self,
        request: tinywallet_bus::wire::Web3QuoteRequest,
    ) -> BusResult<tinywallet_bus::wire::Web3QuoteResponse> {
        let web3 = self.web3.read().await;
        let Some(web3) = web3.as_ref() else {
            return Err(host_unavailable());
        };
        web3.require_handle(&request.service)
            .map_err(web3_operation_failed)?;
        web3::with_quote_owner(request.owner, async {
            let params =
                serde_json::from_value::<tinywallet_web3::crypto::service::DappCallParams>(
                    request.params,
                )
                .map_err(|error| invalid_input(error.to_string()))?;
            web3.service
                .prepare_dapp_call(params)
                .await
                .map_err(web3_operation_failed)
        })
        .await
        .map(web3::quote_response)
    }

    /// Approve, sign and broadcast one previously prepared Web3 quote.
    ///
    /// The secret arrives only on this confidential member and is consumed by
    /// the module's signer; the host approves transaction facts but never
    /// builds or signs the transaction.
    #[tinybus(confidential)]
    async fn web3_execute(
        &self,
        mut request: tinywallet_bus::wire::Web3ExecuteRequest,
    ) -> BusResult<tinywallet_web3::crypto::service::Web3ExecutionResult> {
        let web3 = self.web3.read().await;
        let Some(web3) = web3.as_ref() else {
            wipe(&mut request.secret);
            return Err(host_unavailable());
        };
        if let Err(error) = web3.require_handle(&request.service) {
            wipe(&mut request.secret);
            return Err(web3_operation_failed(error));
        }
        if !request.confirmed {
            wipe(&mut request.secret);
            return Err(invalid_input(
                "web3 execution requires confirmed: true".to_string(),
            ));
        }
        let approval = match web3.execution_approval(&request.quote_id, request.owner.as_ref()) {
            Ok(approval) => approval,
            Err(error) => {
                wipe(&mut request.secret);
                return Err(web3_operation_failed(error));
            }
        };
        if let Some(intent @ tinywallet_bus::wire::Web3ExecutionIntent::Solana { .. }) =
            &approval.solana_intent
        {
            let decision = match web3
                .callbacks
                .authorize_web3_execution(tinywallet_bus::wire::AuthorizeWeb3ExecutionRequest {
                    quote_id: approval.quote_id.clone(),
                    operation: approval.operation.clone(),
                    transaction: intent.clone(),
                })
                .await
            {
                Ok(decision) => decision,
                Err(error) => {
                    wipe(&mut request.secret);
                    return Err(host_call_failed(error));
                }
            };
            if !decision.approved {
                wipe(&mut request.secret);
                return Err(BusError::MethodFailed {
                    name: "ai.tinyhumans.tinywallet.Error.AuthorizationDenied".to_string(),
                    message: decision
                        .reason
                        .unwrap_or_else(|| "wallet transaction was not approved".to_string()),
                });
            }
        }
        let secret = std::mem::replace(
            &mut request.secret,
            SecretMaterial {
                mnemonic: String::new(),
                derivation_path: String::new(),
                chain: Chain::Evm,
            },
        );
        let quote_id = request.quote_id;
        let result = web3::with_execution_context(request.owner, secret, Some(approval), async {
            web3.service
                .execute_quote(tinywallet_web3::crypto::service::ExecuteQuoteParams {
                    quote_id,
                    confirmed: request.confirmed,
                })
                .await
                .map_err(web3_operation_failed)
        })
        .await;
        wipe(&mut request.secret);
        result
    }

    /// Parse a 402 challenge, reserve its budget, and build the payment proof.
    /// The module durably records the pending authorization before returning;
    /// the host retries HTTP and supplies a trusted receipt for settlement.
    #[tinybus(confidential)]
    async fn x402_prepare_payment(
        &self,
        request: tinywallet_bus::wire::X402PreparePaymentRequest,
    ) -> BusResult<tinywallet_bus::wire::X402PreparePaymentResponse> {
        let x402 = self.x402.read().await;
        let Some(x402) = x402.as_ref() else {
            let mut request = request;
            wipe(&mut request.secret);
            for secret in &mut request.additional_secrets {
                wipe(secret);
            }
            return Err(host_unavailable());
        };
        x402.prepare(request).await.map_err(x402_operation_failed)
    }

    /// Sign an x402 `sign-in-with-x` challenge with the EVM secret. Only a
    /// sign-in for the requested host is signed; anything else is refused
    /// before the key is used.
    #[tinybus(confidential)]
    async fn x402_sign_in(
        &self,
        request: tinywallet_bus::wire::X402SignInRequest,
    ) -> BusResult<tinywallet_bus::wire::X402SignInResponse> {
        x402::sign_in(request).await.map_err(x402_operation_failed)
    }

    /// Open or replace the active Web3 quote service after the host establishes
    /// the account context. Replacing it waits for in-flight executions and
    /// discards every quote tied to the previous credentials.
    async fn web3_configure(
        &self,
        _request: (),
    ) -> BusResult<tinywallet_bus::wire::Web3ServiceHandle> {
        let callbacks = self.callbacks.clone().ok_or_else(host_unavailable)?;
        let mut web3 = self.web3.write().await;
        let next = web3::Web3Runtime::new(callbacks);
        let handle = next.handle();
        *web3 = Some(next);
        Ok(handle)
    }

    /// Open Web3 with the host's cluster and opaque override endpoint references.
    async fn web3_configure_with_endpoints(
        &self,
        request: tinywallet_bus::wire::Web3ConfigureRequest,
    ) -> BusResult<tinywallet_bus::wire::Web3ConfigureResponse> {
        let callbacks = self.callbacks.clone().ok_or_else(host_unavailable)?;
        let (next, endpoint_references) =
            web3::Web3Runtime::configured(callbacks, request).map_err(web3_operation_failed)?;
        let service = next.handle();
        let mut web3 = self.web3.write().await;
        *web3 = Some(next);
        Ok(tinywallet_bus::wire::Web3ConfigureResponse {
            service,
            endpoint_references,
        })
    }

    /// Close the active Web3 service and discard all quotes for its account.
    async fn web3_close(&self, request: tinywallet_bus::wire::Web3CloseRequest) -> BusResult<()> {
        let mut web3 = self.web3.write().await;
        let Some(current) = web3.as_ref() else {
            return Err(host_unavailable());
        };
        current
            .require_handle(&request.service)
            .map_err(web3_operation_failed)?;
        *web3 = None;
        Ok(())
    }

    /// Open or replace a native wallet engine with host-selected cluster and
    /// endpoint override keys. URLs and credentials stay in the host.
    async fn native_wallet_configure(
        &self,
        request: tinywallet_bus::wire::NativeWalletConfigRequest,
    ) -> BusResult<tinywallet_bus::wire::NativeWalletConfigResponse> {
        let callbacks = self.callbacks.clone().ok_or_else(host_unavailable)?;
        let mut active = self.native.write().await;
        let (next, response) = native_wallet::NativeWalletRuntime::new(callbacks, request)
            .map_err(native_wallet_operation_failed)?;
        *active = Some(next);
        Ok(response)
    }

    /// Close one native wallet engine and discard its unexecuted transfer quotes.
    async fn native_wallet_close(
        &self,
        request: tinywallet_bus::wire::NativeWalletCloseRequest,
    ) -> BusResult<()> {
        let mut active = self.native.write().await;
        let Some(current) = active.as_ref() else {
            return Err(host_unavailable());
        };
        current
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        *active = None;
        Ok(())
    }

    /// Return implementation-owned network defaults using only opaque host
    /// references for endpoints overridden by the host.
    async fn native_wallet_network_defaults(
        &self,
        request: tinywallet_bus::wire::NativeWalletServiceRequest,
    ) -> BusResult<Vec<tinywallet_bus::wire::WalletNetworkDefaults>> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        Ok(active.engine.network_defaults())
    }

    /// Return the implementation's complete chain-aware supported asset catalog.
    async fn native_wallet_supported_assets(
        &self,
        request: tinywallet_bus::wire::NativeWalletServiceRequest,
    ) -> BusResult<Vec<tinywallet_bus::wire::SupportedAsset>> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        Ok(active.engine.supported_assets())
    }

    /// Probe configured accounts against the providers selected by the host.
    async fn native_wallet_chain_status(
        &self,
        request: tinywallet_bus::wire::NativeWalletServiceRequest,
    ) -> BusResult<Vec<tinywallet_bus::wire::ChainStatus>> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        active
            .engine
            .chain_status()
            .await
            .map_err(native_wallet_operation_failed)
    }

    /// Read native balances across the configured accounts and networks.
    async fn native_wallet_balances(
        &self,
        request: tinywallet_bus::wire::NativeWalletServiceRequest,
    ) -> BusResult<Vec<tinywallet_bus::wire::BalanceInfo>> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        active
            .engine
            .balances()
            .await
            .map_err(native_wallet_operation_failed)
    }

    /// Read catalogued token balances (SPL mints on Solana) for the
    /// configured accounts. Contract 1.15.
    async fn native_wallet_token_balances(
        &self,
        request: tinywallet_bus::wire::NativeWalletServiceRequest,
    ) -> BusResult<Vec<tinywallet_bus::wire::TokenBalanceInfo>> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        active
            .engine
            .token_balances()
            .await
            .map_err(native_wallet_operation_failed)
    }

    /// Validate and store an owner-scoped transfer quote inside the module.
    async fn native_wallet_prepare_transfer(
        &self,
        request: tinywallet_bus::wire::NativeWalletPrepareTransferRequest,
    ) -> BusResult<tinywallet_bus::wire::PreparedTransaction> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        web3::with_quote_owner(request.owner, async {
            active
                .engine
                .prepare_transfer(request.params)
                .await
                .map_err(native_wallet_operation_failed)
        })
        .await
    }

    /// Confirm, authorize, sign and broadcast one prepared transfer.
    #[tinybus(confidential)]
    async fn native_wallet_execute_prepared(
        &self,
        mut request: tinywallet_bus::wire::NativeWalletExecuteRequest,
    ) -> BusResult<tinywallet_bus::wire::ExecutionResult> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            wipe(&mut request.secret);
            return Err(host_unavailable());
        };
        if let Err(error) = active.require_handle(&request.service) {
            wipe(&mut request.secret);
            return Err(native_wallet_operation_failed(error));
        }
        if !request.confirmed {
            wipe(&mut request.secret);
            return Err(invalid_input(
                "native wallet execution requires confirmed: true".to_string(),
            ));
        }
        let owner = request
            .owner
            .as_ref()
            .map(|owner| tinywallet_web3::quote::QuoteOwner {
                thread_id: owner.thread_id.clone(),
                client_id: owner.client_id.clone(),
            });
        let quote = match active
            .engine
            .prepared_quote_for_owner(&request.quote_id, owner.as_ref())
        {
            Ok(quote) => quote,
            Err(error) => {
                wipe(&mut request.secret);
                return Err(native_wallet_operation_failed(error));
            }
        };
        let secret = std::mem::replace(
            &mut request.secret,
            SecretMaterial {
                mnemonic: String::new(),
                derivation_path: String::new(),
                chain: Chain::Evm,
            },
        );
        let quote_id = request.quote_id;
        let confirmed = request.confirmed;
        let owner = request.owner;
        let approval = web3::NativeApprovalContext {
            callbacks: active.callbacks.clone(),
            quote,
        };
        let result = Box::pin(web3::with_execution_context(owner, secret, None, async {
            web3::with_native_approval(approval, async {
                active
                    .engine
                    .execute_prepared(tinywallet_bus::wire::ExecutePreparedParams {
                        quote_id,
                        confirmed,
                    })
                    .await
                    .map_err(native_wallet_operation_failed)
            })
            .await
        }))
        .await;
        wipe(&mut request.secret);
        result
    }

    /// Read transaction confirmation status from the selected provider.
    async fn native_wallet_tx_status(
        &self,
        request: tinywallet_bus::wire::NativeWalletTransactionRequest,
    ) -> BusResult<tinywallet_bus::wire::TxStatusInfo> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        active
            .engine
            .tx_status(request.chain, request.evm_network, &request.hash)
            .await
            .map_err(native_wallet_operation_failed)
    }

    /// Read a transaction receipt from the selected provider.
    async fn native_wallet_tx_receipt(
        &self,
        request: tinywallet_bus::wire::NativeWalletTransactionRequest,
    ) -> BusResult<tinywallet_bus::wire::TxReceiptInfo> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        active
            .engine
            .tx_receipt(request.chain, request.evm_network, &request.hash)
            .await
            .map_err(native_wallet_operation_failed)
    }

    /// Look up a raw transaction from the selected provider.
    async fn native_wallet_lookup_tx(
        &self,
        request: tinywallet_bus::wire::NativeWalletTransactionRequest,
    ) -> BusResult<tinywallet_bus::wire::TxLookupInfo> {
        let active = self.native.read().await;
        let Some(active) = active.as_ref() else {
            return Err(host_unavailable());
        };
        active
            .require_handle(&request.service)
            .map_err(native_wallet_operation_failed)?;
        active
            .engine
            .lookup_tx(request.chain, request.evm_network, &request.hash)
            .await
            .map_err(native_wallet_operation_failed)
    }

    /// Record a paid retry result and release its module-owned reservation.
    async fn x402_record_payment(
        &self,
        request: tinywallet_bus::wire::X402RecordPaymentRequest,
    ) -> BusResult<()> {
        let x402 = self.x402.read().await;
        let Some(x402) = x402.as_ref() else {
            return Err(host_unavailable());
        };
        x402.record(request).map_err(x402_operation_failed)
    }

    /// Report current module-owned x402 totals and reservation state.
    async fn x402_spending_summary(
        &self,
        request: tinywallet_bus::wire::X402SummaryRequest,
    ) -> BusResult<tinywallet_bus::wire::X402SpendingSummary> {
        let x402 = self.x402.read().await;
        let Some(x402) = x402.as_ref() else {
            return Err(host_unavailable());
        };
        x402.summary(&request.service)
            .map_err(x402_operation_failed)
    }

    /// List recent payment records from the configured module-owned ledger.
    async fn x402_list_payments(
        &self,
        request: tinywallet_bus::wire::X402ListPaymentsRequest,
    ) -> BusResult<tinywallet_bus::wire::X402ListPaymentsResponse> {
        let x402 = self.x402.read().await;
        let Some(x402) = x402.as_ref() else {
            return Err(host_unavailable());
        };
        x402.list_payments(&request).map_err(x402_operation_failed)
    }

    /// Update the active spending limits without replacing its ledger.
    async fn x402_update_budget(
        &self,
        request: tinywallet_bus::wire::X402UpdateBudgetRequest,
    ) -> BusResult<tinywallet_bus::wire::X402SpendingSummary> {
        let x402 = self.x402.read().await;
        let Some(x402) = x402.as_ref() else {
            return Err(host_unavailable());
        };
        x402.update_budget(&request).map_err(x402_operation_failed)
    }

    /// Report totals and limits together with payment counts for current hosts.
    async fn x402_spending_summary_detailed(
        &self,
        request: tinywallet_bus::wire::X402SummaryRequest,
    ) -> BusResult<tinywallet_bus::wire::X402DetailedSpendingSummary> {
        let x402 = self.x402.read().await;
        let Some(x402) = x402.as_ref() else {
            return Err(host_unavailable());
        };
        x402.detailed_summary(&request)
            .map_err(x402_operation_failed)
    }

    /// Configure or replace the active x402 ledger after the host has loaded
    /// and selected the user's workspace and spending policy.
    async fn x402_configure(
        &self,
        request: tinywallet_bus::wire::X402ConfigureRequest,
    ) -> BusResult<tinywallet_bus::wire::X402ServiceHandle> {
        let callbacks = self.callbacks.clone().ok_or_else(host_unavailable)?;
        let storage = callbacks
            .ledger_storage()
            .await
            .map_err(x402_operation_failed)?;
        let mut x402 = self.x402.write().await;
        // Build the replacement first. `init_global` swaps the process-wide
        // ledger only once the new one opened, so a failed reconfigure leaves
        // the previous service, its handle and its ledger fully usable.
        let next = x402::X402Runtime::new(callbacks, request.config, storage)
            .map_err(x402_operation_failed)?;
        let handle = next.handle();
        // Dropping the previous runtime stops its lease task; its ledger was
        // replaced above and is not cleared.
        *x402 = Some(next);
        Ok(handle)
    }

    /// Close the configured x402 ledger and release all uncommitted payments.
    async fn x402_close(&self, request: tinywallet_bus::wire::X402CloseRequest) -> BusResult<()> {
        let mut x402 = self.x402.write().await;
        let Some(current) = x402.as_mut() else {
            return Err(host_unavailable());
        };
        current
            .close(&request.service)
            .map_err(x402_operation_failed)?;
        *x402 = None;
        Ok(())
    }

    /// Construct native, ERC-20 or explicit contract transactions and exact approval facts.
    async fn construct_evm_transaction(
        &self,
        request: tinywallet_bus::wire::EvmConstructionRequest,
    ) -> BusResult<tinywallet_bus::wire::ConstructedEvmTransaction> {
        construction::construct(&request).map_err(into_bus_error)
    }

    /// Validate an address using the module's compiled chain rules.
    async fn validate_address(
        &self,
        request: tinywallet_bus::wire::ValidateAddressRequest,
    ) -> BusResult<tinywallet_bus::wire::ValidateAddressResponse> {
        let result = if request.sender && request.chain == Chain::Btc {
            tinywallet::address::btc::validate_sender(&request.address)
        } else {
            tinywallet::address::validate(request.chain, &request.address)
        };
        Ok(tinywallet_bus::wire::ValidateAddressResponse { result })
    }

    /// Report the bytes a caller must sign for `request`.
    async fn build_unsigned(&self, request: SigningRequest) -> BusResult<UnsignedTransaction> {
        build_unsigned(&request).map_err(into_bus_error)
    }

    /// Assemble the broadcast-ready transaction from the caller's signatures.
    async fn attach_signature(&self, request: AttachRequest) -> BusResult<SignedTransaction> {
        attach_signature(&request).map_err(into_bus_error)
    }

    /// Report the address and public key for a phrase, without disclosing a key.
    ///
    /// Confidential: the request carries a recovery phrase. The reply does not
    /// — both of its fields are public information.
    #[tinybus(confidential)]
    async fn derive_account(&self, mut secret: SecretMaterial) -> BusResult<DerivedAccount> {
        let result = derive_account(&secret);
        wipe(&mut secret);
        result.map_err(into_bus_error)
    }

    /// Generate a BIP-39 phrase for the host to encrypt and retain.
    ///
    /// Confidential because the response contains recovery material. The
    /// phrase is generated in the wallet implementation and is not logged or
    /// retained by this module.
    #[tinybus(confidential)]
    async fn generate_mnemonic(
        &self,
        request: tinywallet_bus::wire::GenerateMnemonicRequest,
    ) -> BusResult<tinywallet_bus::wire::GenerateMnemonicResponse> {
        let phrase = tinywallet::key::generate_mnemonic(usize::from(request.word_count))
            .map_err(|error| invalid_input(error.to_string()))?;
        Ok(tinywallet_bus::wire::GenerateMnemonicResponse {
            phrase,
            word_count: request.word_count,
        })
    }

    /// Derive the standard BIP-39 seed for a host-owned storage-key KDF.
    ///
    /// The phrase is accepted only through `TinyBus`'s confidential channel and
    /// wiped from the decoded request before returning.
    #[tinybus(confidential)]
    async fn derive_mnemonic_seed(
        &self,
        mut request: tinywallet_bus::wire::DeriveMnemonicSeedRequest,
    ) -> BusResult<tinywallet_bus::wire::DeriveMnemonicSeedResponse> {
        let result = tinywallet::key::mnemonic_seed(&request.mnemonic).map(|seed| {
            tinywallet_bus::wire::DeriveMnemonicSeedResponse {
                seed: seed.to_vec(),
            }
        });
        zeroize::Zeroize::zeroize(&mut request.mnemonic);
        result.map_err(|error| invalid_input(error.to_string()))
    }

    /// Derive, build, sign and assemble, without the key leaving this module.
    ///
    /// Confidential. This is the method a host should use for everything it
    /// can: the phrase arrives, is used, and is wiped inside one call.
    #[tinybus(confidential)]
    async fn sign_transaction(&self, mut request: SignRequest) -> BusResult<SignedTransaction> {
        let result = sign_transaction(&request);
        wipe(&mut request.secret);
        result.map_err(into_bus_error)
    }

    /// Hand back the raw derived key.
    ///
    /// Confidential in both directions. This is the one method that discloses
    /// key material, and it exists only for a host that must feed a signer it
    /// does not control. Anything that can use `SignTransaction` should.
    /// Sign opaque bytes with the key derived from a phrase.
    ///
    /// Confidential. Blind: nothing here can check what the bytes mean, so
    /// prefer `SignTransaction` wherever the request can be expressed as a
    /// `TransactionSpec`. See `SignMessageRequest` for when this is the right
    /// call and why it is still better than the alternative.
    #[tinybus(confidential)]
    async fn sign_message(&self, mut request: SignMessageRequest) -> BusResult<Signature> {
        let result = sign_message(&request);
        wipe(&mut request.secret);
        result.map_err(into_bus_error)
    }

    #[tinybus(confidential)]
    async fn export_key(&self, mut request: ExportRequest) -> BusResult<ExportedKey> {
        let result = export_key(&request);
        wipe(&mut request.secret);
        result.map_err(into_bus_error)
    }
}

/// Overwrite the recovery phrase once the call that needed it is done.
///
/// **What this achieves, precisely.** It shortens the window in which *this*
/// copy of the phrase is legible in the module's heap. It does not make the
/// module safe against something reading its address space — nothing can, since
/// a loaded module and its host share one — and it does not reach the copies it
/// does not own: the JSON frame the bus decoded from, and any reallocation
/// `String` performed while that decoding grew it. Both are outside this
/// function's reach and neither is claimed to be handled.
///
/// It is still worth doing. A phrase that stays resident for the process
/// lifetime ends up in core dumps and swap; one wiped at the end of the call
/// mostly does not. The bound is real even though it is partial, and the
/// alternative to a partial bound here is no bound at all.
///
/// `SecretMaterial` cannot simply implement `Drop` itself: it lives in
/// `tinywallet::wire`, which is deliberately dependency-free so a host can take
/// the contract without linking anything, and `zeroize` is a dependency.
fn wipe(secret: &mut SecretMaterial) {
    use zeroize::Zeroize;
    secret.mnemonic.zeroize();
    secret.derivation_path.zeroize();
}

/// Derive the key for `secret`, wiping it when the guard drops.
///
/// Every confidential entry point goes through here, so there is one place that
/// knows how a phrase becomes a key and one place that decides what a failure
/// says. The error deliberately names neither the phrase nor the path: a
/// rejected mnemonic that echoed itself into a log would defeat the point of
/// having carried it confidentially.
fn derive(secret: &SecretMaterial) -> Result<key::DerivedKey, Failure> {
    key::derive(secret.chain, &secret.mnemonic, &secret.derivation_path).map_err(|error| {
        // `key::Error`'s Display is written not to quote the phrase; this maps
        // by variant anyway rather than trusting that to stay true.
        Failure::InvalidInput(match error {
            key::Error::InvalidMnemonic => "recovery phrase is not valid BIP-39".to_string(),
            key::Error::InvalidPath { .. } => "derivation path is malformed".to_string(),
            key::Error::UnhardenedSolanaPath { .. } => {
                "Solana derivation path must be fully hardened".to_string()
            }
            other => format!("key derivation failed: {}", failure_kind(&other)),
        })
    })
}

/// A stable, phrase-free label for a derivation failure this build did not map.
fn failure_kind(error: &key::Error) -> &'static str {
    match error {
        key::Error::ChainNotCompiled { .. } => "chain not compiled into this module",
        _ => "unsupported",
    }
}

fn derive_account(secret: &SecretMaterial) -> Result<DerivedAccount, Failure> {
    let derived = derive(secret)?;
    Ok(DerivedAccount {
        address: derived.address().to_string(),
        public_key: PublicKey {
            key_hex: public_key_hex(secret.chain, derived.secret_bytes())?,
        },
    })
}

fn sign_transaction(request: &SignRequest) -> Result<SignedTransaction, Failure> {
    let derived = derive(&request.secret)?;

    // The chain the caller asked to derive for and the chain the transaction is
    // for must agree. Without this a Solana phrase could be walked with EVM
    // rules and sign an EVM transaction from an address the user never saw —
    // the request would look consistent and the money would be gone.
    if request.secret.chain != request.transaction.chain() {
        return Err(Failure::InvalidInput(
            "derivation chain does not match the transaction's chain".to_string(),
        ));
    }

    let public_key = PublicKey {
        key_hex: public_key_hex(request.secret.chain, derived.secret_bytes())?,
    };

    // Built, signed and reassembled through exactly the paths the split flow
    // uses. Sharing them is what makes `the_one_shot_path_agrees_with_the_split_path`
    // a real assertion rather than two implementations agreeing by luck.
    let unsigned = build_unsigned(&SigningRequest {
        transaction: request.transaction.clone(),
        public_key: public_key.clone(),
    })?;
    let signatures = unsigned
        .payloads
        .iter()
        .map(|payload| sign_payload(payload, derived.secret_bytes()))
        .collect::<Result<Vec<_>, Failure>>()?;
    attach_signature(&AttachRequest {
        transaction: request.transaction.clone(),
        public_key,
        signatures,
    })
}

fn sign_message(request: &SignMessageRequest) -> Result<Signature, Failure> {
    let derived = derive(&request.secret)?;
    // Routed through the same `sign_payload` the transaction paths use, so the
    // prehash-vs-whole-message distinction is decided in exactly one place. A
    // second implementation here is how the two would eventually disagree, and
    // a signature over the wrong bytes is still a valid signature.
    sign_payload(
        &SigningPayload {
            bytes_hex: request.message_hex.clone(),
            scheme: request.scheme,
        },
        derived.secret_bytes(),
    )
}

fn export_key(request: &ExportRequest) -> Result<ExportedKey, Failure> {
    let derived = derive(&request.secret)?;
    Ok(ExportedKey {
        secret_key_hex: hex(derived.secret_bytes()),
        address: derived.address().to_string(),
    })
}

/// The compressed public key a chain's builder expects, as lowercase hex.
fn public_key_hex(chain: Chain, secret: &[u8]) -> Result<String, Failure> {
    // Solana is the ed25519 chain; the other three are secp256k1. Written as a
    // two-way split rather than a match because `Chain` is `#[non_exhaustive]`,
    // so a match would need a wildcard that silently treated a future chain as
    // secp256k1 — which is what the `else` does too, but visibly.
    if chain == Chain::Solana {
        let key = ed25519_signing_key(secret)?;
        Ok(hex(&key.verifying_key().to_bytes()))
    } else {
        {
            use bitcoin::secp256k1::{PublicKey as SecpPublic, Secp256k1, SecretKey};
            let secret = SecretKey::from_slice(secret).map_err(|_| {
                Failure::BuildFailed("derived key is not a valid scalar".to_string())
            })?;
            Ok(hex(&SecpPublic::from_secret_key(
                &Secp256k1::new(),
                &secret,
            )
            .serialize()))
        }
    }
}

/// Sign one payload with the scheme it names.
///
/// The scheme comes from the payload rather than from the chain, so this cannot
/// drift from what the builder actually produced: a builder that starts
/// emitting a different scheme is followed here automatically.
fn sign_payload(payload: &SigningPayload, secret: &[u8]) -> Result<Signature, Failure> {
    let bytes = decode_hex(&payload.bytes_hex)?;
    match payload.scheme {
        Scheme::Secp256k1Prehash => {
            use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
            // `Message::from_digest` takes exactly 32 bytes. The builder always
            // emits that, and a payload that is not is a bug worth failing on
            // rather than padding into something signable.
            let digest: [u8; 32] = bytes.try_into().map_err(|_| {
                Failure::BuildFailed("secp256k1 payload is not a 32-byte digest".to_string())
            })?;
            let secret = SecretKey::from_slice(secret).map_err(|_| {
                Failure::BuildFailed("derived key is not a valid scalar".to_string())
            })?;
            let recoverable = Secp256k1::signing_only()
                .sign_ecdsa_recoverable(&Message::from_digest(digest), &secret);
            let (recovery_id, compact) = recoverable.serialize_compact();
            Ok(Signature::Secp256k1 {
                rs_hex: hex(&compact),
                recovery_id: u8::try_from(recovery_id.to_i32())
                    .map_err(|_| Failure::BuildFailed("recovery id out of range".to_string()))?,
            })
        }
        Scheme::Ed25519 => {
            use ed25519_dalek::Signer;
            let key = ed25519_signing_key(secret)?;
            Ok(Signature::Ed25519 {
                signature_hex: hex(&key.sign(&bytes).to_bytes()),
            })
        }
        // `Scheme` is `#[non_exhaustive]`, so a future variant compiles against
        // this build and arrives here. Refuse it. Falling back to either arm
        // would sign real bytes with the wrong scheme — the one outcome that
        // must never be reachable by adding a variant somewhere else.
        _ => Err(Failure::BuildFailed(
            "signing scheme is not supported by this module build".to_string(),
        )),
    }
}

fn ed25519_signing_key(secret: &[u8]) -> Result<ed25519_dalek::SigningKey, Failure> {
    let bytes: [u8; 32] = secret
        .try_into()
        .map_err(|_| Failure::BuildFailed("derived ed25519 key is not 32 bytes".to_string()))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Why a call failed, before it becomes a wire error name.
#[derive(Debug)]
enum Failure {
    /// The caller's request was wrong.
    InvalidInput(String),
    /// Building or assembling failed for a reason the caller did not cause.
    BuildFailed(String),
}

/// Map a failure onto the wire name a host matches on.
fn into_bus_error(failure: Failure) -> BusError {
    let (name, message) = match failure {
        Failure::InvalidInput(message) => (INVALID_INPUT_ERROR, message),
        Failure::BuildFailed(message) => (BUILD_FAILED_ERROR, message),
    };
    BusError::MethodFailed {
        name: name.to_string(),
        message,
    }
}

fn failure_message(failure: Failure) -> String {
    match failure {
        Failure::InvalidInput(message) | Failure::BuildFailed(message) => message,
    }
}

/// Compute the signing payloads for `request`.
fn build_unsigned(request: &SigningRequest) -> Result<UnsignedTransaction, Failure> {
    // `chain_of` runs first so an unrecognised shape is refused before any
    // arm is tried; the chain itself then comes from the variant.
    let payloads = match &request.transaction {
        TransactionSpec::Btc {
            from,
            to,
            amount_sat,
            fee_sat,
            utxos,
        } => {
            let transfer = btc_transfer(from, to, *amount_sat, *fee_sat);
            let public = compressed_public_key(&request.public_key.key_hex)?;
            let (_, digests) = transfer
                .sighashes(&btc_utxos(utxos), &public)
                .map_err(|e| build_failed(&e))?;
            digests.into_iter().map(secp256k1_payload).collect()
        }
        spec @ TransactionSpec::Evm { .. } => {
            vec![secp256k1_payload(
                evm_transaction(spec)?
                    .digest()
                    .map_err(|e| build_failed(&e))?,
            )]
        }
        spec @ TransactionSpec::Solana { .. } => {
            // ed25519 signs the message itself — there is nothing to pre-hash,
            // so this payload is the whole serialized message, not a digest.
            vec![SigningPayload {
                bytes_hex: hex(&solana_transfer(spec)?
                    .message()
                    .map_err(|e| build_failed(&e))?),
                scheme: Scheme::Ed25519,
            }]
        }
        TransactionSpec::Tron {
            raw_data_hex,
            expected_to,
            expected_txid,
            transfer,
        } => {
            // Tron's node builds the transaction, so the only defence against a
            // compromised endpoint is checking that what came back is what was
            // asked for — before signing it, which is here.
            //
            // `verify_contract`, not `verify_transfer`: the latter searches for
            // the recipient and amount as byte runs anywhere in `raw_data`, so a
            // node can pay someone else and leave the requested address in an
            // unrelated field and still be signed. This parses the protobuf and
            // reads the fields that will actually execute.
            //
            // `fee_limit_sun` is `None` because the wire spec does not carry it
            // — only the host knows what it pinned in its `createtransaction`
            // request, and it checks that before handing the spec over. Every
            // other field is checked here, on the side that holds the key.
            tx::tron::verify_contract(raw_data_hex, expected_to, expected_txid, transfer, None)
                .map_err(|e| Failure::InvalidInput(e.to_string()))?;
            vec![secp256k1_payload(
                tx::tron::digest(raw_data_hex).map_err(|e| build_failed(&e))?,
            )]
        }
        // Required because `TransactionSpec` is `#[non_exhaustive]`: a shape
        // added after this build must be refused, never guessed at.
        _ => return Err(unknown_kind()),
    };
    Ok(UnsignedTransaction { payloads })
}

/// Assemble the signed transaction for `request`.
fn attach_signature(request: &AttachRequest) -> Result<SignedTransaction, Failure> {
    match &request.transaction {
        TransactionSpec::Btc {
            from,
            to,
            amount_sat,
            fee_sat,
            utxos,
        } => {
            let transfer = btc_transfer(from, to, *amount_sat, *fee_sat);
            let public = compressed_public_key(&request.public_key.key_hex)?;
            let signatures = request
                .signatures
                .iter()
                .map(secp256k1_rs)
                .collect::<Result<Vec<_>, _>>()?;
            let raw = transfer
                .attach_signatures(&btc_utxos(utxos), &public, &signatures)
                .map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                // A Bitcoin txid is the hash of the serialized transaction, but
                // reporting it would mean hashing here and in the host; the
                // node returns it on broadcast, so it is left unset rather than
                // computed twice.
                txid: None,
                raw,
            })
        }
        spec @ TransactionSpec::Evm { .. } => {
            let (rs, recovery) = single_secp256k1(&request.signatures)?;
            let signed = evm_transaction(spec)?
                .attach_signature(&rs, recovery)
                .map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                txid: Some(tx::evm::LegacyTransaction::hash_of(&signed)),
                raw: format!("0x{}", hex(&signed)),
            })
        }
        spec @ TransactionSpec::Solana { .. } => {
            let signature = single_ed25519(&request.signatures)?;
            let signed = solana_transfer(spec)?
                .attach_signature(&signature)
                .map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                // Solana's signature *is* its id, base58-encoded. Encoded
                // here rather than through `address::solana::encode`, which
                // takes a 32-byte address — a signature is 64.
                txid: Some(bs58::encode(signature).into_string()),
                raw: base64(&signed),
            })
        }
        TransactionSpec::Tron {
            raw_data_hex,
            expected_to,
            expected_txid,
            transfer,
        } => {
            // Verified again rather than trusted from the first call: the two
            // requests are independent, and a host could reach this one with
            // different bytes than the digest was computed over. Structurally,
            // for the same reason as the sign path above.
            tx::tron::verify_contract(raw_data_hex, expected_to, expected_txid, transfer, None)
                .map_err(|e| Failure::InvalidInput(e.to_string()))?;
            let (rs, recovery) = single_secp256k1(&request.signatures)?;
            let signature =
                tx::tron::attach_signature(&rs, recovery).map_err(|e| build_failed(&e))?;
            Ok(SignedTransaction {
                txid: Some(expected_txid.clone()),
                raw: tx::tron::signature_hex(&signature),
            })
        }
        _ => Err(unknown_kind()),
    }
}

/// The refusal for a transaction shape added after this build.
///
/// `TransactionSpec` is `#[non_exhaustive]`, so a peer built against a newer
/// revision can send a variant this module cannot name. Refusing beats
/// guessing: the alternative is building some other chain's transaction.
fn unknown_kind() -> Failure {
    Failure::InvalidInput("this build does not understand that transaction kind".to_string())
}

/// Collapse a `tinywallet` build error, which is never the caller's fault by
/// the time it is reached — inputs are checked before building.
fn build_failed(error: &tx::Error) -> Failure {
    Failure::BuildFailed(error.to_string())
}

/// A secp256k1 payload over an already-computed digest.
fn secp256k1_payload(digest: [u8; 32]) -> SigningPayload {
    SigningPayload {
        bytes_hex: hex(&digest),
        scheme: Scheme::Secp256k1Prehash,
    }
}

/// The one secp256k1 signature a single-signature chain expects.
fn single_secp256k1(signatures: &[Signature]) -> Result<([u8; 64], u8), Failure> {
    let [only] = signatures else {
        return Err(Failure::InvalidInput(format!(
            "expected exactly one signature, got {}",
            signatures.len()
        )));
    };
    secp256k1_rs(only).map(|rs| (rs, recovery_of(only)))
}

/// The 64-byte `r ‖ s` of a secp256k1 signature.
fn secp256k1_rs(signature: &Signature) -> Result<[u8; 64], Failure> {
    match signature {
        Signature::Secp256k1 { rs_hex, .. } => fixed_hex::<64>(rs_hex, "signature"),
        Signature::Ed25519 { .. } => Err(Failure::InvalidInput(
            "expected a secp256k1 signature, got an ed25519 one".to_string(),
        )),
        // `Signature` is `#[non_exhaustive]`: a scheme this build has never
        // heard of cannot be reassembled, and guessing would produce a
        // well-formed transaction carrying nonsense.
        _ => Err(Failure::InvalidInput(
            "unrecognised signature scheme".to_string(),
        )),
    }
}

/// The recovery id of a secp256k1 signature, or zero for the wrong variant.
///
/// Only ever called after [`secp256k1_rs`] has confirmed the variant, so the
/// fallback is unreachable; it exists so this cannot panic inside a wallet.
fn recovery_of(signature: &Signature) -> u8 {
    match signature {
        Signature::Secp256k1 { recovery_id, .. } => *recovery_id,
        Signature::Ed25519 { .. } | _ => 0,
    }
}

/// The one ed25519 signature Solana expects.
fn single_ed25519(signatures: &[Signature]) -> Result<[u8; 64], Failure> {
    let [Signature::Ed25519 { signature_hex }] = signatures else {
        return Err(Failure::InvalidInput(
            "expected exactly one ed25519 signature".to_string(),
        ));
    };
    fixed_hex::<64>(signature_hex, "signature")
}

/// A compressed SEC1 public key from its hex.
fn compressed_public_key(key_hex: &str) -> Result<[u8; 33], Failure> {
    fixed_hex::<33>(key_hex, "public key")
}

/// Decode hex into exactly `N` bytes.
fn fixed_hex<const N: usize>(value: &str, what: &str) -> Result<[u8; N], Failure> {
    let body = value.strip_prefix("0x").unwrap_or(value);
    if body.len() != N * 2 {
        return Err(Failure::InvalidInput(format!(
            "{what} must be {N} bytes, got {} hex characters",
            body.len()
        )));
    }
    let mut out = [0u8; N];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = body
            .get(index * 2..index * 2 + 2)
            .ok_or_else(|| Failure::InvalidInput(format!("{what} is truncated")))?;
        *slot = u8::from_str_radix(pair, 16)
            .map_err(|_| Failure::InvalidInput(format!("{what} is not hex")))?;
    }
    Ok(out)
}

/// Rebuild the Bitcoin transfer from its wire fields.
fn btc_transfer(from: &str, to: &str, amount_sat: u64, fee_sat: u64) -> tx::btc::Transfer {
    tx::btc::Transfer {
        from: from.to_string(),
        to: to.to_string(),
        amount: amount_sat,
        fee: fee_sat,
    }
}

/// Rebuild the UTXO set from its wire form.
fn btc_utxos(utxos: &[tinywallet::wire::Utxo]) -> Vec<tx::btc::Utxo> {
    utxos
        .iter()
        .map(|utxo| tx::btc::Utxo {
            txid: utxo.txid.clone(),
            vout: utxo.vout,
            value: utxo.value,
        })
        .collect()
}

/// Rebuild the EVM transaction from its wire fields.
fn evm_transaction(spec: &TransactionSpec) -> Result<tx::evm::LegacyTransaction, Failure> {
    let TransactionSpec::Evm {
        to,
        value_wei,
        data_hex,
        nonce,
        gas_limit,
        gas_price_wei,
        chain_id,
    } = spec
    else {
        return Err(Failure::InvalidInput(
            "expected an EVM transaction".to_string(),
        ));
    };

    // An empty recipient would be contract creation, which a wallet
    // transaction never is: refuse it rather than sign one.
    if to.trim().is_empty() {
        return Err(Failure::InvalidInput(
            "EVM recipient is required".to_string(),
        ));
    }

    Ok(tx::evm::LegacyTransaction {
        nonce: u128::from(*nonce),
        gas_price: decimal_u128(gas_price_wei, "gas_price_wei")?,
        gas_limit: u128::from(*gas_limit),
        to: Some(to.clone()),
        value: decimal_u128(value_wei, "value_wei")?,
        data: decode_hex(data_hex)?,
        chain_id: *chain_id,
    })
}

/// Rebuild the Solana transfer from its wire fields.
fn solana_transfer(spec: &TransactionSpec) -> Result<tx::solana::NativeTransfer, Failure> {
    let TransactionSpec::Solana {
        from,
        to,
        lamports,
        recent_blockhash,
    } = spec
    else {
        return Err(Failure::InvalidInput(
            "expected a Solana transaction".to_string(),
        ));
    };
    Ok(tx::solana::NativeTransfer {
        from: from.clone(),
        to: to.clone(),
        lamports: *lamports,
        recent_blockhash: recent_blockhash.clone(),
    })
}

/// Parse a base-10 wei amount.
///
/// `u128` rather than a 256-bit type because that is what
/// `LegacyTransaction` takes: wei amounts and gas prices live far below 2^128,
/// and the RLP encoder is written against it.
fn decimal_u128(value: &str, field: &str) -> Result<u128, Failure> {
    value.trim().parse().map_err(|_| {
        Failure::InvalidInput(format!(
            "{field} is not a base-10 integer that fits in 128 bits"
        ))
    })
}

/// Decode optionally-`0x`-prefixed hex of any length.
fn decode_hex(value: &str) -> Result<Vec<u8>, Failure> {
    let body = value.strip_prefix("0x").unwrap_or(value).trim();
    if body.is_empty() {
        return Ok(Vec::new());
    }
    if !body.len().is_multiple_of(2) {
        return Err(Failure::InvalidInput(
            "call data has an odd number of hex characters".to_string(),
        ));
    }
    (0..body.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(
                body.get(index..index + 2)
                    .ok_or_else(|| Failure::InvalidInput("call data is not hex".to_string()))?,
                16,
            )
            .map_err(|_| Failure::InvalidInput("call data is not hex".to_string()))
        })
        .collect()
}

/// Lowercase hex, unprefixed.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// Standard base64, which is what Solana's `sendTransaction` takes.
///
/// Hand-rolled rather than pulled in: it is one table and a three-byte loop,
/// and this module has no other use for an encoding crate.
fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;

        out.push(char::from(TABLE[((triple >> 18) & 0x3f) as usize]));
        out.push(char::from(TABLE[((triple >> 12) & 0x3f) as usize]));
        out.push(if chunk.len() > 1 {
            char::from(TABLE[((triple >> 6) & 0x3f) as usize])
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            char::from(TABLE[(triple & 0x3f) as usize])
        } else {
            '='
        });
    }
    out
}

async fn setup(connection: Connection) -> BusResult<()> {
    let callbacks = host::HostCallbacks::new(&connection)?;
    let wallet = Wallet {
        callbacks: Some(callbacks.clone()),
        web3: tokio::sync::RwLock::new(None),
        native: tokio::sync::RwLock::new(None),
        x402: tokio::sync::RwLock::new(None),
    };
    connection.serve_at(OBJECT_PATH.try_into()?, wallet).await?;
    connection.request_name(BUS_NAME).await?;
    Ok(())
}

fn host_unavailable() -> BusError {
    BusError::MethodFailed {
        name: "ai.tinyhumans.tinywallet.Error.HostUnavailable".to_string(),
        message: "wallet host callback interface is unavailable".to_string(),
    }
}

fn host_call_failed(message: String) -> BusError {
    BusError::MethodFailed {
        name: "ai.tinyhumans.tinywallet.Error.HostCallFailed".to_string(),
        message,
    }
}

fn invalid_input(message: String) -> BusError {
    BusError::MethodFailed {
        name: INVALID_INPUT_ERROR.to_string(),
        message,
    }
}

fn web3_operation_failed(message: String) -> BusError {
    BusError::MethodFailed {
        name: "ai.tinyhumans.tinywallet.Error.Web3OperationFailed".to_string(),
        message,
    }
}

fn x402_operation_failed(message: String) -> BusError {
    BusError::MethodFailed {
        name: "ai.tinyhumans.tinywallet.Error.X402OperationFailed".to_string(),
        message,
    }
}

fn native_wallet_operation_failed(message: String) -> BusError {
    BusError::MethodFailed {
        name: "ai.tinyhumans.tinywallet.Error.NativeWalletOperationFailed".to_string(),
        message,
    }
}

fn host_build_failed(message: String) -> BusError {
    BusError::MethodFailed {
        name: BUILD_FAILED_ERROR.to_string(),
        message,
    }
}

// Isolate the generated public C symbols so the lint exception cannot hide
// undocumented Rust API. Their contract is TinyBus ABI v1, and none is a
// Rust-callable export from this private module.
#[allow(
    missing_docs,
    unreachable_pub,
    reason = "generated C ABI symbols are documented by the TinyBus module SDK"
)]
mod exports {
    tinybus_module::module_export_optional_static! {
        setup = super::setup,
        worker_threads = 2,
        provides = ["ai.tinyhumans.tinywallet.Wallet"],
        // Hand-maintained, and the compiler cannot check it against the
        // `#[tinybus::interface]` block above — a method missing here is
        // simply not advertised. `the_manifest_advertises_every_method` in
        // `tests/module_e2e.rs` is the guard; keep the two in step.
        methods = [
            "BuildUnsigned",
            "AttachSignature",
            "DeriveAccount",
            "DeriveMnemonicSeed",
            "EncodeErc20Transfer",
            "GenerateMnemonic",
            "SignTransaction",
            "ExportKey",
            "SignMessage",
            "ValidateAddress",
            "ConstructEvmTransaction",
            "Web3Routes",
            "Web3SwapQuote",
            "Web3BridgeQuote",
            "Web3DappQuote",
            "Web3Execute",
            "Web3Configure",
            "Web3ConfigureWithEndpoints",
            "Web3Close",
            "NativeWalletConfigure",
            "NativeWalletClose",
            "NativeWalletNetworkDefaults",
            "NativeWalletSupportedAssets",
            "NativeWalletChainStatus",
            "NativeWalletBalances",
            "NativeWalletTokenBalances",
            "NativeWalletPrepareTransfer",
            "NativeWalletExecutePrepared",
            "NativeWalletTxStatus",
            "NativeWalletTxReceipt",
            "NativeWalletLookupTx",
            "X402PreparePayment",
            "X402RecordPayment",
            "X402SpendingSummary",
            "X402SpendingSummaryDetailed",
            "X402ListPayments",
            "X402UpdateBudget",
            "X402Configure",
            "X402Close",
            "X402SignIn",
        ],
        signals = [],
        requires = [],
        optional = ["ai.tinyhumans.tinywallet.Host"],
        lazy = false,
    }
}

/// Entry points and manifest for a host that links this module in-process
/// (local dev and tests only; released modules load as the `cdylib`).
#[cfg(feature = "static-link")]
pub use exports::linked_module;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
