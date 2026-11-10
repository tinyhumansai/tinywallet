//! The `TinyWallet` module's bus identity and member names.
//!
//! A host that spells a member as a string literal finds out it got it wrong
//! when the call returns `NameHasNoOwner` in the field. Naming them here makes
//! the same mistake a compile error.

/// The well-known interface name the module claims on the bus.
pub const BUS_NAME: &str = "ai.tinyhumans.tinywallet.Wallet";

/// The object path the module serves its interface at.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinywallet/Wallet";

/// The host callback interface the wallet module uses for custody and I/O.
pub const HOST_INTERFACE: &str = "ai.tinyhumans.tinywallet.Host";

/// The object path at which the host serves [`HOST_INTERFACE`].
pub const HOST_OBJECT_PATH: &str = "/ai/tinyhumans/tinywallet/Host";

/// One constant per callback member of the host interface.
pub mod host_methods {
    /// Host account state and public addresses.
    pub const WALLET_ACCOUNTS: &str = "WalletAccounts";
    /// Chain RPC or REST transport.
    pub const CHAIN_TRANSPORT: &str = "ChainTransport";
    /// Authenticated `TinyHumans` backend transport.
    pub const WALLET_BACKEND: &str = "WalletBackend";
    /// Authorize the exact facts in one stored Web3 quote.
    pub const AUTHORIZE_WEB3_EXECUTION: &str = "AuthorizeWeb3Execution";
    /// Authorize the exact facts of one native wallet transfer.
    pub const AUTHORIZE_NATIVE_WALLET_EXECUTION: &str = "AuthorizeNativeWalletExecution";
    /// Approval for exact x402 challenge terms before signing.
    pub const AUTHORIZE_X402_PAYMENT: &str = "AuthorizeX402Payment";
}

/// Every callback member of the host interface.
pub const HOST_METHODS: &[&str] = &[
    host_methods::AUTHORIZE_NATIVE_WALLET_EXECUTION,
    host_methods::AUTHORIZE_WEB3_EXECUTION,
    host_methods::AUTHORIZE_X402_PAYMENT,
    host_methods::CHAIN_TRANSPORT,
    host_methods::WALLET_ACCOUNTS,
    host_methods::WALLET_BACKEND,
];

/// One constant per member of [`BUS_NAME`].
pub mod methods {
    /// Constructs an EVM transaction with exact facts for host approval.
    pub const CONSTRUCT_EVM_TRANSACTION: &str = "ConstructEvmTransaction";
    /// Reports the bytes a caller must sign for a [`crate::wire::SigningRequest`].
    pub const BUILD_UNSIGNED: &str = "BuildUnsigned";
    /// Assembles the broadcast-ready transaction from a caller's signatures.
    pub const ATTACH_SIGNATURE: &str = "AttachSignature";
    /// Reports the address and public key for a recovery phrase. Confidential.
    pub const DERIVE_ACCOUNT: &str = "DeriveAccount";
    /// Derives the standard BIP-39 seed for an existing host storage-key KDF. Confidential.
    pub const DERIVE_MNEMONIC_SEED: &str = "DeriveMnemonicSeed";
    /// Derives, builds, signs and assembles in one call. Confidential.
    pub const SIGN_TRANSACTION: &str = "SignTransaction";
    /// Signs arbitrary bytes with a derived key. Confidential.
    pub const SIGN_MESSAGE: &str = "SignMessage";
    /// Exports the private key for a derivation path. Confidential.
    pub const EXPORT_KEY: &str = "ExportKey";
    /// Generates a recovery phrase for host encryption and custody. Confidential.
    pub const GENERATE_MNEMONIC: &str = "GenerateMnemonic";
    /// Validates a recipient or Bitcoin sender address inside the module.
    pub const VALIDATE_ADDRESS: &str = "ValidateAddress";
    /// Lists supported swap and bridge routes.
    pub const WEB3_ROUTES: &str = "Web3Routes";
    /// Prepares a single-chain swap quote.
    pub const WEB3_SWAP_QUOTE: &str = "Web3SwapQuote";
    /// Prepares a cross-chain bridge quote.
    pub const WEB3_BRIDGE_QUOTE: &str = "Web3BridgeQuote";
    /// Prepares an EVM dapp-call quote.
    pub const WEB3_DAPP_QUOTE: &str = "Web3DappQuote";
    /// Executes a stored quote after module-side signing and host approval.
    pub const WEB3_EXECUTE: &str = "Web3Execute";
    /// Open or replace the active module-owned Web3 quote service.
    pub const WEB3_CONFIGURE: &str = "Web3Configure";
    /// Open Web3 with host-selected cluster and opaque endpoint references.
    pub const WEB3_CONFIGURE_WITH_ENDPOINTS: &str = "Web3ConfigureWithEndpoints";
    /// Close one Web3 quote service and discard its unexecuted quotes.
    pub const WEB3_CLOSE: &str = "Web3Close";
    /// Open a configured native wallet engine service.
    pub const NATIVE_WALLET_CONFIGURE: &str = "NativeWalletConfigure";
    /// Close a native wallet engine service.
    pub const NATIVE_WALLET_CLOSE: &str = "NativeWalletClose";
    /// Read native wallet network defaults.
    pub const NATIVE_WALLET_NETWORK_DEFAULTS: &str = "NativeWalletNetworkDefaults";
    /// List native wallet supported assets.
    pub const NATIVE_WALLET_SUPPORTED_ASSETS: &str = "NativeWalletSupportedAssets";
    /// Read native wallet chain status.
    pub const NATIVE_WALLET_CHAIN_STATUS: &str = "NativeWalletChainStatus";
    /// Read native wallet balances.
    pub const NATIVE_WALLET_BALANCES: &str = "NativeWalletBalances";
    /// Prepare a native wallet transfer quote.
    pub const NATIVE_WALLET_PREPARE_TRANSFER: &str = "NativeWalletPrepareTransfer";
    /// Read catalogued token balances (SPL mints on Solana) for the configured
    /// accounts. Contract 1.15.
    pub const NATIVE_WALLET_TOKEN_BALANCES: &str = "NativeWalletTokenBalances";
    /// Execute a prepared native wallet transfer.
    pub const NATIVE_WALLET_EXECUTE_PREPARED: &str = "NativeWalletExecutePrepared";
    /// Read native wallet transaction status.
    pub const NATIVE_WALLET_TX_STATUS: &str = "NativeWalletTxStatus";
    /// Read a native wallet transaction receipt.
    pub const NATIVE_WALLET_TX_RECEIPT: &str = "NativeWalletTxReceipt";
    /// Look up a native wallet transaction.
    pub const NATIVE_WALLET_LOOKUP_TX: &str = "NativeWalletLookupTx";
    /// Parses a challenge, reserves budget and builds a confidential payment.
    pub const X402_PREPARE_PAYMENT: &str = "X402PreparePayment";
    /// Encodes ERC-20 transfer calldata using the module-owned ABI implementation.
    pub const ENCODE_ERC20_TRANSFER: &str = "EncodeErc20Transfer";
    /// Records a retry result and commits or releases its module reservation.
    pub const X402_RECORD_PAYMENT: &str = "X402RecordPayment";
    /// Reports ledger totals and spending limits.
    pub const X402_SPENDING_SUMMARY: &str = "X402SpendingSummary";
    /// Reports ledger totals, counts and spending limits for host projection.
    pub const X402_SPENDING_SUMMARY_DETAILED: &str = "X402SpendingSummaryDetailed";
    /// Configure or replace the active module-owned x402 ledger.
    pub const X402_CONFIGURE: &str = "X402Configure";
    /// List recent payment records from the module-owned ledger.
    pub const X402_LIST_PAYMENTS: &str = "X402ListPayments";
    /// Close the active x402 ledger and release pending reservations.
    pub const X402_CLOSE: &str = "X402Close";
    /// Update the active ledger's host-selected spending limits.
    pub const X402_UPDATE_BUDGET: &str = "X402UpdateBudget";
}

/// Every member of [`BUS_NAME`], in the interface's sorted dispatch order.
pub const METHODS: &[&str] = &[
    methods::ATTACH_SIGNATURE,
    methods::BUILD_UNSIGNED,
    methods::CONSTRUCT_EVM_TRANSACTION,
    methods::DERIVE_ACCOUNT,
    methods::DERIVE_MNEMONIC_SEED,
    methods::ENCODE_ERC20_TRANSFER,
    methods::EXPORT_KEY,
    methods::GENERATE_MNEMONIC,
    methods::NATIVE_WALLET_BALANCES,
    methods::NATIVE_WALLET_CHAIN_STATUS,
    methods::NATIVE_WALLET_CLOSE,
    methods::NATIVE_WALLET_CONFIGURE,
    methods::NATIVE_WALLET_EXECUTE_PREPARED,
    methods::NATIVE_WALLET_LOOKUP_TX,
    methods::NATIVE_WALLET_NETWORK_DEFAULTS,
    methods::NATIVE_WALLET_PREPARE_TRANSFER,
    methods::NATIVE_WALLET_SUPPORTED_ASSETS,
    methods::NATIVE_WALLET_TOKEN_BALANCES,
    methods::NATIVE_WALLET_TX_RECEIPT,
    methods::NATIVE_WALLET_TX_STATUS,
    methods::SIGN_MESSAGE,
    methods::SIGN_TRANSACTION,
    methods::VALIDATE_ADDRESS,
    methods::WEB3_BRIDGE_QUOTE,
    methods::WEB3_CLOSE,
    methods::WEB3_CONFIGURE,
    methods::WEB3_CONFIGURE_WITH_ENDPOINTS,
    methods::WEB3_DAPP_QUOTE,
    methods::WEB3_EXECUTE,
    methods::WEB3_ROUTES,
    methods::WEB3_SWAP_QUOTE,
    methods::X402_CLOSE,
    methods::X402_CONFIGURE,
    methods::X402_LIST_PAYMENTS,
    methods::X402_PREPARE_PAYMENT,
    methods::X402_RECORD_PAYMENT,
    methods::X402_SPENDING_SUMMARY,
    methods::X402_SPENDING_SUMMARY_DETAILED,
    methods::X402_UPDATE_BUDGET,
];

/// The members that carry a recovery phrase or a private key.
///
/// These must be called over a confidential channel. Listing them here rather
/// than leaving it to each host's memory is the point: the distinction is not
/// visible in a member's name, and calling one of these in the clear puts a
/// recovery phrase on the wire.
pub const CONFIDENTIAL_METHODS: &[&str] = &[
    methods::DERIVE_ACCOUNT,
    methods::DERIVE_MNEMONIC_SEED,
    methods::EXPORT_KEY,
    methods::GENERATE_MNEMONIC,
    methods::NATIVE_WALLET_EXECUTE_PREPARED,
    methods::SIGN_MESSAGE,
    methods::SIGN_TRANSACTION,
    methods::WEB3_EXECUTE,
    methods::X402_PREPARE_PAYMENT,
];
