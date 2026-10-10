//! The `TinyWallet` module's bus identity and member names.
//!
//! A host that spells a member as a string literal finds out it got it wrong
//! when the call returns `NameHasNoOwner` in the field. Naming them here makes
//! the same mistake a compile error.

/// The well-known interface name the module claims on the bus.
pub const BUS_NAME: &str = "ai.tinyhumans.tinywallet.Wallet";

/// The object path the module serves its interface at.
pub const OBJECT_PATH: &str = "/ai/tinyhumans/tinywallet/Wallet";

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
    /// Derives, builds, signs and assembles in one call. Confidential.
    pub const SIGN_TRANSACTION: &str = "SignTransaction";
    /// Signs arbitrary bytes with a derived key. Confidential.
    pub const SIGN_MESSAGE: &str = "SignMessage";
    /// Exports the private key for a derivation path. Confidential.
    pub const EXPORT_KEY: &str = "ExportKey";
    /// Validates a recipient or Bitcoin sender address inside the module.
    pub const VALIDATE_ADDRESS: &str = "ValidateAddress";
}

/// Every member of [`BUS_NAME`], in the interface's sorted dispatch order.
pub const METHODS: &[&str] = &[
    methods::ATTACH_SIGNATURE,
    methods::BUILD_UNSIGNED,
    methods::CONSTRUCT_EVM_TRANSACTION,
    methods::DERIVE_ACCOUNT,
    methods::EXPORT_KEY,
    methods::SIGN_MESSAGE,
    methods::SIGN_TRANSACTION,
    methods::VALIDATE_ADDRESS,
];

/// The members that carry a recovery phrase or a private key.
///
/// These must be called over a confidential channel. Listing them here rather
/// than leaving it to each host's memory is the point: the distinction is not
/// visible in a member's name, and calling one of these in the clear puts a
/// recovery phrase on the wire.
pub const CONFIDENTIAL_METHODS: &[&str] = &[
    methods::DERIVE_ACCOUNT,
    methods::EXPORT_KEY,
    methods::SIGN_MESSAGE,
    methods::SIGN_TRANSACTION,
];
