//! The transfer shapes a node-built transaction is verified against.

/// Transfer-specific verification for a node-built Tron transaction.
///
/// With the `serde` feature the JSON form is internally tagged by `kind` in
/// `snake_case` and rejects unknown fields, which is the exact encoding the
/// `tinywallet-bus` wire contract has always used for it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)
)]
pub enum TronTransfer {
    /// A native TRX transfer; the amount is encoded as a protobuf varint.
    Native {
        /// Requested amount in sun.
        amount_sun: u64,
    },
    /// A TRC20 transfer; the ABI parameter binds both recipient and amount.
    Trc20 {
        /// Unprefixed ABI-encoded transfer arguments.
        parameter_hex: String,
    },
}
