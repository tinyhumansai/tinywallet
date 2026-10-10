//! Stateless EVM construction requests and exact host approval facts.
use super::{PublicKey, TransactionSpec, UnsignedTransaction};
use serde::{Deserialize, Serialize};

/// Maximum JSON request bytes admitted by transaction construction.
pub const MAX_CONSTRUCTION_BYTES: usize = 65_536;
/// Maximum contract calldata bytes admitted by transaction construction.
pub const MAX_CALLDATA_BYTES: usize = 16_384;

/// The intended EVM action. Encoding and validation execute inside the module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum EvmIntent {
    /// Send native currency without calldata.
    NativeTransfer {
        /// Recipient address.
        to: String,
        /// Positive amount in wei, base ten.
        amount_wei: String,
    },
    /// ERC-20 transfer encoded by the module, including full uint256 amounts.
    Erc20Transfer {
        /// Token contract.
        token: String,
        /// Token recipient.
        to: String,
        /// Positive base-ten token amount in smallest units.
        amount_raw: String,
    },
    /// Explicit contract call. The host reviews the exact calldata, without guessed semantics.
    ContractCall {
        /// Contract address.
        to: String,
        /// Native value in wei.
        value_wei: String,
        /// Byte-aligned hexadecimal calldata, optionally 0x-prefixed.
        data_hex: String,
    },
}

/// Public construction input; RPC resolution and approval are separate operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmConstructionRequest {
    /// Sender's compressed SEC1 public key; contains no secret material.
    pub public_key: PublicKey,
    /// EIP-155 network identifier.
    pub chain_id: u64,
    /// Resolved sender nonce.
    pub nonce: u64,
    /// Maximum gas units.
    pub gas_limit: u64,
    /// Gas price in wei, base ten.
    pub gas_price_wei: String,
    /// Action to encode.
    pub intent: EvmIntent,
}

/// Exact facts bound to the returned transaction for a host's approval decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvmApprovalFacts {
    /// Sender derived from the validated public key.
    pub sender: String,
    /// EIP-155 network identifier.
    pub chain_id: u64,
    /// Sender nonce.
    pub nonce: u64,
    /// Maximum gas units.
    pub gas_limit: u64,
    /// Canonical decimal gas price.
    pub gas_price_wei: String,
    /// Maximum gas cost, gas limit times gas price.
    pub max_fee_wei: String,
    /// Native transaction value plus maximum gas cost.
    pub max_native_debit_wei: String,
    /// Native value encoded in the transaction.
    pub native_value_wei: String,
    /// The native or token recipient, or explicit contract target.
    pub recipient: String,
    /// Token contract for ERC-20; absent otherwise.
    pub token_contract: Option<String>,
    /// Canonical full uint256 token amount for ERC-20; absent otherwise.
    pub token_amount_raw: Option<String>,
    /// Exact canonical calldata encoded in the transaction.
    pub calldata_hex: String,
}

/// Encoded transaction, its signing payload and approval facts; no state or secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConstructedEvmTransaction {
    /// The exact fields to pass to existing confidential signing or split signing.
    pub transaction: TransactionSpec,
    /// Payload computed over these exact fields.
    pub unsigned: UnsignedTransaction,
    /// Facts for the host to approve before signing.
    pub approval: EvmApprovalFacts,
}

#[cfg(test)]
#[path = "construction_tests.rs"]
mod tests;
