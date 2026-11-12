//! Permit2 `upto` authorizations, and the EIP-2612 `Permit` that lets a
//! facilitator approve Permit2 on the payer's behalf.
//!
//! The x402 `upto` scheme signs a Permit2 `PermitWitnessTransferFrom` whose
//! spender is the `x402UptoPermit2Proxy`. Its witness binds the recipient, the
//! one facilitator allowed to settle, and the start of the validity window, so
//! the proxy can move any amount up to `permitted.amount`, to that recipient
//! only, and only when that facilitator submits it.
//!
//! The type strings are those of the x402 reference client
//! (`uptoPermit2WitnessTypes` and `eip2612PermitTypes`); EIP-712 appends the
//! referenced struct types, sorted by name, to the primary type.

use super::{Address20, U256Bytes, keccak, left_pad_address, u256_from_u64};

/// The canonical Permit2 contract, at the same address on every EVM chain.
pub const PERMIT2: Address20 = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0xd4, 0x73, 0x03, 0x0f, 0x11, 0x6d, 0xde, 0xe9, 0xf6, 0xb4,
    0x3a, 0xc7, 0x8b, 0xa3,
];

/// The `x402UptoPermit2Proxy`, the spender of every `upto` authorization. It
/// is deployed with CREATE2 to the same address on every supported chain.
pub const UPTO_PERMIT2_PROXY: Address20 = [
    0x40, 0x20, 0xa4, 0xf3, 0xb7, 0xb9, 0x0c, 0xca, 0x42, 0x3b, 0x9f, 0xab, 0xcc, 0x0c, 0xe5, 0x7c,
    0x6c, 0x24, 0x00, 0x02,
];

/// Permit2's EIP-712 domain has a name but no version.
const PERMIT2_DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,uint256 chainId,address verifyingContract)";

/// Permit2's `TokenPermissions` struct.
pub(super) const TOKEN_PERMISSIONS_TYPE: &[u8] = b"TokenPermissions(address token,uint256 amount)";

/// The `upto` witness struct.
const WITNESS_TYPE: &[u8] = b"Witness(address to,address facilitator,uint256 validAfter)";

/// The primary type with its referenced types appended in name order.
const PERMIT_WITNESS_TRANSFER_FROM_TYPE: &[u8] = b"PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,Witness witness)TokenPermissions(address token,uint256 amount)Witness(address to,address facilitator,uint256 validAfter)";

/// The EIP-2612 `Permit` struct.
pub(super) const PERMIT_TYPE: &[u8] =
    b"Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)";

/// The domain separator of the canonical Permit2 contract on `chain_id`.
#[must_use]
pub fn permit2_domain_separator(chain_id: u64) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(4 * 32);
    encoded.extend_from_slice(&keccak(PERMIT2_DOMAIN_TYPE));
    encoded.extend_from_slice(&keccak(b"Permit2"));
    encoded.extend_from_slice(&u256_from_u64(chain_id));
    encoded.extend_from_slice(&left_pad_address(PERMIT2));
    keccak(&encoded)
}

/// A Permit2 `PermitWitnessTransferFrom` carrying the x402 `upto` witness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UptoPermit {
    /// The token the proxy may move (`permitted.token`).
    pub token: Address20,
    /// The most the proxy may move (`permitted.amount`).
    pub amount: U256Bytes,
    /// Who may call Permit2 with this permit: [`UPTO_PERMIT2_PROXY`].
    pub spender: Address20,
    /// Permit2's unordered nonce; any unused value.
    pub nonce: U256Bytes,
    /// Unix time after which the permit is void.
    pub deadline: U256Bytes,
    /// The only recipient the proxy may pay (`witness.to`).
    pub to: Address20,
    /// The only facilitator that may settle (`witness.facilitator`).
    pub facilitator: Address20,
    /// Unix time before which the permit is not yet valid
    /// (`witness.validAfter`).
    pub valid_after: U256Bytes,
}

impl UptoPermit {
    /// The EIP-712 struct hash, to be combined with
    /// [`permit2_domain_separator`] by [`signing_digest`](super::signing_digest).
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut permitted = Vec::with_capacity(3 * 32);
        permitted.extend_from_slice(&keccak(TOKEN_PERMISSIONS_TYPE));
        permitted.extend_from_slice(&left_pad_address(self.token));
        permitted.extend_from_slice(&self.amount);

        let mut witness = Vec::with_capacity(4 * 32);
        witness.extend_from_slice(&keccak(WITNESS_TYPE));
        witness.extend_from_slice(&left_pad_address(self.to));
        witness.extend_from_slice(&left_pad_address(self.facilitator));
        witness.extend_from_slice(&self.valid_after);

        let mut encoded = Vec::with_capacity(6 * 32);
        encoded.extend_from_slice(&keccak(PERMIT_WITNESS_TRANSFER_FROM_TYPE));
        encoded.extend_from_slice(&keccak(&permitted));
        encoded.extend_from_slice(&left_pad_address(self.spender));
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.deadline);
        encoded.extend_from_slice(&keccak(&witness));
        keccak(&encoded)
    }
}

/// An EIP-2612 `Permit`: the token holder approves `spender` without a
/// transaction. Hash it under the token's own domain
/// ([`domain_separator`](super::domain_separator)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eip2612Permit {
    /// The token holder.
    pub owner: Address20,
    /// The approved spender: [`PERMIT2`] for x402 gas sponsoring.
    pub spender: Address20,
    /// The allowance granted.
    pub value: U256Bytes,
    /// The holder's current `nonces(owner)` on the token.
    pub nonce: U256Bytes,
    /// Unix time after which the permit is void.
    pub deadline: U256Bytes,
}

impl Eip2612Permit {
    /// The EIP-712 struct hash.
    #[must_use]
    pub fn struct_hash(&self) -> [u8; 32] {
        let mut encoded = Vec::with_capacity(6 * 32);
        encoded.extend_from_slice(&keccak(PERMIT_TYPE));
        encoded.extend_from_slice(&left_pad_address(self.owner));
        encoded.extend_from_slice(&left_pad_address(self.spender));
        encoded.extend_from_slice(&self.value);
        encoded.extend_from_slice(&self.nonce);
        encoded.extend_from_slice(&self.deadline);
        keccak(&encoded)
    }
}

#[cfg(test)]
#[path = "permit2_tests.rs"]
mod tests;
