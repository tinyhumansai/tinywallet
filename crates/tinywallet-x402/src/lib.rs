//! The x402 machine-payment protocol for `TinyWallet`.
//!
//! This crate owns the parts of x402 that are the same for every host:
//!
//! - [`wire`] — the v2 header payloads and the rules for reading them.
//! - [`eip712`] — EIP-712 typed-data hashing and the EIP-3009 authorization
//!   x402 signs. Nothing here signs; it returns the bytes to sign.
//! - [`abi`] — ERC-20 `transfer` calldata.
//!
//! It depends on `tinywallet-crypto` and never on `tinywallet-bus`, so the bus
//! can re-export from here without a cycle. Payment execution, the spending
//! ledger and the agent tools are not here yet; they will join as further
//! modules and features (`ledger`, `protocol`, `crypto::*`, `tools`) in a
//! follow-up. Rail-neutral code (ledger, protocol) will stay apart from the
//! crypto-specific code so another payment rail can share it later.
//!
//! # Feature flags
//!
//! | Feature | Default | Gates |
//! | --- | --- | --- |
//! | `wire` | on | the x402 header payload types ([`wire`]) |
//! | `eip712` | off | EIP-712 hashing ([`eip712`]) |
//! | `abi` | off | ERC-20 `transfer` calldata ([`abi`]) |

#[cfg(feature = "abi")]
pub mod abi;
#[cfg(feature = "eip712")]
pub mod eip712;
#[cfg(feature = "wire")]
pub mod wire;
