//! Transfer descriptions that are shared by the wire contract and the
//! transaction verifiers.
//!
//! [`TronTransfer`] lives here, and not next to the other wire types, because
//! `tx::tron` verifies against it while `tinywallet-bus` embeds it in a
//! request. Defining it in the bus would make this crate depend on the bus,
//! which depends on this crate. `tinywallet_bus::wire::TronTransfer` re-exports
//! it, so the path hosts already use is unchanged.

mod types;

pub use types::TronTransfer;
