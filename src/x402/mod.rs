//! The x402 machine-payment protocol (v2) wire types.
//!
//! The types live in [`tinywallet_x402::wire`]; this module re-exports them so
//! `tinywallet::x402::…` paths keep resolving. See that module for the protocol
//! description and the reasons amounts are decimal strings.

pub use tinywallet_x402::wire::*;
