//! Agent tools over the wallet engine and the swap/bridge/dapp service.
//!
//! Each tool holds an `Arc` of the engine or service it drives, so a host
//! builds the instances once and registers the boxed tools. All of them are
//! [`ToolExposure::Deferred`](tinytools::ToolExposure::Deferred): they are
//! discovered on demand rather than listed in every prompt.
//!
//! - [`wallet`] — status, chain status, prepare a transfer, and the three
//!   transaction lookups.
//! - [`web3`] — swap, bridge and dapp quote/execute tools.
//!
//! Host-side name gating and approvals stay in the host; these tools only turn
//! calls into engine operations and results into text.

pub mod wallet;
pub mod web3;
