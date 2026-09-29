//! Swap, bridge and dapp tools: `web3_swap_quote`, `web3_swap_execute`,
//! `web3_swap_routes`, `web3_bridge_quote`, `web3_bridge_execute`,
//! `web3_dapp_call` and `web3_dapp_execute`.
//!
//! These call the backend per invocation, so they error gracefully (rather than
//! being hidden) when the user is not signed in.

mod bridge;
mod dapp;
mod swap;

pub use bridge::{Web3BridgeExecuteTool, Web3BridgeQuoteTool};
pub use dapp::{Web3DappCallTool, Web3DappExecuteTool};
pub use swap::{Web3SwapExecuteTool, Web3SwapQuoteTool, Web3SwapRoutesTool};

#[cfg(test)]
mod test;
