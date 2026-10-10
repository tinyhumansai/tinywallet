//! Compatibility re-export of the serialized chain vocabulary.
pub use tinywallet_bus::chain::{Chain, UnknownChain};
#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
