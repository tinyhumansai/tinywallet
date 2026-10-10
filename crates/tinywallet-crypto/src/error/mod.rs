//! Compatibility re-export of shared error vocabulary.
pub use tinywallet_bus::{Error, Result};
#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
