# Storage collection consumer proof

This directory is excluded from the TinyWallet workspace and has its own lock
file. It compiles the public `tinywallet_bus::storage::collections()` API from
a downstream crate using the bus-owned collection declaration, without a
TinyStorageDrivers dependency. The CI job runs this consumer with Rust 1.88
and `--locked`.
