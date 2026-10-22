# Storage-needs consumer proof

This directory is excluded from the TinyWallet workspace and has its own lock
file. It compiles the public `tinywallet-bus::storage_needs()` API from a
downstream crate and names TinyWallet's host-facing declaration type directly.
TinyStorageDrivers v2 no longer defines an aggregate `StorageNeeds` type, so
the declaration belongs to the module contract while its collection schema
continues to use the canonical TSD type. The CI job runs this consumer with
Rust 1.85 and `--locked`.
