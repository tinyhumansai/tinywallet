# Minimal wallet bus contract

The loadable module is the execution boundary. The bus crate owns serialized
identifiers, errors, transfer targets, method declarations and wire DTOs only.
It depends on serde and thiserror, with no implementation dependency under any
feature. Crypto re-exports those shared types and owns validation, hashing,
encoding and transaction verification. x402 and web3 retain their algorithms.

This reverses the old compatibility-shim edge: crypto depends on bus; bus never
depends on crypto or x402. Existing shared vocabulary and transaction JSON are
unchanged. Removed algorithm re-exports require the next minor package release;
legacy feature names are accepted but do not enable implementation code.

Contract 1.1 adds ValidateAddress with a typed request and result. Successful
validation returns the trimmed address and cannot establish ownership, balance
or funding. The Bitcoin sender flag applies the existing P2WPKH restriction.
Validation faults retain the existing error taxonomy and detail for product
presentation. They must never be copied into sanitized module-failure telemetry.
Existing members retain their arities, confidentiality and wire representations.

Hosts retain credentials and approval policy. They may adopt this contract only
with a compatible published module artifact and verified digest. Remaining web3,
quotes, swaps, x402 payment execution, budgets and ledger operations must be
added inside the module before their corresponding host implementations are cut.
