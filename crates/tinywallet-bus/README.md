# tinywallet-bus

The minimal TinyBus contract for TinyWallet: names, version, shared chain
identifiers, error vocabulary, transfer types and request/result DTOs. Normal
and build dependencies are limited to serde and thiserror plus their derive
closure. No feature links crypto, x402, web3, transport or native libraries.

Contract 1.1 adds `ValidateAddress`. It returns the trimmed address or the same
structured errors as the implementation, including Bitcoin's narrower sender
rule. Validation runs inside the compiled artifact. Existing transaction and
confidential signing operations retain their arities and wire forms.

The previous algorithm re-exports (`address`, `asset`, `rpc`, `tx`, `eip712`,
`abi`) are removed as promised for the next minor package release. Legacy
feature names remain accepted for transition, but they enable no behavior.
Implementations re-export `Chain`, `UnknownChain`, `Error`, `Result`, and
`TronTransfer` from this crate, preserving shared type identity and JSON forms.

Host integrations must use module calls and wait for a compatible released
artifact pinned with its verified digest. They must not replace the removed
re-exports with direct crypto/x402/web3 dependencies. Further web3, budget,
ledger and x402 execution members remain separate migration work.

Contract 1.2 adds stateless ConstructEvmTransaction for native/ERC-20/contract
actions, exact signing payloads and host approval facts. Secret fields are
rejected; fee/calldata/request bounds execute in the module. See
[construction specification](../../docs/specs/evm-module-construction.md).
