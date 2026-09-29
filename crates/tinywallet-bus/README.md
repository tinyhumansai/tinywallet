# tinywallet-bus

The TinyBus wire contract for TinyWallet: the bus name and object path, the
member names, the request and response types (`wire`), and the contract version
rule. It links no chain, signing or key-derivation library.

## Compat re-exports

Before 0.6 this crate also held the chain rules. They moved:

| Old path | Now in |
| --- | --- |
| `address`, `asset`, `chain`, `rpc`, `tx`, `Chain`, `Error`, `Result` | `tinywallet-crypto` |
| `eip712`, `abi` | `tinywallet-x402` (features `eip712`, `abi`) |
| `wire::TronTransfer` | `tinywallet-crypto::TronTransfer` |

The old paths still resolve through re-exports so existing hosts keep compiling.
**They are compat re-exports and are removed in the next minor release.** Depend
on the owning crate directly. The feature names are unchanged and forward to the
owner. This crate takes `tinywallet-x402` with default features off, so it can
never enable anything heavier than `eip712` and `abi`.
