# Splitting `tinywallet-bus` into contract, crypto and x402 crates

Status: Historical split specification. The contract dependency and compatibility
shim rules below are superseded by [minimal bus contracts](minimal-bus-contract.md).

## Problem

`tinywallet-bus` was meant to be the TinyBus contract, but it also carried chain
code: addresses, reference data, the `rpc::Transport` seam, the Tron verifier,
EIP-712 and ABI encoding. Meanwhile about 14.6k lines of wallet, x402, swap,
bridge and dapp logic live in the OpenHuman host (`crates/openhuman-core/src/web3/`)
even though nothing in them is specific to OpenHuman. The host cannot share that
code, and the bus name no longer describes what is in it.

## Goals

- Four focused crates in this workspace: `tinywallet-crypto`, `tinywallet-x402`,
  `tinywallet-web3` (PR 2) and a contract-only `tinywallet-bus`.
- Every existing public path keeps working for one release through re-exports.
- No host-linked crate ever links `bitcoin`, `k256` or `coins-*`.
- A layout that leaves room for a second payment rail (`tinywallet-card`).

## Non-goals

- Changing the wire contract: `CONTRACT_VERSION` stays `(1, 0)`.
- Moving key custody. Keys stay in the host, and signing stays in the module.
- New repositories. Everything lives in this workspace.

## Crate graph

```text
tinywallet-crypto   chain, error, address/*, asset, rpc::Transport,
  ^                 tx::{proto,tron}, TronTransfer
  |
tinywallet-x402     -> crypto        wire, eip712, abi   (PR 2: ledger, protocol,
  ^                                   crypto::*, tools)
  |
tinywallet-bus      -> crypto, x402[eip712,abi]   names, version, wire + compat shims
  ^
tinywallet-web3     -> crypto, bus(wire)   (PR 2) wallet, swap, bridge, dapp + tools
tinywallet (root)   -> bus, crypto, x402   key/, tx/, client/ (only place `bitcoin` lives)
tinywallet-module   unchanged behaviour
```

Rules:

- `Chain`, `Error` and `TronTransfer` live in crypto so the graph has no cycle.
  `TronTransfer` used to sit in `bus::wire`, but `tx::tron` needs it, so it moved
  down and `bus::wire::TronTransfer` re-exports it. Its JSON form is unchanged.
- x402 depends on crypto and never on the bus or web3.
- The bus takes x402 with `default-features = false`, so it can enable only
  `eip712` and `abi`. It must never enable anything heavier, in particular the
  PR 2 `pay` feature.
- Crypto, x402 and the bus must not depend on `bitcoin`, `k256`, `coins-bip32`
  or `coins-bip39`. CI runs `cargo tree -e normal -i <dep> -p <crate>` for each
  and fails if any is found.

## Feature mapping

Bus features keep their names and forward to the owner, so a downstream
`features = [...]` list keeps working. OpenHuman uses `btc evm solana tron
keccak net wire eip712 abi tx-codec` with default features off.

| Bus feature | Forwards to |
| --- | --- |
| `btc`, `evm`, `solana`, `tron`, `keccak`, `net`, `asset` | `tinywallet-crypto/<same>` |
| `serde` | `tinywallet-crypto/serde` |
| `wire` | `serde` (and so `tinywallet-crypto/serde`) |
| `tx-codec` | `tinywallet-crypto/tx-codec`, `wire` |
| `eip712` | `tinywallet-x402/eip712` |
| `abi` | `eip712`, `tinywallet-x402/abi` |

`tinywallet-x402` features: `wire` (default), `eip712`, `abi`. `abi` enables
crypto's `evm` and `keccak`. The root crate forwards its own gates the same way;
`tinywallet::x402` re-exports `tinywallet_x402::wire`.

## Compat re-exports

`tinywallet-bus` re-exports `address`, `asset`, `chain`, `rpc`, `tx`, `Chain`,
`Error` and `Result` from crypto, `abi` and `eip712` from x402, and
`wire::TronTransfer`. Each is doc-commented as a compat re-export, removed in the
next minor release, and gated by the same feature as before. The crypto `error`
module was private in the bus, so only its `Error` and `Result` are re-exported.

## Rail-neutral layout

Code that is neutral about the payment rail stays apart from crypto-specific
code inside each crate, so a later `tinywallet-payments` crate below both
`crypto` and `card` is a file move plus re-exports.

- `tinywallet-x402` (PR 2): rail-neutral `ledger`, `protocol` and `ProxyPolicy`;
  crypto-specific `crypto::{eip712, abi, evm_payment, solana_payment, signer}`;
  and `tools`.
- `tinywallet-web3` (PR 2): rail-neutral `quote` and `seams` (`QuoteScope`);
  crypto-specific `crypto::{wallet, chains, execution, defaults, seams}`; and
  `tools`.
- Nothing rail-neutral goes into `tinywallet-crypto`. A CI grep over `quote/`, `seams/` and
  `ledger/` for `tinywallet_crypto|WalletChain|EvmNetwork` must match nothing.
- The signing seams are deliberately not generalized: a card rail authorizes
  rather than signing bytes.

## Acceptance criteria

- `cargo test --workspace` passes with default and all features.
- Clippy, rustfmt, rustdoc (`-D warnings`) and the 1.85 MSRV build pass.
- `tinywallet-module`'s E2E asserts byte-identical signing.
- The no-`bitcoin` guard passes for the three host-linked crates.
- OpenHuman still compiles against the shimmed bus with its current feature list.

## Open questions

- Whether PR 2 is split into wallet, swap-bridge-dapp and x402 for review size.
