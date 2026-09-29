# Plan: web3 split

Specification: [`../specs/web3-split.md`](../specs/web3-split.md)

## Goal

Move chain rules out of `tinywallet-bus` into `tinywallet-crypto` and
`tinywallet-x402`, then (PR 2) move the wallet, swap, bridge, dapp and x402
logic from OpenHuman's `web3/` into this workspace behind seam traits.

## PR 1: structure only (this change)

No logic moves from OpenHuman. Tasks, in order:

1. `git mv` `chain`, `error`, `address/**`, `asset`, `rpc`, `tx/{mod,proto,tron}`
   and their `test.rs` files from `crates/tinywallet-bus/src` to
   `crates/tinywallet-crypto/src`. Add the `transfer` module holding
   `TronTransfer`, and re-export it from `bus::wire`.
2. `git mv` `eip712` and `abi` to `crates/tinywallet-x402/src`, and the root
   `src/x402` wire types to `crates/tinywallet-x402/src/wire`. The root
   `tinywallet::x402` re-exports them.
3. Slim the bus to `names`, `version`, `wire` and add doc-commented compat
   re-exports plus feature forwarding.
4. Point the root crate at all three crates and forward its gates.
5. Register both crates as workspace members and default members.
6. `release.yml`: add both `Cargo.toml` paths to `bump()` and the `git add` list.
   The sibling path dependencies carry no version requirement, so there is no
   pin to rewrite. The `cargo package` smoke test moves to `tinywallet-crypto`,
   the only crate with no path dependency.
7. `ci.yml`: add the no-`bitcoin`/`k256`/`coins-*` guard (with the root crate as
   a positive control), build the three libraries in the MSRV job, and document
   the whole workspace.
8. Docs: this plan, the spec, README, AGENTS and the bus README.

Verification: fmt, clippy (`-D warnings`, all features), tests with default and
all features, the 1.85 build, `cargo doc` with `-D warnings`, the module E2E, the
tree guard, and a compile of the host against the shimmed bus.

## PR 2: logic

1. Add `tinywallet-web3` and x402's `pay`, `ledger` and `tools`. Split into
   wallet, swap/bridge/dapp and x402 if it is too large to review.
2. Seams the host implements: `WalletSigner`, `WalletAccounts`, `RpcEndpoints`,
   `QuoteScope`, `Web3Backend` and `PaymentSigner`; `ProxyPolicy` for the x402
   HTTP client. State becomes instance-owned (`WalletEngine`, `Web3Service`).
3. Add `tinytools` as a workspace git dependency at the rev tinyagents pins, and
   allow that source in `deny.toml`.
4. Replace `is_multiple_of` with `%` for MSRV 1.85, split files over roughly 500
   lines, and clean up for pedantic clippy and `missing_docs`.
5. Move the tests to the `mod.rs`/`types.rs`/`test.rs` layout, replacing env and
   `set_var` fixtures with fakes (`forbid(unsafe)` rules out `set_var`).
6. Keep error strings byte-identical; the moved tests pin them.
7. Add the CI grep that keeps `quote/` and `ledger/` free of crypto types.

## Release and host

1. Release a minor version (0.6.0) after both PRs merge. The compat re-exports
   are removed in the release after that.
2. OpenHuman pins the new submodule commit, updates its module registry
   checksums from the published `checksum.toml`, adds path dependencies on the
   new crates, and replaces `web3/` with seam implementations.

## Checklist

- [x] PR 1 implemented
- [ ] PR 2 opened
- [ ] Minor release cut
- [ ] Compat re-exports removed
