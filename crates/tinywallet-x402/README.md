# tinywallet-x402

The x402 machine-payment protocol (x402.org, v2) for `TinyWallet`. A server
answers a request with `402 Payment Required` and a `PAYMENT-REQUIRED` header;
the client pays, retries with `PAYMENT-SIGNATURE`, and reads `PAYMENT-RESPONSE`.
This crate is everything about that flow that is not specific to one host.

## Layout

| Module | Feature | Rail | What it holds |
| --- | --- | --- | --- |
| `wire` | `wire` (default) | neutral | Header payload types, CAIP-2 and asset constants, challenge selection. |
| `eip712`, `abi` | `eip712`, `abi` | crypto | EIP-712 / EIP-3009 hashing and ERC-20 `transfer` calldata. Pure hashing, no signer. |
| `ledger` | `ledger` | neutral | `PaymentRecord`, `SpendingBudget`, the append-only JSONL `PaymentLedger`, budget `Reservation`s (`reserve`), and the process-wide handle (`init_global`, `with_ledger`, `with_ledger_mut`). Imports no chain type. |
| `thread` | `ledger` | neutral | The `ThreadScope` seam (which conversation thread is running this call) and its `NoThread` default. |
| `protocol` | `pay` | neutral | Header codec, `X402Error`, `X402Client`, `handle_402`, `handle_402_and_pay`, and the `PaymentBuilder` and `ProxyPolicy` seams. |
| `crypto` | `pay` | crypto | `CryptoPayments` (the `PaymentBuilder` for the crypto rail), EVM EIP-3009 and Solana SPL payment construction, and the `PaymentSigner` seam. |
| `tools` | `tools` | neutral | `X402RequestTool`, the `x402_request` agent tool (`tinytools::Tool`). |

The neutral half (`ledger`, `protocol`) never names a chain, a key or a
signature, so another payment rail can reuse it by implementing
`PaymentBuilder`. `crypto` is the only module that knows about chains.

## Seams

The host implements these traits; the crate holds no wallet, endpoint or proxy
configuration of its own.

- `crypto::PaymentSigner`: `account(chain)` returns an address, and
  `sign(chain, bytes, scheme)` returns a signature (`Ed25519`, or
  `Secp256k1Digest` as `r || s || recovery_id`). **A key or mnemonic never
  enters this crate.**
- `tinywallet_crypto::rpc::Transport`: reads the Solana blockhash.
- `protocol::ProxyPolicy`: applies the host's proxy rules to a
  `reqwest::ClientBuilder`.
- `thread::ThreadScope` (optional): `current_thread()` names the conversation
  thread (chat thread, job) running the tool call. It is synchronous and is
  called on the tool's own task, so a host can answer from a task-local. Install
  it with `X402RequestTool::with_thread_scope`; the default, `NoThread`, reports
  none.

## Payment safety

- **Budget reservation.** `handle_402_and_pay` checks the daily and monthly caps
  and holds the amount (`ledger::reserve`) in one critical section *before*
  signing, so concurrent payments cannot together overspend. The hold is a
  `Reservation` on `X402PaymentResult::reservation`: `commit(record)` records the
  outcome and ends the hold in one step; dropping it releases the hold. A hold
  counts toward the caps like a settled payment and is not persisted.
- **Allowlist.** Only USDC on the networks of `wire::SUPPORTED_USDC` (Solana
  mainnet and devnet, Base mainnet and Sepolia, Ethereum mainnet) is payable. An
  option outside it is skipped during selection; if nothing else is payable the
  payment fails with `UnsupportedNetwork` or `UnsupportedAsset` before anything
  is signed. `pay_challenge_header` applies the same check.
- **Replayable bodies.** `X402Client::try_paid_request` clones the request before
  sending it. If the body is a stream (`try_clone` is `None`), a 402 is answered
  with `NonReplayableBody` before the challenge is read or anything is signed.
  The paid retry is that clone plus `PAYMENT-SIGNATURE`.
- **Session and thread ids.** `PaymentRecord.session_id` is always the ledger's
  own session (`PaymentLedger::session_id()`), so `session_total` counts every
  payment the process made, tool payments included. `PaymentRecord.thread_id`
  (`Option`, omitted from the file when absent, so older ledgers still load) is
  the host's `ThreadScope::current_thread()`, for attribution.

## Changes in 0.6.1 / 0.7.0 (API)

- `X402PaymentResult` gains `reservation` and is no longer `Clone`, `PartialEq` or
  `Eq`.
- `X402Error` gains `NonReplayableBody`, `UnsupportedNetwork` and
  `UnsupportedAsset` (the enum is `non_exhaustive`).
- New: `ledger::{reserve, Reservation, ReservationId, BudgetRefusal}`,
  `PaymentLedger::{reserve, release, commit_reservation, reserved_atomic,
  session_id}`; `check_budget` now counts held reservations. `PaymentRecord`
  gains `thread_id: Option<String>` (serde default; struct literals need it).
- New: `wire::{check_usdc, AssetCheck, SUPPORTED_USDC}`; `thread::{ThreadScope,
  NoThread}`; `X402RequestTool::with_thread_scope`.
- `handle_402` and `X402Client` no longer select a requirement outside the
  allowlist. `PaymentRequired::best_exact_requirement` and its siblings still do
  not consult it.

## Constraints

- Not `bitcoin`, `k256` or `coins-*` in the normal dependency graph (CI guard).
- The ledger owns one process-wide handle; hosts choose the budget when they
  call `ledger::init_global`.
- `tools` needs a compiler new enough for `tinytools` (1.88). The other features
  build on the crate's MSRV, except that `pay` pulls `reqwest`, whose `icu`
  dependencies need a newer compiler than 1.85 with a current lockfile.
- Error strings are user-visible and pinned by tests.
