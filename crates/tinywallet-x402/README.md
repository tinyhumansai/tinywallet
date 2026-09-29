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
| `ledger` | `ledger` | neutral | `PaymentRecord`, `SpendingBudget`, the append-only JSONL `PaymentLedger`, and the process-wide handle (`init_global`, `with_ledger`, `with_ledger_mut`). Imports no chain type. |
| `protocol` | `pay` | neutral | Header codec, `X402Error`, `X402Client`, `handle_402`, `handle_402_and_pay`, and the `PaymentBuilder` and `ProxyPolicy` seams. |
| `crypto` | `pay` | crypto | `CryptoPayments` (the `PaymentBuilder` for the crypto rail), EVM EIP-3009 and Solana SPL payment construction, and the `PaymentSigner` seam. |
| `tools` | `tools` | neutral | `X402RequestTool`, the `x402_request` agent tool (`tinytools::Tool`). |

The neutral half (`ledger`, `protocol`) never names a chain, a key or a
signature, so another payment rail can reuse it by implementing
`PaymentBuilder`. `crypto` is the only module that knows about chains.

## Seams

The host implements three traits; the crate holds no wallet, endpoint or proxy
configuration of its own.

- `crypto::PaymentSigner`: `account(chain)` returns an address, and
  `sign(chain, bytes, scheme)` returns a signature (`Ed25519`, or
  `Secp256k1Digest` as `r || s || recovery_id`). **A key or mnemonic never
  enters this crate.**
- `tinywallet_crypto::rpc::Transport`: reads the Solana blockhash.
- `protocol::ProxyPolicy`: applies the host's proxy rules to a
  `reqwest::ClientBuilder`.

## Constraints

- Not `bitcoin`, `k256` or `coins-*` in the normal dependency graph (CI guard).
- The ledger owns one process-wide handle; hosts choose the budget when they
  call `ledger::init_global`.
- `tools` needs a compiler new enough for `tinytools` (1.88). The other features
  build on the crate's MSRV, except that `pay` pulls `reqwest`, whose `icu`
  dependencies need a newer compiler than 1.85 with a current lockfile.
- Error strings are user-visible and pinned by tests.
