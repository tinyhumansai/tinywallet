# tinywallet-web3

The wallet, swap, bridge and dapp flows of TinyWallet, behind host seams. It is
the logic that used to live inside the OpenHuman host, moved here so any host
can use it.

It holds no key, no HTTP client and no configuration. A host implements the
seams and builds a `WalletEngine` (and a `Web3Service` over it); everything
else is in the crate.

## Layout

```text
src/
├── quote/            rail-neutral: QuoteStore<T> (TTL, capacity, owner-gated take),
│                     QuoteOwner, Quoted, WALLET_NOT_CONFIGURED_MESSAGE,
│                     execute_tool_schema, to_tool_result (feature `tools`)
├── seams/            rail-neutral: QuoteScope (sync `current_owner`)
├── crypto/           the crypto rail
│   ├── wallet/       WalletEngine, WalletSeams, WalletChain, WalletStatus
│   ├── execution/    balances, prepare/execute transfer, tx lookups (engine methods)
│   ├── chains/       btc / evm / solana / tron choreography (private)
│   ├── service/      Web3Service: swap, bridge, dapp calls
│   ├── defaults/     static networks, assets, explorer links
│   ├── abi/          ERC-20 calldata wrapper
│   └── seams/        WalletSigner, WalletAccounts, RpcEndpoints, Web3Backend
├── tools/            agent tools (feature `tools`)
└── test_support/     fakes for every seam (tests only)
```

`quote/` and `seams/` name no chain; CI greps them for
`tinywallet_crypto|WalletChain|EvmNetwork`. That is what keeps a future card
rail able to reuse them.

## Seams

| Seam | The host owns |
| --- | --- |
| `Transport` (from `tinywallet-crypto`) | reaching a chain: endpoints, failover, log redaction |
| `WalletSigner` | keys: `derive_account`, `sign_transaction`, `sign_message` |
| `WalletAccounts` | whether a wallet is set up, and its accounts |
| `RpcEndpoints` | which endpoint serves a chain, and the Solana cluster |
| `Web3Backend` | the hosted swap/bridge quote service |
| `QuoteScope` | which chat thread is asking |

Errors are plain `String`s and are surfaced verbatim: the wording a model reads
to correct itself is the host's to choose. Transport messages are passed through
untouched, because some are matched on (`status=404` decides "not found" for
Esplora).

## Confirm-then-execute

Every write is prepared first, then confirmed. A quote is bound to the chat
thread that prepared it and expires after five minutes. `execute` removes it
before acting, so two concurrent confirmations cannot double-submit, and puts it
back with a fresh lifetime if signing or broadcast fails. A caller of the wrong
thread gets exactly the not-found text, so a leaked quote id gives no oracle.

## Features

| Feature | Default | Gates |
| --- | --- | --- |
| `tools` | off | the agent tools, and `quote::to_tool_result` |

`tools` pulls in `tinytools`, which needs a newer compiler than the rest of the
crate, so the MSRV job builds without it.

## Testing

Tests sit beside the code in `test.rs` and drive the real engine against fakes:
canned chain answers with a call log, a signer backed by the real derivation of
the standard test mnemonic, and scripted accounts, endpoints, scope and backend.
There are no environment variables, sockets or globals in them.
