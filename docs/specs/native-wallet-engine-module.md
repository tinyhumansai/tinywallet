# Native Wallet engine in the TinyWallet module

Status: Accepted implementation specification

## Goal

Move OpenHuman's remaining native wallet execution surface into the
TinyWallet implementation while keeping key custody, endpoint credentials,
host policy, and authenticated transport in the host. The wallet implementation
owns validation, catalogs, quote state, transaction construction, signing,
broadcast, and transaction parsing for EVM, Bitcoin, Solana, and Tron.

The existing TinyWallet bus contract remains compatible. Existing 20 module
members, five host callbacks, and every existing member arity remain unchanged.
New native operations and the native service lifecycle are additive typed
members. Existing stateless signing/address operations continue to work if the
optional host callback peer is absent or incompatible.

## Operations

The native service exposes the current engine surface through typed requests:

- configure and close one opaque, host-owned-user-scoped service handle;
- list network defaults and supported assets;
- query chain readiness and native balances;
- query catalogued token balances (SPL mints on Solana; contract 1.15);
- prepare and execute a transfer;
- read transaction status, receipt, and raw transaction by chain and hash.

The nine query/transfer/transaction operations each take one typed request.
Every operation validates the handle. Transfer preparation carries the
conversation owner, if any. Execution requires `confirmed: true`, validates
the owner before requesting approval, and signs only after host authorization.
Quote consumption remains atomic; a failed signing or broadcast restores the
quote with a refreshed expiry. Closing or replacing a service waits
for in-flight calls, invalidates the prior handle, and drops its quote store.

The module uses its existing wallet engine algorithms and DTOs. Shared wire
DTOs and enums live in `tinywallet-bus`; implementation crates re-export them
for source compatibility. The contract crate remains free of crypto and chain
implementation dependencies. The bus carries concrete operation DTOs rather
than a generic algorithm-dispatch payload.

## Host boundary

The optional host callback peer supplies only:

- current public wallet account facts;
- chain transport, with URL resolution, credentials, proxy policy, and pooling
  kept host-side;
- exact native transfer approval for EVM, Bitcoin, Solana, and Tron.

The native approval intent is derived from the stored module quote and the
actual transaction being signed. It includes the quote identity and precise
chain-specific destination, asset, amount, fee, and unsigned transaction facts
needed by host policy. The callback returns an authorization decision; it never
returns a signature or transaction. Secret material is delivered only through
the existing confidential, attested-module call, is consumed by module-side
signing, and is zeroized after use. Missing or incompatible native callbacks
make callback-backed native operations explicitly unavailable; there is no
host-side algorithm fallback.

## Endpoints and reference data

The host continues to resolve `OPENHUMAN_WALLET_RPC_*` endpoint overrides and
`OPENHUMAN_SOLANA_CLUSTER`. The native configure request gives the module the
typed Solana cluster and which endpoint keys have overrides, but never sends
endpoint URLs or credentials. The module's endpoint seam emits stable opaque
host endpoint references for overridden networks. Chain transport requests
carry those references, and the host resolves them against the configured
endpoint set. Reference data, Solana mint/explorer selection, transaction
parsing, and default endpoint selection stay in the implementation crate.

For the existing `network_defaults` response, the host mechanically projects
the configured URL into the RPC URL field from the opaque endpoint reference.
The module-to-host frame contains only the reference, never a credentialized
URL. Default endpoints and source labels retain their current behavior.

Opaque endpoint references are scoped to the native service handle/config
epoch. Closing or replacing that service invalidates both its handles and
endpoint references, so a callback from an old user cannot resolve against a
new user's endpoint configuration.

## Verification

Tests cover contract serialization and method inventory, exact preservation of
the old member/callback inventory and arities, configure/close and stale-handle
behavior, owner isolation, all four chain authorization intents, and the
endpoint mapping/projection without putting a credentialized URL in a bus
frame. A local compiled-module fixture proves callback round trips and
fail-closed behavior when the optional callback is absent or incompatible.
Existing native execution fixtures continue to cover chain algorithms and
transaction bytes. No test calls a real network or performs real signing with
external credentials.
