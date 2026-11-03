# tinywallet-bus

The minimal TinyBus contract for TinyWallet: names, version, shared chain
identifiers, error vocabulary, transfer types, request/result DTOs, and the
x402 ledger's storage collection declarations and stored record vocabulary.
Collection declarations are bus-owned names, without a storage backend,
client, or transport dependency.

The bus contract supports Rust 1.88. The excluded collection-contract consumer
checks the public collection names without depending on a storage crate.

Network enums in the bus are identifiers only. RPC endpoints, explorer URLs,
Solana mint addresses, and display labels remain implementation-owned reference
data in `tinywallet-crypto`.

Contract 1.1 adds `ValidateAddress`. It returns the trimmed address or the same
structured errors as the implementation, including Bitcoin's narrower sender
rule. Validation runs inside the compiled artifact. Existing transaction and
confidential signing operations retain their arities and wire forms.

The previous algorithm re-exports (`address`, `asset`, `rpc`, `tx`, `eip712`,
`abi`) are removed as promised for the next minor package release. Legacy
feature names remain accepted for transition, but they enable no behavior.
This is a source API break for the pre-1.0 bus crate; the release workflow must
use a minor package bump before hosts adopt it. The compatibility promise below
applies to shared vocabulary identity and its wire forms, not removed algorithm
imports. Implementations re-export `Chain`, `UnknownChain`, `Error`, `Result`, and
`TronTransfer` from this crate, preserving shared type identity and JSON forms.

Host integrations must use module calls and wait for a compatible released
artifact pinned with its verified digest. They must not replace the removed
re-exports with direct crypto/x402/web3 dependencies. The optional Host
interface in contract 1.4 exposes typed account, custody, approval, transport,
and backend callbacks; it does not move quote, payment, budget, or ledger
algorithms into the host. Web3 and x402 services are opened explicitly after
host account/workspace policy is ready and return opaque module-scoped handles.
Reconfiguration and close wait for in-flight operations, discard old quotes or
pending reservations, and invalidate old handles. Secret-bearing calls are
confidential and require an attested artifact.

Contract 1.5 adds the module-owned native WalletEngine service for endpoint
defaults, chain status, balances, transfer quotes and transaction lookups, plus
the exact-signing authorization callback. Host endpoint overrides cross the
transport callback as opaque service-scoped references; URLs remain in host
custody. The pure `tools` module also owns the static names, descriptions and
argument schemas for all six wallet, seven Web3 and one x402 tools. The
implementation crates keep their `tinytools::Tool` adapters and delegate those
declarations here. A pre-move fixture pins the established tool JSON.

Contract 1.7 adds `Web3ConfigureWithEndpoints` alongside the unchanged
`Web3Configure(())` member. Hosts that need configured RPC overrides pass the
Solana cluster and overridden endpoint keys, never endpoint URLs. The module
returns opaque service-scoped references for those keys and includes them in
chain transport requests; the host resolves each reference against its private
endpoint configuration. The configured service keeps cluster-dependent
reference data inside the implementation.

Contract 1.8 adds an optional public `endpoint_url` to chain transport
requests only when the module selected its default endpoint. Requests for a
host-configured endpoint continue to carry only the opaque `endpoint_ref`.
The optional field is omitted when absent, so existing override payloads keep
their serialized shape. The host still owns generic URL safety checks and
authenticated transport; it does not select or infer module defaults.

Contract 1.9 adds confidential `GenerateMnemonic(word_count)`. The module
generates BIP-39 entropy and returns the phrase for the host to encrypt and
store; the host remains responsible for custody and persistence.

Contract 1.10 adds confidential `DeriveMnemonicSeed(mnemonic)` for hosts that
must preserve an existing mnemonic-derived storage-key KDF. The wallet module
validates the phrase and derives the standard 64-byte BIP-39 seed; the host
continues to apply its own storage-key KDF and custody policy.

Contract 1.2 adds stateless ConstructEvmTransaction for native/ERC-20/contract
actions, exact signing payloads and host approval facts. Secret fields are
rejected; fee/calldata/request bounds execute in the module. See
[construction specification](../../docs/specs/evm-module-construction.md).

Contract 1.12 adds optional `additional_secrets` to confidential
`X402PreparePayment`. When omitted or empty, the request keeps its prior JSON
shape. The module parses the challenge, selects the payment chain, and uses
only the matching confidential secret; hosts do not parse payment challenges.

The bus exposes `storage::collections()` for the host's wallet storage grant.
The declarations include the current `wallet.budgets` and
`wallet.migrations` collections. Migration behavior and the payment stream
remain owned by the x402 ledger implementation.
