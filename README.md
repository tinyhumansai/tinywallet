# TinyWallet

Agent-friendly multi-chain wallet primitives in Rust.

`tinywallet` owns the parts of wallet handling that are pure: address formats,
their validation, and the conversions between their encodings. Bitcoin, EVM
chains, Solana, and Tron each get a module, and `address::validate` dispatches
across them for chain-generic callers.

```rust
use tinywallet::{address, Chain};

// Chain-generic dispatch.
let addr = address::validate(Chain::Btc, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?;

// Or reach for a chain's own module when you need more than validation.
let hex = address::tron::to_hex("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t")?;
assert!(hex.starts_with("41"));
# Ok::<(), tinywallet::Error>(())
```

## What it does not do

No network access, no RPC endpoints, no key storage, no transaction
broadcasting. Every function here is a deterministic pure function of its
arguments.

That is the seam, not a gap. Endpoint selection, retry policy, and key custody
depend on a host's config, threat model, and runtime — a crate that guessed at
any of them would be wrong for every host that guessed differently. What is
left is the part that is genuinely the same everywhere.

## What validation proves, per chain

Validation answers one question: is this string a well-formed address on this
chain. How much that is worth varies sharply, and it is worth being explicit
because it is easy to assume otherwise:

| Chain | Checksum | A single typo is… |
| --- | --- | --- |
| Bitcoin | yes (base58check / bech32) | caught |
| Tron | yes (base58check) | caught |
| EVM | optional (EIP-55, only if mixed-case) | usually **not** caught |
| Solana | none | **not reliably** caught |

For EVM, `address::evm::is_checksum_valid` recovers the typo protection when
the caller has a mixed-case address. For Solana there is nothing to recover:
a Base58 substitution can also fail the fixed 32-byte length outright, so a
typo often errors rather than naming another valid address — but when a typo
stays on-curve it is undetectable here, so confirm the address out of band.

## Bitcoin has two rules, not one

Which address is acceptable depends on which side of the transaction it sits:

- `btc::validate` — any well-formed mainnet address. Correct for a
  **recipient**: paying to a P2WPKH, P2TR, P2SH, or P2PKH output is the same
  operation.
- `btc::validate_sender` — additionally requires **P2WPKH** (`bc1q…` native
  segwit), the only script type signing is implemented for.

Using the first where the second belongs is the dangerous direction: it accepts
an address that fails much later, at signing time, after a transaction has been
assembled. They are separate functions rather than a boolean flag so that
mistake reads wrong at the call site.

## Feature flags

Every chain is a separate default-on gate, so a host that needs one chain does
not pay for the others' parsers.

| Feature | Default | Gates | Pulls |
| --- | --- | --- | --- |
| `btc` | on | Bitcoin addresses | `bs58`, `bech32`, `ripemd`, `sha2` |
| `evm` | on | EVM addresses | — (dependency-free) |
| `solana` | on | Solana addresses | `bs58` |
| `tron` | on | Tron addresses | `bs58`, `hex` |
| `keccak` | on | EIP-55 checksums for EVM | `sha3` |

With a chain's gate off, `address::validate` returns `Error::ChainNotCompiled`
for it — a build fact reported honestly, rather than a wrong answer dressed up
as a real one.

## Crates: the contract, the pure rules, and the signer

The repository builds six libraries and one loadable module.

| Crate | Holds | Pulls |
| --- | --- | --- |
| `tinywallet-crypto` | the `Chain` enum, address validation, reference data, the `rpc::Transport` seam, and the Tron protobuf reader and verification | hashes and codecs only — no native build |
| `tinywallet-x402` | the x402 wire types, EIP-712 hashing and ERC-20 calldata (`wire`, `eip712`, `abi`) | `tinywallet-crypto`, keccak, serde |
| `tinywallet-web3` | the wallet, swap, bridge and dapp flows and their agent tools (`tools`), behind host seams: `WalletSigner`, `WalletAccounts`, `RpcEndpoints`, `Web3Backend`, `QuoteScope` | `tinywallet-crypto`, `tinywallet-bus` (`wire`), `tinywallet-x402` (`abi`) — never `bitcoin`, `k256` or `coins-*` |
| `tinywallet-bus` | identifiers, errors, transfers, wire DTOs, member names and contract version | serde, thiserror only |
| `tinywallet` (root) | key derivation, transaction building and signing, chain queries; re-exports the crates above | `bitcoin` and its native `secp256k1` build, `coins-bip39`, `ed25519-dalek` |
| `tinywallet-module` | the TinyBus adapter, built as a `cdylib` | all of the above |

Hosts use `tinywallet-bus` alone and execute validation, transaction and payment
behavior through the compiled module. The bus depends only on serde and
thiserror. Implementations consume and re-export the same shared vocabulary,
so `tinywallet::Chain` and `tinywallet_bus::Chain` are identical types. The
root library retains its historical implementation paths for library users;
hosts do not import those algorithms. See
[the minimal contract specification](docs/specs/minimal-bus-contract.md).

## Layout

```text
crates/tinywallet-bus/src/
├── lib.rs              # contract docs and shared vocabulary
├── names/              # BUS_NAME, OBJECT_PATH, one constant per member
├── version/            # CONTRACT_VERSION and its binding rule
└── wire/               # the host/module request and response types
crates/tinywallet-crypto/src/
├── lib.rs
├── error/              # crate-wide `Error` and `Result<T>`
├── chain/              # the `Chain` enum, ungated
├── address/            # per-chain validation + the generic `validate` dispatch
├── asset/              # network and token reference data
├── rpc/                # the `Transport` seam — models I/O, performs none
├── transfer/           # `TronTransfer`, shared by the wire and the verifier
└── tx/                 # `Error`, the protobuf reader, Tron verification
crates/tinywallet-x402/src/
├── lib.rs
├── wire/               # x402 v2 header payload types
├── eip712/             # typed-data hashing and the EIP-3009 authorization
└── abi/                # ERC-20 `transfer` calldata
crates/tinywallet-web3/src/
├── lib.rs
├── quote/              # rail-neutral: the capped, TTL'd, owner-gated quote store
├── seams/              # rail-neutral: `QuoteScope`
├── crypto/             # the crypto rail
│   ├── wallet/         #   `WalletEngine`, `WalletChain`, `WalletStatus`
│   ├── execution/      #   balances, transfers, lookups on the engine
│   ├── chains/         #   btc / evm / solana / tron choreography (private)
│   ├── service/        #   `Web3Service`: swap, bridge, dapp calls
│   ├── defaults/       #   static networks, assets, explorer links
│   ├── abi/            #   ERC-20 calldata wrapper
│   └── seams/          #   `WalletSigner`, `WalletAccounts`, `RpcEndpoints`, `Web3Backend`
└── tools/              # agent tools (feature `tools`)
src/                    # the root crate: what needs a key or a chain library
├── lib.rs
├── key/                # BIP-39 / BIP-32 / SLIP-0010 derivation
├── tx/                 # building and signing (btc, evm, solana, tron::sign)
├── client/             # chain queries over the `Transport` seam
└── x402/               # re-export of `tinywallet_x402::wire`
crates/tinywallet-module/
└── src/service/        # the TinyBus interface, built as a cdylib
tests/
└── public_api.rs       # integration tests against the public API only
examples/
└── basic.rs            # compiled and linted in CI
```

## Development

```sh
git submodule update --init --recursive

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo run --example basic
```

Run the gated builds too — they are the only thing that catches code that
compiles only when a feature is on. The lib tests are feature-aware, so the
same matrix also exercises the `ChainNotCompiled` contract (a disabled chain
must error, never validate):

```sh
cargo clippy --all-targets --no-default-features -- -D warnings
cargo test --lib --no-default-features
for f in btc evm solana tron keccak; do
  cargo check --lib --no-default-features --features "$f"
  cargo test --lib --no-default-features --features "$f"
done
```

## Roadmap

Address handling is the first slice. The natural next ones, in order of how
cleanly they separate from a host:

1. **Key derivation** — BIP39 seeds, BIP32/SLIP-0010 paths, per-chain keypair
   derivation. Pure, and the largest remaining shared surface.
2. **Transaction encoding** — Solana message serialization, TRC20 ABI
   parameters, PSBT construction. Pure, but each needs its chain's type model.

RPC transport, endpoint config, and key custody stay with the host by design
and are not on this list.

## Documentation

- [`AGENTS.md`](AGENTS.md) — repository guidelines for humans and agents
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — how to propose a change
- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability

## License

GPL-3.0-only. See [LICENSE](LICENSE).

Contract 1.1 adds module-side address validation and removes algorithm re-exports
from the bus crate for the next minor package release. Shared vocabulary moves
to the bus and implementations re-export it. Hosts call the compiled module;
see [minimal bus contracts](docs/specs/minimal-bus-contract.md).

Contract 1.2 adds bounded stateless EVM construction with exact host approval
facts, preserving existing confidential signing. See
[the construction specification](docs/specs/evm-module-construction.md). RPC,
quote/payment lifecycle and host artifact integration remain later slices.
