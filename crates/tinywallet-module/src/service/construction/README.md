# EVM construction and approval facts

ConstructEvmTransaction is a stateless, one-argument module operation. It accepts
public account metadata, an explicit native/ERC-20/contract action and resolved
network facts. It generates the TransactionSpec, signing payload and exact facts
the host reviews before signing. No request carries a phrase, private key,
approval flag or policy; unknown fields are rejected.

The host owns RPC configuration/resolution, credential custody and approval.
Before signing, it compares the returned sender with its intended account and
approves the returned network, nonce, recipient, token/amount, calldata and
maximum native debit. It passes the exact returned TransactionSpec through the
existing confidential SignTransaction operation, or the split signing flow.
The constructor never signs, broadcasts, reserves funds or stores a handle.
Lost replies/retries therefore produce identical public results without side
effects or orphaned resources. A host changing returned fields must obtain a new
construction result and approval for those fields.

The request JSON budget is 64 KiB; a counting writer rejects serialization
before allocating a request copy. Calldata is at most 16 KiB. Recipient/public
key, decimal fields and generated calldata have explicit or validation-implied
bounds, so repeated transaction/fact fields cannot produce unbounded output.
Gas multiplication and maximum native debit use checked u128 arithmetic,
matching the existing EVM legacy transaction implementation. ERC-20 amounts
retain full uint256 range through the owning ABI implementation. Facts show the
canonical decimal amounts and exact calldata that the payload commits to.

RPC querying, network fee estimation, provider callbacks, quote lifecycle,
x402 payments, spending budgets, durable ledger and sign-out cleanup remain
following owner slices. Host adapters, root pins and release digest adoption
remain gated on independently reviewed compatible published artifacts.
