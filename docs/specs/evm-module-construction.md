# Module EVM transaction construction

Contract 1.2 adds ConstructEvmTransaction with one typed argument. Existing
member arities, transaction/signature wire forms and confidential methods remain
unchanged. Pure bus DTOs declare explicit native transfer, full uint256 ERC-20
transfer and contract call intents. Algorithms stay in the implementation.

The module validates sender public-key encoding/curve membership, addresses,
amounts and calldata; generates token calldata through the owning ABI encoder;
and builds the exact legacy EVM signing digest. Its response contains the
TransactionSpec and signing payload together with sender, network, nonce,
recipient, token/amount, calldata, maximum gas cost and maximum native debit.
The sender uses the existing key owner's EIP-55 public address derivation rather
than a parallel module implementation. Native transfers require positive value;
explicit contract calls can carry zero value and arbitrary bounded hex calldata.
ERC-20 transfers require positive canonical uint256 amounts and carry zero
native value. Checked fee arithmetic refuses overflows instead of wrapping.

A 64 KiB serialized request limit and 16 KiB calldata limit bound work/output.
Secret fields and approval flags are rejected by strict serde request DTOs.
The operation holds no state and performs no I/O, signing or broadcast. Replays
return the same result. Host credentials/approvals remain external; the host
checks its intended signer matches returned sender before signing the exact
returned fields through the existing attested confidential path. RPC, services,
quotes, payment/budget/ledger lifecycle and actual host migration are subsequent
slices. No local build is treated as a released, digest-pinned artifact.

During this work, an existing module hex decoder was found to panic on a
multibyte string whose byte-aligned length concealed a UTF-8 boundary. A fresh
failing regression using a public non-secret fixture precedes a checked-slice
fix; malformed input now returns the existing InvalidInput error.
