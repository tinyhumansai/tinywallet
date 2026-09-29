//! Solana `exact` scheme payment construction: a partially-signed legacy
//! transaction carrying `ComputeBudget` + SPL `TransferChecked` (+ optional
//! Memo) instructions, encoded by hand — no `solana-sdk` dependency.
//!
//! Layout:
//!   `account_keys[0]` = `fee_payer` (facilitator) — signer, writable
//!   `account_keys[1]` = `our_pubkey` (transfer authority) — signer, writable
//!   `account_keys[2]` = `src_ata` — writable
//!   `account_keys[3]` = `dst_ata` — writable
//!   `account_keys[4]` = mint — readonly
//!   `account_keys[5]` = `token_program` — readonly
//!   `account_keys[6]` = `compute_budget_program` — readonly
//!   `account_keys[7]` = `memo_program` — readonly
//!
//! Instructions:
//!   0. `SetComputeUnitLimit(DEFAULT_COMPUTE_UNITS)`
//!   1. `SetComputeUnitPrice(DEFAULT_COMPUTE_UNIT_PRICE)`
//!   2. `TransferChecked { amount, decimals=6 }`
//!   3. Memo (`extra.memo` if set, otherwise a random 16-byte hex nonce)

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use log::debug;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tinywallet_crypto::Chain;
use tinywallet_crypto::rpc::{self, NetworkId, Transport};

use super::signer::{PaymentSigner, SignScheme};
use super::{LOG_PREFIX, fresh_nonce};
use crate::protocol::X402Error;
use crate::wire::{
    COMPUTE_BUDGET_PROGRAM, PaymentChain, PaymentPayload, PaymentProof, PaymentRequired,
    PaymentRequirements, SPL_MEMO_PROGRAM, SPL_TOKEN_PROGRAM, SolanaPaymentProof, X402_VERSION,
};

/// Reasonable compute budget defaults for a single SPL `TransferChecked`.
const DEFAULT_COMPUTE_UNITS: u32 = 50_000;
/// Micro-lamports per compute unit.
const DEFAULT_COMPUTE_UNIT_PRICE: u64 = 1000;
/// The associated-token-account program.
const ATA_PROGRAM: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
/// The decimals `TransferChecked` is told the mint has (USDC).
const USDC_DECIMALS: u8 = 6;

/// Build a partially-signed Solana transaction for the `exact` scheme.
pub(super) async fn build_solana_payment(
    signer: &dyn PaymentSigner,
    transport: &dyn Transport,
    our_pubkey: [u8; 32],
    challenge: &PaymentRequired,
    req: &PaymentRequirements,
) -> Result<PaymentPayload, X402Error> {
    let amount: u64 = req
        .amount
        .parse()
        .map_err(|e| X402Error::Protocol(format!("invalid amount '{}': {e}", req.amount)))?;

    let fee_payer = req
        .fee_payer_pubkey()
        .ok_or_else(|| X402Error::Protocol("no fee_payer in payment requirements".into()))?;
    let fee_payer_bytes = b58_to_32(fee_payer)?;
    let pay_to_bytes = b58_to_32(&req.pay_to)?;
    let mint_bytes = b58_to_32(&req.asset)?;

    let token_program = b58_to_32(SPL_TOKEN_PROGRAM)?;
    let compute_budget = b58_to_32(COMPUTE_BUDGET_PROGRAM)?;
    let memo_program = b58_to_32(SPL_MEMO_PROGRAM)?;

    let src_ata = derive_ata(&our_pubkey, &mint_bytes, &token_program)?;
    let dst_ata = derive_ata(&pay_to_bytes, &mint_bytes, &token_program)?;

    let memo_data = req
        .memo_value()
        .map_or_else(random_memo_nonce, |m| m.as_bytes().to_vec());

    // Account keys; the order matters.
    let account_keys: Vec<[u8; 32]> = vec![
        fee_payer_bytes, // 0: fee payer (signer, writable)
        our_pubkey,      // 1: transfer authority (signer, writable)
        src_ata,         // 2: source ATA (writable)
        dst_ata,         // 3: destination ATA (writable)
        mint_bytes,      // 4: mint (readonly)
        token_program,   // 5: SPL Token program (readonly)
        compute_budget,  // 6: Compute Budget program (readonly)
        memo_program,    // 7: SPL Memo program (readonly)
    ];

    // Header: [num_required_sigs, num_readonly_signed, num_readonly_unsigned].
    // 2 signers (fee payer + us), 0 readonly signed, 4 readonly unsigned (mint,
    // token program, compute budget, memo program).
    let header = [2u8, 0u8, 4u8];

    let instructions = vec![
        build_set_compute_unit_limit(6, DEFAULT_COMPUTE_UNITS),
        build_set_compute_unit_price(6, DEFAULT_COMPUTE_UNIT_PRICE),
        build_transfer_checked(
            5, // token_program index
            2, // src_ata index
            4, // mint index
            3, // dst_ata index
            1, // authority (our_pubkey) index
            amount,
            USDC_DECIMALS,
        ),
        build_memo(7, &memo_data),
    ];

    let blockhash = fetch_recent_blockhash(transport).await?;
    let message = encode_legacy_message(&header, &account_keys, &blockhash, &instructions);

    // Wire format: 2 signature slots; slot 0 (the fee payer) is left zeroed for
    // the facilitator and only ours (slot 1) is filled.
    let mut wire = Vec::with_capacity(1 + 128 + message.len());
    wire.extend(encode_shortvec(2));
    wire.extend([0u8; 64]);

    // Signed behind the seam: the private key is never assembled in this
    // process.
    let signature = signer
        .sign(PaymentChain::Solana, &message, SignScheme::Ed25519)
        .await
        .map_err(|e| X402Error::Wallet(format!("sign payment: {e}")))?;
    let sig_bytes = <[u8; 64]>::try_from(signature.as_slice()).map_err(|_| {
        X402Error::Wallet("the wallet module returned a malformed signature".to_string())
    })?;
    wire.extend(sig_bytes);
    wire.extend(&message);

    let tx_b64 = B64.encode(&wire);
    debug!(
        "{LOG_PREFIX} built payment tx {} bytes, amount={amount} asset={}",
        wire.len(),
        req.asset
    );

    Ok(PaymentPayload {
        x402_version: X402_VERSION,
        resource: Some(challenge.resource.clone()),
        accepted: req.clone(),
        payload: PaymentProof::Solana(SolanaPaymentProof {
            transaction: tx_b64,
        }),
        extensions: serde_json::Map::new(),
    })
}

/// Decode a base58 string that must be exactly 32 bytes.
pub(super) fn b58_to_32(addr: &str) -> Result<[u8; 32], X402Error> {
    let v = bs58::decode(addr.trim())
        .into_vec()
        .map_err(|e| X402Error::Protocol(format!("invalid base58 '{addr}': {e}")))?;
    let len = v.len();
    <[u8; 32]>::try_from(v).map_err(|_| {
        X402Error::Protocol(format!("expected 32-byte key, got {len} for '{addr}'"))
    })
}

/// The associated token account for `owner` and `mint`: the first bump, counting
/// down from 255, whose candidate address is *off* the ed25519 curve.
pub(super) fn derive_ata(
    owner: &[u8; 32],
    mint: &[u8; 32],
    token_program: &[u8; 32],
) -> Result<[u8; 32], X402Error> {
    let ata_program = b58_to_32(ATA_PROGRAM)?;
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        hasher.update(owner);
        hasher.update(token_program);
        hasher.update(mint);
        hasher.update([bump]);
        hasher.update(ata_program);
        hasher.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = hasher.finalize().into();
        if curve25519_dalek::edwards::CompressedEdwardsY(candidate)
            .decompress()
            .is_none()
        {
            return Ok(candidate);
        }
    }
    Err(X402Error::Protocol("ATA PDA derivation failed".into()))
}

/// Solana's compact-u16 length encoding.
pub(super) fn encode_shortvec(value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = value;
    loop {
        // Masked to 7 bits, so the narrowing cannot lose anything.
        #[allow(clippy::cast_possible_truncation)]
        let mut byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

struct Instruction {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

fn build_set_compute_unit_limit(program_idx: u8, units: u32) -> Instruction {
    let mut data = vec![2u8]; // discriminator
    data.extend(units.to_le_bytes());
    Instruction {
        program_id_index: program_idx,
        accounts: vec![],
        data,
    }
}

fn build_set_compute_unit_price(program_idx: u8, micro_lamports: u64) -> Instruction {
    let mut data = vec![3u8]; // discriminator
    data.extend(micro_lamports.to_le_bytes());
    Instruction {
        program_id_index: program_idx,
        accounts: vec![],
        data,
    }
}

fn build_transfer_checked(
    token_program_idx: u8,
    src_idx: u8,
    mint_idx: u8,
    dst_idx: u8,
    authority_idx: u8,
    amount: u64,
    decimals: u8,
) -> Instruction {
    let mut data = vec![12u8]; // SPL Token: TransferChecked = 12
    data.extend(amount.to_le_bytes());
    data.push(decimals);
    Instruction {
        program_id_index: token_program_idx,
        accounts: vec![src_idx, mint_idx, dst_idx, authority_idx],
        data,
    }
}

fn build_memo(program_idx: u8, memo_data: &[u8]) -> Instruction {
    Instruction {
        program_id_index: program_idx,
        accounts: vec![],
        data: memo_data.to_vec(),
    }
}

fn encode_instruction(ins: &Instruction) -> Vec<u8> {
    let mut out = vec![ins.program_id_index];
    out.extend(encode_shortvec(ins.accounts.len()));
    out.extend(&ins.accounts);
    out.extend(encode_shortvec(ins.data.len()));
    out.extend(&ins.data);
    out
}

fn encode_legacy_message(
    header: &[u8; 3],
    account_keys: &[[u8; 32]],
    recent_blockhash: &[u8; 32],
    instructions: &[Instruction],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(header);
    out.extend(encode_shortvec(account_keys.len()));
    for key in account_keys {
        out.extend(key);
    }
    out.extend(recent_blockhash);
    out.extend(encode_shortvec(instructions.len()));
    for ins in instructions {
        out.extend(encode_instruction(ins));
    }
    out
}

/// A memo that makes two otherwise identical transfers distinct transactions:
/// 16 fresh bytes as lowercase hex.
pub(super) fn random_memo_nonce() -> Vec<u8> {
    hex::encode(&fresh_nonce()[..16]).into_bytes()
}

/// The latest finalized blockhash, through the host's [`Transport`].
async fn fetch_recent_blockhash(transport: &dyn Transport) -> Result<[u8; 32], X402Error> {
    #[derive(Deserialize)]
    struct BlockhashResponse {
        value: BlockhashValue,
    }
    #[derive(Deserialize)]
    struct BlockhashValue {
        blockhash: String,
    }

    const METHOD: &str = "getLatestBlockhash";
    let network = NetworkId::chain(Chain::Solana);
    let value = transport
        .json_rpc(
            network,
            METHOD,
            serde_json::json!([{"commitment": "finalized"}]),
        )
        .await
        .map_err(|e| X402Error::Wallet(format!("fetch blockhash: {e}")))?;
    let result: BlockhashResponse = rpc::decode(network, METHOD, value)
        .map_err(|e| X402Error::Wallet(format!("fetch blockhash: {e}")))?;

    b58_to_32(&result.value.blockhash)
}
