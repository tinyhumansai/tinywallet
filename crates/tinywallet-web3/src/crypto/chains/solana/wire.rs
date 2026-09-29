//! Hand-built Solana wire format, so the crate does not pull in `solana-sdk`
//! (which transitively brings in ~150 crates).
//!
//! References:
//! - <https://docs.solana.com/developing/programming-model/transactions>
//! - <https://docs.solana.com/developing/programming-model/runtime#compact-u16>
//! - <https://spl.solana.com/token>

use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// System Program ID (all zeros).
pub(super) const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

const TOKEN_PROGRAM_B58: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ATA_PROGRAM_B58: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// The SPL Token program id.
pub(super) fn token_program_id() -> Result<[u8; 32], String> {
    b58_to_pubkey(TOKEN_PROGRAM_B58)
}

/// The Associated Token Account program id.
fn ata_program_id() -> Result<[u8; 32], String> {
    b58_to_pubkey(ATA_PROGRAM_B58)
}

/// Decode a base58 32-byte public key.
pub(super) fn b58_to_pubkey(addr: &str) -> Result<[u8; 32], String> {
    let v = bs58::decode(addr)
        .into_vec()
        .map_err(|e| format!("invalid base58 '{addr}': {e}"))?;
    <[u8; 32]>::try_from(v.as_slice())
        .map_err(|_| format!("expected 32-byte pubkey, got {}", v.len()))
}

/// Encode a public key as base58.
pub(super) fn pubkey_to_b58(pubkey: &[u8; 32]) -> String {
    bs58::encode(pubkey).into_string()
}

/// Solana compact-u16 (shortvec) encoding.
pub(super) fn encode_shortvec(value: u16) -> Vec<u8> {
    let mut out = Vec::new();
    let mut v = u32::from(value);
    loop {
        // Masked to 7 bits, so the narrowing cannot lose information.
        let mut byte = u8::try_from(v & 0x7f).unwrap_or(0x7f);
        v >>= 7;
        if v == 0 {
            out.push(byte);
            return out;
        }
        byte |= 0x80;
        out.push(byte);
    }
}

/// Decode a Solana compact-u16 (shortvec). Returns `(value, bytes_consumed)`.
pub(super) fn decode_shortvec(bytes: &[u8]) -> Result<(u16, usize), String> {
    let mut value: u32 = 0;
    let mut shift = 0u32;
    for (i, byte) in bytes.iter().enumerate() {
        if i >= 3 {
            return Err("shortvec too long".to_string());
        }
        value |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            let decoded = u16::try_from(value)
                .map_err(|_| "shortvec exceeds u16 range".to_string())?;
            return Ok((decoded, i + 1));
        }
        shift += 7;
    }
    Err("shortvec truncated".to_string())
}

/// A shortvec length prefix for a slice length.
fn shortvec_len(len: usize) -> Vec<u8> {
    // Instruction, account and key counts are bounded far below `u16::MAX` by
    // the transaction size limit; saturating keeps an absurd input encodable
    // rather than panicking.
    encode_shortvec(u16::try_from(len).unwrap_or(u16::MAX))
}

#[derive(Debug, Clone)]
struct CompiledInstruction {
    program_id_index: u8,
    accounts: Vec<u8>,
    data: Vec<u8>,
}

fn encode_compiled_instruction(ins: &CompiledInstruction) -> Vec<u8> {
    let mut out = vec![ins.program_id_index];
    out.extend(shortvec_len(ins.accounts.len()));
    out.extend(&ins.accounts);
    out.extend(shortvec_len(ins.data.len()));
    out.extend(&ins.data);
    out
}

fn encode_message(
    header: [u8; 3],
    account_keys: &[[u8; 32]],
    recent_blockhash: &[u8; 32],
    instructions: &[CompiledInstruction],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend(header);
    out.extend(shortvec_len(account_keys.len()));
    for key in account_keys {
        out.extend(key);
    }
    out.extend(recent_blockhash);
    out.extend(shortvec_len(instructions.len()));
    for ins in instructions {
        out.extend(encode_compiled_instruction(ins));
    }
    out
}

/// Solana `find_program_address`: iterates a bump seed 255..=0, returning the
/// first off-curve PDA. Used to derive Associated Token Accounts.
fn find_program_address(seeds: &[&[u8]], program_id: &[u8; 32]) -> Result<[u8; 32], String> {
    let pda_marker = b"ProgramDerivedAddress";
    for bump in (0u8..=255).rev() {
        let mut hasher = Sha256::new();
        for seed in seeds {
            hasher.update(seed);
        }
        hasher.update([bump]);
        hasher.update(program_id);
        hasher.update(pda_marker);
        let candidate: [u8; 32] = hasher.finalize().into();
        // Off-curve means it cannot be a public key.
        if CompressedEdwardsY(candidate).decompress().is_none() {
            return Ok(candidate);
        }
    }
    Err("no off-curve PDA found".to_string())
}

/// The Associated Token Account of `owner` for `mint`.
pub(super) fn associated_token_account(
    owner: &[u8; 32],
    mint: &[u8; 32],
) -> Result<[u8; 32], String> {
    let token_program = token_program_id()?;
    let ata_program = ata_program_id()?;
    find_program_address(&[&owner[..], &token_program[..], &mint[..]], &ata_program)
}

/// A native SOL transfer message.
pub(super) fn build_native_transfer_message(
    from: [u8; 32],
    to: [u8; 32],
    lamports: u64,
    recent_blockhash: [u8; 32],
) -> Vec<u8> {
    // accounts: [from (signer, writable), to (writable), system_program (read-only)]
    let account_keys = [from, to, SYSTEM_PROGRAM_ID];
    // header: 1 required sig, 0 readonly signed, 1 readonly unsigned (system program)
    let header = [1u8, 0u8, 1u8];
    let mut data = vec![2u8, 0u8, 0u8, 0u8]; // SystemInstruction::Transfer = 2
    data.extend(lamports.to_le_bytes());
    let ins = CompiledInstruction {
        program_id_index: 2,
        accounts: vec![0, 1],
        data,
    };
    encode_message(header, &account_keys, &recent_blockhash, &[ins])
}

/// An SPL token transfer message between two Associated Token Accounts.
pub(super) fn build_spl_transfer_message(
    from_owner: [u8; 32],
    src_ata: [u8; 32],
    dst_ata: [u8; 32],
    amount: u64,
    recent_blockhash: [u8; 32],
) -> Result<Vec<u8>, String> {
    let token_program = token_program_id()?;
    // accounts:
    //  0: from_owner (signer, writable: pays the fee)
    //  1: src_ata (writable)
    //  2: dst_ata (writable)
    //  3: token_program (readonly, unsigned)
    let account_keys = [from_owner, src_ata, dst_ata, token_program];
    let header = [1u8, 0u8, 1u8];
    let mut data = vec![3u8]; // SPL Token instruction: Transfer = 3
    data.extend(amount.to_le_bytes());
    let ins = CompiledInstruction {
        program_id_index: 3,
        accounts: vec![1, 2, 0], // src, dst, owner(signer)
        data,
    };
    Ok(encode_message(header, &account_keys, &recent_blockhash, &[ins]))
}

#[cfg(test)]
mod test;
