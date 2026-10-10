//! Stateless EVM transaction construction with bounded public input and exact approval facts.
use super::{Failure, build_unsigned, compressed_public_key, decimal_u128, hex};
use tinywallet::wire::{PublicKey, SigningRequest, TransactionSpec};
use tinywallet_bus::wire::{
    ConstructedEvmTransaction, EvmApprovalFacts, EvmConstructionRequest, EvmIntent,
    MAX_CALLDATA_BYTES, MAX_CONSTRUCTION_BYTES,
};

fn invalid(message: &str) -> Failure {
    Failure::InvalidInput(message.into())
}

struct Budget(usize);
impl std::io::Write for Budget {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|size| *size <= MAX_CONSTRUCTION_BYTES)
            .ok_or_else(|| std::io::Error::other("construction request exceeds byte limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(super) fn construct(
    request: &EvmConstructionRequest,
) -> Result<ConstructedEvmTransaction, Failure> {
    serde_json::to_writer(&mut Budget(0), request)
        .map_err(|_| invalid("construction request exceeds byte limit"))?;
    if request.chain_id == 0 || request.gas_limit == 0 {
        return Err(invalid("chain id and gas limit must be greater than zero"));
    }
    let public = compressed_public_key(&request.public_key.key_hex)?;
    let sender = tinywallet::key::evm_address_from_public_key(&public)
        .map_err(|_| invalid("public key is not a valid compressed SEC1 point"))?;
    let gas_price = decimal_u128(&request.gas_price_wei, "gas_price_wei")?;
    let max_fee = gas_price
        .checked_mul(u128::from(request.gas_limit))
        .ok_or_else(|| invalid("maximum gas cost overflows 128 bits"))?;
    let (target, recipient, value, calldata, token_contract, token_amount_raw) =
        match &request.intent {
            EvmIntent::NativeTransfer { to, amount_wei } => {
                let to = address(to)?;
                let value = decimal_u128(amount_wei, "amount_wei")?;
                if value == 0 {
                    return Err(invalid("transfer amount must be greater than zero"));
                }
                (to.clone(), to, value, "0x".into(), None, None)
            }
            EvmIntent::Erc20Transfer {
                token,
                to,
                amount_raw,
            } => {
                let token = address(token)?;
                let to = address(to)?;
                let amount = canonical_token_amount(amount_raw)?;
                let calldata = tinywallet::abi::encode_erc20_transfer(&to, &amount)
                    .map_err(|_| invalid("ERC-20 recipient or uint256 amount is invalid"))?;
                (token.clone(), to, 0, calldata, Some(token), Some(amount))
            }
            EvmIntent::ContractCall {
                to,
                value_wei,
                data_hex,
            } => {
                let to = address(to)?;
                let value = decimal_u128(value_wei, "value_wei")?;
                let body = data_hex
                    .trim()
                    .strip_prefix("0x")
                    .unwrap_or(data_hex.trim());
                if body.len() > MAX_CALLDATA_BYTES * 2
                    || body.len() % 2 != 0
                    || !body.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(invalid("calldata must be bounded byte-aligned hex"));
                }
                (
                    to.clone(),
                    to,
                    value,
                    format!("0x{}", body.to_ascii_lowercase()),
                    None,
                    None,
                )
            }
            _ => return Err(invalid("EVM construction intent is not supported")),
        };
    let max_native = value
        .checked_add(max_fee)
        .ok_or_else(|| invalid("maximum native debit overflows 128 bits"))?;
    let transaction = TransactionSpec::Evm {
        to: target,
        value_wei: value.to_string(),
        data_hex: calldata.clone(),
        nonce: request.nonce,
        gas_limit: request.gas_limit,
        gas_price_wei: gas_price.to_string(),
        chain_id: request.chain_id,
    };
    let unsigned = build_unsigned(&SigningRequest {
        transaction: transaction.clone(),
        public_key: PublicKey {
            key_hex: hex(&public),
        },
    })?;
    Ok(ConstructedEvmTransaction {
        transaction,
        unsigned,
        approval: EvmApprovalFacts {
            sender,
            chain_id: request.chain_id,
            nonce: request.nonce,
            gas_limit: request.gas_limit,
            gas_price_wei: gas_price.to_string(),
            max_fee_wei: max_fee.to_string(),
            max_native_debit_wei: max_native.to_string(),
            native_value_wei: value.to_string(),
            recipient,
            token_contract,
            token_amount_raw,
            calldata_hex: calldata,
        },
    })
}

fn address(raw: &str) -> Result<String, Failure> {
    tinywallet::address::evm::validate(raw).map_err(|_| invalid("EVM address is invalid"))
}

fn canonical_token_amount(raw: &str) -> Result<String, Failure> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 78 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("token amount must be a positive uint256 decimal"));
    }
    let canonical = raw.trim_start_matches('0');
    if canonical.is_empty() {
        return Err(invalid("transfer amount must be greater than zero"));
    }
    Ok(canonical.into())
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
