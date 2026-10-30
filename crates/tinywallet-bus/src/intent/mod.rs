//! Pure comparisons between prepared wallet quotes and execution intents.
//!
//! These functions describe whether a supplied intent agrees with a quote.
//! They do not retain or consume host approval, authorize execution, or call a
//! wallet implementation.

use crate::TronTransfer;

const HEX: &[u8; 16] = b"0123456789abcdef";
use crate::wire::{
    AuthorizeWeb3ExecutionRequest, NativeWalletExecutionIntent, PreparedKind, PreparedTransaction,
    TransactionSpec, WalletChain, Web3ExecutionIntent, Web3QuoteKind, Web3QuoteResponse,
};

/// Check that a native-wallet signing intent preserves the facts in a prepared
/// transfer quote.
///
/// This pure comparison covers the recipient and amount for each supported
/// chain, and the transfer calldata for EVM tokens. It does not consume a host
/// approval or authorize execution.
#[must_use]
pub fn native_intent_matches_quote(
    quote: &PreparedTransaction,
    intent: &NativeWalletExecutionIntent,
) -> bool {
    match intent {
        NativeWalletExecutionIntent::Transaction { transaction } => match transaction {
            TransactionSpec::Btc {
                from,
                to,
                amount_sat,
                ..
            } => {
                quote.chain == WalletChain::Btc
                    && quote.kind == PreparedKind::NativeTransfer
                    && from == &quote.from_address
                    && to == &quote.to_address
                    && quote.amount_raw.parse::<u64>().ok() == Some(*amount_sat)
            }
            TransactionSpec::Evm {
                to,
                value_wei,
                data_hex,
                chain_id,
                ..
            } => {
                let network = quote
                    .evm_network
                    .unwrap_or(crate::wire::EvmNetwork::EthereumMainnet);
                if quote.chain != WalletChain::Evm || network.chain_id() != *chain_id {
                    return false;
                }
                match quote.kind {
                    PreparedKind::NativeTransfer => {
                        to == &quote.to_address
                            && value_wei == &quote.amount_raw
                            && data_hex.is_empty()
                    }
                    PreparedKind::TokenTransfer => {
                        let Some(contract) = quote.token_address.as_deref() else {
                            return false;
                        };
                        to.eq_ignore_ascii_case(contract)
                            && value_wei == "0"
                            && evm_transfer_data_matches(
                                data_hex,
                                &quote.to_address,
                                &quote.amount_raw,
                            )
                    }
                }
            }
            TransactionSpec::Solana {
                from, to, lamports, ..
            } => {
                quote.chain == WalletChain::Solana
                    && quote.kind == PreparedKind::NativeTransfer
                    && from == &quote.from_address
                    && to == &quote.to_address
                    && quote.amount_raw.parse::<u64>().ok() == Some(*lamports)
            }
            TransactionSpec::Tron {
                expected_to,
                transfer,
                ..
            } => {
                if quote.chain != WalletChain::Tron || expected_to != &quote.to_address {
                    return false;
                }
                match (quote.kind, transfer) {
                    (PreparedKind::NativeTransfer, TronTransfer::Native { amount_sun }) => {
                        quote.amount_raw.parse::<u64>().ok() == Some(*amount_sun)
                    }
                    (PreparedKind::TokenTransfer, TronTransfer::Trc20 { parameter_hex }) => {
                        valid_hex(parameter_hex)
                    }
                    _ => false,
                }
            }
        },
        NativeWalletExecutionIntent::SolanaMessage { message_hex } => {
            quote.chain == WalletChain::Solana
                && quote.kind == PreparedKind::TokenTransfer
                && valid_hex(message_hex)
        }
    }
}

/// Check that a Web3 execution request preserves the operation and transaction
/// facts in a previously prepared quote.
///
/// EVM addresses compare case-insensitively. Calldata and decimal value strings
/// compare exactly. This function does not retain or consume a quote-bound
/// permission and does not authorize execution.
#[must_use]
pub fn web3_approval_matches_request(
    quote: &Web3QuoteResponse,
    request: &AuthorizeWeb3ExecutionRequest,
) -> bool {
    let operation_matches = matches!(
        (quote.kind, request.operation.as_str()),
        (Web3QuoteKind::Swap, "swap")
            | (Web3QuoteKind::Bridge, "bridge")
            | (Web3QuoteKind::DappCall, "dapp_call")
    );
    if quote.quote_id != request.quote_id || !operation_matches {
        return false;
    }

    match (&request.transaction, quote.signing_chain) {
        (
            Web3ExecutionIntent::Evm {
                network,
                to,
                data,
                value,
                chain_id,
                ..
            },
            WalletChain::Evm,
        ) => {
            let expected_network = quote
                .quote
                .get("network")
                .and_then(serde_json::Value::as_str);
            if expected_network.is_some_and(|expected| expected != network)
                || !known_evm_chain(network, *chain_id)
            {
                return false;
            }
            let transaction = quote.quote.get("tx");
            match quote.kind {
                Web3QuoteKind::DappCall => {
                    let expected_to = quote
                        .quote
                        .get("contractAddress")
                        .and_then(serde_json::Value::as_str);
                    let expected_data = quote
                        .quote
                        .get("calldata")
                        .and_then(serde_json::Value::as_str);
                    let expected_value = quote
                        .quote
                        .get("valueRaw")
                        .and_then(serde_json::Value::as_str);
                    expected_to.is_some_and(|expected| expected.eq_ignore_ascii_case(to))
                        && expected_data.is_some_and(|expected| data.as_deref() == Some(expected))
                        && expected_value.is_some_and(|expected| expected == value)
                }
                Web3QuoteKind::Swap | Web3QuoteKind::Bridge => {
                    transaction.is_some_and(|transaction| {
                        transaction
                            .get("to")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|expected| expected.eq_ignore_ascii_case(to))
                            && transaction.get("data").and_then(serde_json::Value::as_str)
                                == data.as_deref()
                            && decimal_json(transaction.get("value")).as_deref()
                                == Some(value.as_str())
                    })
                }
            }
        }
        (Web3ExecutionIntent::Solana { tx_blob_hex }, WalletChain::Solana) => {
            let expected = quote
                .quote
                .get("tx")
                .and_then(|transaction| transaction.get("data"))
                .and_then(serde_json::Value::as_str);
            matches!(quote.kind, Web3QuoteKind::Swap | Web3QuoteKind::Bridge)
                && expected == Some(tx_blob_hex.as_str())
        }
        _ => false,
    }
}

fn known_evm_chain(network: &str, chain_id: u64) -> bool {
    crate::wire::EvmNetwork::ALL
        .into_iter()
        .any(|known| known.as_str() == network && known.chain_id() == chain_id)
}

fn decimal_json(value: Option<&serde_json::Value>) -> Option<String> {
    match value? {
        serde_json::Value::String(value) => Some(value.clone()),
        serde_json::Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn evm_transfer_data_matches(data: &str, recipient: &str, amount: &str) -> bool {
    let Some(address) = recipient
        .strip_prefix("0x")
        .or_else(|| recipient.strip_prefix("0X"))
    else {
        return false;
    };
    if address.len() != 40 || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return false;
    }
    let Some(amount_word) = decimal_u256_word(amount) else {
        return false;
    };
    let expected = format!("a9059cbb{:0>64}{amount_word}", address.to_ascii_lowercase());
    let actual = data
        .strip_prefix("0x")
        .or_else(|| data.strip_prefix("0X"))
        .unwrap_or(data);
    actual.eq_ignore_ascii_case(&expected)
}

fn decimal_u256_word(decimal: &str) -> Option<String> {
    if decimal.is_empty() || !decimal.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut bytes = [0u8; 32];
    for digit in decimal.bytes().map(|byte| byte - b'0') {
        let mut carry = u16::from(digit);
        for byte in bytes.iter_mut().rev() {
            let value = u16::from(*byte) * 10 + carry;
            *byte = (value & 0xff) as u8;
            carry = value >> 8;
        }
        if carry != 0 {
            return None;
        }
    }
    let mut word = String::with_capacity(64);
    for byte in bytes {
        word.push(char::from(HEX[usize::from(byte >> 4)]));
        word.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Some(word)
}

fn valid_hex(value: &str) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
