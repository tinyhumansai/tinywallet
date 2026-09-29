//! ERC-20 calldata, delegated to `tinywallet-x402`, which owns the encoding.
//!
//! What stays here is the error shape. The wallet's RPC surface and its agent
//! tool report failures as a plain `String` a model reads to correct itself, so
//! the typed error is flattened into the wording the tool schema documents.

use tinywallet_x402::abi::Error;

/// ABI-encode an ERC-20 `transfer(address,uint256)` call.
///
/// `amount_raw` is a base-10 string in the token's smallest unit: an 18-decimal
/// token puts ordinary balances past `u64`, and a caller almost always has the
/// value as text from an RPC or a user.
///
/// # Errors
///
/// A human-readable message if the recipient is not a valid EVM address or the
/// amount is not a non-negative integer that fits in 256 bits.
pub fn encode_erc20_transfer(to_address: &str, amount_raw: &str) -> Result<String, String> {
    tinywallet_x402::abi::encode_erc20_transfer(to_address, amount_raw).map_err(|error| match error
    {
        Error::InvalidRecipient { .. } => {
            format!("invalid EVM recipient address '{to_address}': {error}")
        }
        // Preserves the wording the previous implementation used, because
        // the agent tool's schema documents it and a model reads it to
        // correct itself.
        Error::InvalidAmount { .. } => {
            format!("amount '{amount_raw}' is not a valid non-negative integer")
        }
        // `Error` is `#[non_exhaustive]`, so a future variant must be
        // handled; its own message is the best available wording.
        other => other.to_string(),
    })
}

#[cfg(test)]
mod test;
