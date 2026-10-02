//! Chain queries over the [`Transport`] seam.
//!
//! The first operations that need a network: reading a native balance, and
//! (for Bitcoin) listing the UTXOs a transfer would spend. Each is a thin,
//! chain-specific translation — build the right request, read the right field
//! out of the answer — with the actual I/O delegated to the host's
//! [`Transport`].
//!
//! ## Balances are returned in base units, never as a decimal
//!
//! [`balance`] returns a `u128` of the chain's smallest unit: satoshis, wei,
//! lamports, sun. It does **not** return a float or a formatted string, and
//! that is deliberate. `f64` cannot represent 1 wei exactly, so any float in a
//! balance path silently loses precision on ordinary mainnet values, and
//! formatting is a presentation concern that needs
//! [`Asset::decimals`](crate::asset::Asset::decimals) anyway — which the caller
//! has and this function should not assume.
//!
//! ## The address is validated before the request goes out
//!
//! Every operation validates its address first. A malformed address sent to a
//! node is answered inconsistently across chains — some 400, some return zero,
//! some return an error the caller may read as "empty wallet" — and "you typed
//! a bad address" is a much better answer than "your balance is 0".

use crate::asset::Network;
use crate::rpc::{NetworkId, Transport, TransportError, decode};

mod btc;
mod evm;
mod solana;
mod status;
mod tron;

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;

/// Errors raised by a chain query.
///
/// Not `Clone`: it wraps [`crate::Error`], which is not, and a query error is
/// handled once at the call site rather than fanned out.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The address was rejected before any request was made.
    #[error(transparent)]
    Address(#[from] crate::Error),

    /// The request reached, or failed to reach, the network.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// Building or signing the transaction failed.
    #[error(transparent)]
    Tx(crate::tx::Error),

    /// The endpoint serves a different network than the caller named.
    ///
    /// Checked before anything is signed. EIP-155 binds a signature to a chain
    /// id, so a host whose endpoint config points at the wrong network would
    /// otherwise produce a perfectly valid transaction for a chain the user
    /// did not choose.
    #[error("{network} endpoint reports chain id {reported}, expected {expected}")]
    ChainIdMismatch {
        /// The network the caller named.
        network: NetworkId,
        /// The chain id that network should have.
        expected: u64,
        /// What the endpoint actually reported.
        reported: u128,
    },

    /// The node answered, but not in the shape this chain's API documents.
    ///
    /// Distinct from a [`TransportError::Rpc`] carrying the node's own error
    /// message: this means the response parsed as JSON and then lacked a field
    /// the API is specified to return, which usually points at an endpoint
    /// that is not the API it claims to be — a proxy, a captive portal, or a
    /// misconfigured URL.
    #[error("{network} returned a malformed {operation} response: {detail}")]
    MalformedResponse {
        /// The network that answered.
        network: NetworkId,
        /// Which operation was in flight.
        operation: &'static str,
        /// What was missing or unusable.
        detail: String,
    },
}

/// Result alias for chain queries.
pub type Result<T> = std::result::Result<T, Error>;

pub use status::{TxState, TxStatus, status};

/// Read the native balance of `address` on `network`, in base units.
///
/// "Native" means the chain's own gas asset — BTC, ETH, SOL, TRX — not a
/// token. See the module docs for why the return is a `u128` of the smallest
/// unit rather than a formatted decimal.
///
/// For Bitcoin the result includes unconfirmed mempool activity, matching what
/// a block explorer shows as the spendable balance.
///
/// # Errors
///
/// - [`Error::Address`] if `address` is not valid for `network`'s chain. No
///   request is made.
/// - [`Error::Transport`] if the request failed or the node returned an error.
/// - [`Error::MalformedResponse`] if the answer lacked a documented field.
///
/// # Examples
///
/// ```no_run
/// # async fn example(transport: &dyn tinywallet::rpc::Transport) -> Result<(), tinywallet::client::Error> {
/// use tinywallet::{asset::{EvmNetwork, Network}, client};
///
/// let wei = client::balance(
///     transport,
///     Network::Evm(EvmNetwork::Base),
///     "0x52908400098527886E0F7030069857D2E4169EE7",
/// )
/// .await?;
///
/// // Base units. Format with the asset's decimals, never with a float.
/// println!("{wei} wei");
/// # Ok(())
/// # }
/// ```
pub async fn balance(transport: &dyn Transport, network: Network, address: &str) -> Result<u128> {
    // Validate before spending a round trip — and before a node can answer a
    // malformed address with something that reads like "zero".
    let address = crate::address::validate(network.chain(), address)?;

    match network {
        Network::Btc => btc::balance(transport, &address).await,
        Network::Evm(evm) => evm::balance(transport, evm, &address).await,
        Network::Solana(_) => solana::balance(transport, &address).await,
        Network::Tron => tron::balance(transport, &address).await,
    }
}

/// Build, sign and broadcast a native-asset transfer on an EVM network.
///
/// Returns the transaction hash.
///
/// Two ordering decisions matter here. The chain id is verified against the
/// endpoint *before* anything is signed, because EIP-155 binds a signature to
/// a chain id and a misrouted endpoint would otherwise yield a perfectly valid
/// transaction for a network the user never chose. And the nonce is read at
/// `pending` rather than `latest` — the opposite of a balance — so two
/// transfers in quick succession do not collide on a nonce and replace one
/// another.
///
/// # Errors
///
/// See [`Error`]. No signature is produced if any pre-flight step fails.
pub async fn send_evm(
    transport: &dyn Transport,
    network: crate::asset::EvmNetwork,
    from: &str,
    to: &str,
    value: u128,
    data: Vec<u8>,
    secret_key: &[u8],
) -> Result<String> {
    let from = crate::address::evm::validate(from)?;
    let to = crate::address::evm::validate(to)?;
    evm::send(transport, network, &from, &to, value, data, secret_key).await
}

/// Build, sign and broadcast a native SOL transfer.
///
/// Returns the transaction signature, which is Solana's transaction id. The
/// blockhash is fetched immediately before signing because it doubles as the
/// transaction's expiry — a stale one yields a signed transaction that can
/// never land.
///
/// # Errors
///
/// See [`Error`].
pub async fn send_solana(
    transport: &dyn Transport,
    cluster: crate::asset::SolanaCluster,
    from: &str,
    to: &str,
    lamports: u64,
    secret_key: &[u8],
) -> Result<String> {
    let from = crate::address::solana::validate(from)?;
    let to = crate::address::solana::validate(to)?;
    solana::send(transport, cluster, &from, &to, lamports, secret_key).await
}

/// List the unspent outputs a Bitcoin address controls.
///
/// # Errors
///
/// See [`Error`].
pub async fn btc_utxos(
    transport: &dyn Transport,
    address: &str,
) -> Result<Vec<crate::tx::btc::Utxo>> {
    let address = crate::address::btc::validate(address)?;
    btc::utxos(transport, &address).await
}

/// Build, sign and broadcast a Bitcoin transfer. Returns the txid.
///
/// `fee` is absolute, in satoshis. Bitcoin's fee is implicit
/// (`inputs - outputs`), so it is stated explicitly here rather than inferred.
///
/// # Errors
///
/// See [`Error`].
pub async fn send_btc(
    transport: &dyn Transport,
    from: &str,
    to: &str,
    amount: u64,
    fee: u64,
    secret_key: &[u8],
) -> Result<String> {
    let from = crate::address::btc::validate_sender(from)?;
    let to = crate::address::btc::validate(to)?;
    btc::send(transport, &from, &to, amount, fee, secret_key).await
}

/// Build, verify, sign and broadcast a Tron transfer. Returns the txid.
///
/// `amount` is in sun. The node builds the transaction, so its answer is
/// verified against the request before anything is signed.
///
/// # Errors
///
/// See [`Error`].
pub async fn send_tron(
    transport: &dyn Transport,
    from: &str,
    to: &str,
    amount: u64,
    secret_key: &[u8],
) -> Result<String> {
    let from = crate::address::tron::validate(from)?;
    let to = crate::address::tron::validate(to)?;
    tron::send(transport, &from, &to, amount, secret_key).await
}

/// Map a [`Network`] onto the transport's [`NetworkId`].
fn network_id(network: Network) -> NetworkId {
    match network.chain_id() {
        Some(chain_id) => NetworkId::evm(chain_id),
        None => NetworkId::chain(network.chain()),
    }
}

/// Parse a `0x`-prefixed hex quantity, as EVM JSON-RPC returns for balances,
/// nonces and gas prices.
fn parse_hex_u128(network: NetworkId, operation: &'static str, raw: &str) -> Result<u128> {
    let body = raw.strip_prefix("0x").unwrap_or(raw);
    u128::from_str_radix(body, 16).map_err(|e| Error::MalformedResponse {
        network,
        operation,
        detail: format!("expected a hex quantity, got {raw:?}: {e}"),
    })
}
