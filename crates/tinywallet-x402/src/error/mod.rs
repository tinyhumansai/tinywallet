//! Errors returned by x402 host policy seams.

/// A host refused to authorize an agent-directed request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Host policy denied the proposed method, headers, body, or destination.
    #[error("[policy-blocked] {0}")]
    Denied(String),
    /// The host could not produce a usable approved destination.
    #[error("[policy-blocked] Invalid destination: {0}")]
    InvalidDestination(String),
}

/// Result returned by the x402 host policy seam.
pub type Result<T> = std::result::Result<T, Error>;
