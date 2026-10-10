//! The outbound-HTTP policy seam.

/// Applies the host's proxy and network policy to an HTTP client under
/// construction.
///
/// Which proxy a process uses is deployment configuration, so this crate never
/// reads it: it hands the host its [`reqwest::ClientBuilder`] and takes back
/// the configured one.
pub trait ProxyPolicy: Send + Sync {
    /// Configure `builder` for the caller named `service`, a stable label such
    /// as `"tool.x402_request"` the host can key its per-service rules on.
    fn apply(&self, builder: reqwest::ClientBuilder, service: &str) -> reqwest::ClientBuilder;

    /// Whether this service may connect directly to the destination approved
    /// by its request guard. A proxy performs its own DNS lookup, which would
    /// bypass the guard's pinned addresses. Hosts that require a proxy must
    /// leave this false, so guarded requests fail closed.
    fn allows_direct_connection(&self, _service: &str) -> bool {
        false
    }
}
