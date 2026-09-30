//! Which session a payment belongs to: the seam between the host's notion of a
//! conversation and the ledger's `session_id`.
//!
//! Rail-neutral. A payment record names the session that made it so per-session
//! totals can be reported; what a "session" is (a chat thread, a job, a process)
//! is the host's to say, and this crate holds no state of its own about it. The
//! host implements [`SessionScope`] and hands it to the tool.
//!
//! The lookup is synchronous on purpose: it is called on the tool's own task, so
//! a host can answer from a task-local without any `.await` or lock.

/// The host's answer to "which session is running this tool call?".
///
/// Called once per payment, on the task that runs the tool. Implementations must
/// not block.
pub trait SessionScope: Send + Sync {
    /// The active session's id, or `None` when the call runs outside any
    /// session (a CLI call, a background job).
    ///
    /// A payment made with no active session is attributed to the ledger's own
    /// session.
    fn current_session(&self) -> Option<String>;
}

/// The default scope: there is never an active session.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSession;

impl SessionScope for NoSession {
    fn current_session(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod test;
