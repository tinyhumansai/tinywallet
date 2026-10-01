//! Which conversation thread a payment belongs to: the seam between the host's
//! notion of a conversation and the ledger's `thread_id`.
//!
//! Rail-neutral. The ledger's `session_id` is its own (one per process, set at
//! [`init_global`](crate::ledger::init_global)) and never comes from here. A
//! thread is finer attribution the host may add: which chat thread, job or
//! conversation asked for the payment. This crate holds no state about it; the
//! host implements [`ThreadScope`] and hands it to the tool.
//!
//! The lookup is synchronous on purpose: it is called on the tool's own task, so
//! a host can answer from a task-local without any `.await` or lock.

/// The host's answer to "which thread is running this tool call?".
///
/// Called once per payment, on the task that runs the tool. Implementations must
/// not block.
pub trait ThreadScope: Send + Sync {
    /// The active thread's id, or `None` when the call runs outside any thread
    /// (a CLI call, a background job). A payment made then has no `thread_id`.
    fn current_thread(&self) -> Option<String>;
}

/// The default scope: there is never an active thread.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoThread;

impl ThreadScope for NoThread {
    fn current_thread(&self) -> Option<String> {
        None
    }
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod test;
