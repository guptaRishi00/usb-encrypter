//! Progress reporting and cooperative cancellation.
//!
//! The engine knows nothing about Tauri events. It calls a sink; the command
//! layer implements one that emits to the window, and the tests implement one
//! that records. Cancellation is checked between chunks, so a cancel during a
//! multi-gigabyte file takes effect within one megabyte rather than at the end
//! of the file.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressSnapshot {
    pub files_done: u64,
    pub total_files: u64,
    pub bytes_done: u64,
    pub total_bytes: u64,
}

pub trait ProgressSink: Send + Sync {
    fn report(&self, snapshot: ProgressSnapshot, current_name: &str);
    /// Checked between chunks. Returning true aborts the operation and rolls
    /// back everything it had written.
    fn is_cancelled(&self) -> bool {
        false
    }
}

/// A sink that discards everything. Used by tests and by internal operations
/// that have no UI attached.
pub struct NoProgress;

impl ProgressSink for NoProgress {
    fn report(&self, _snapshot: ProgressSnapshot, _current_name: &str) {}
}

/// Shared, thread-safe counters that a UI thread can flip to cancel.
#[derive(Debug, Default)]
pub struct CancelFlag {
    cancelled: AtomicBool,
    /// Bumped on every new operation so a stale cancel from a previous run
    /// cannot abort the next one.
    generation: AtomicU64,
}

impl CancelFlag {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a new operation, clearing any previous cancel. Returns the
    /// generation to pass back to [`CancelFlag::cancel`].
    pub fn begin(&self) -> u64 {
        self.cancelled.store(false, Ordering::SeqCst);
        self.generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }

    pub fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        seen: Mutex<Vec<ProgressSnapshot>>,
    }

    impl ProgressSink for Recorder {
        fn report(&self, snapshot: ProgressSnapshot, _n: &str) {
            self.seen.lock().unwrap().push(snapshot);
        }
    }

    #[test]
    fn a_sink_receives_what_it_is_told() {
        let r = Recorder::default();
        r.report(
            ProgressSnapshot { files_done: 1, total_files: 2, bytes_done: 10, total_bytes: 20 },
            "x",
        );
        assert_eq!(r.seen.lock().unwrap().len(), 1);
    }

    #[test]
    fn begin_clears_a_previous_cancel() {
        let f = CancelFlag::new();
        f.cancel();
        assert!(f.is_cancelled());
        f.begin();
        assert!(!f.is_cancelled(), "a stale cancel must not abort the next run");
    }

    #[test]
    fn generation_advances_on_each_operation() {
        let f = CancelFlag::new();
        let a = f.begin();
        let b = f.begin();
        assert!(b > a);
        assert_eq!(f.current_generation(), b);
    }
}
