//! Structured logging, with a hard rule about what may be written.
//!
//! # What is never logged
//!
//! Passwords, key material, nonces, salts, plaintext file contents, and the
//! full paths of a user's files. The types that hold secrets do not implement
//! `Display`, and their `Debug` implementations print `<redacted>`, so a stray
//! log line cannot leak one by accident.
//!
//! File *names* are shown live in the progress panel because the user asked to
//! see what is being encrypted, but they are not written to the log. The log
//! records counts, byte totals, durations, generations and error kinds.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

static LOG_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Initialise logging into `dir/vaultdrive.log`.
///
/// Safe to call more than once; later calls are ignored.
pub fn init(dir: &Path) {
    let _ = fs::create_dir_all(dir);
    let path = dir.join("vaultdrive.log");
    let _ = LOG_PATH.set(path.clone());

    let file_appender = tracing_appender::rolling::never(dir, "vaultdrive.log");

    // `VAULTDRIVE_LOG` can raise the level for debugging; the default is
    // deliberately quiet.
    let filter = EnvFilter::try_from_env("VAULTDRIVE_LOG")
        .unwrap_or_else(|_| EnvFilter::new("vaultdrive_lib=info,warn"));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(fmt::layer().with_ansi(false).with_target(true).with_writer(file_appender))
        .try_init();

    tracing::info!(version = env!("CARGO_PKG_VERSION"), "VaultDrive started");
}

pub fn log_path() -> Option<PathBuf> {
    LOG_PATH.get().cloned()
}

/// Read the diagnostic log so the user can look at it or save a copy.
///
/// There is no separate "sanitised" export, because there is no unsanitised
/// log: the redaction happens at every call site, not on the way out. What this
/// returns is exactly what is on disk.
pub fn read_diagnostics() -> String {
    match log_path().and_then(|p| fs::read_to_string(p).ok()) {
        Some(s) => s,
        None => String::from("No diagnostic log has been written yet."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_readable_even_before_any_log_exists() {
        // `init` may not have run in this test binary; the call must still
        // return something printable rather than panicking.
        let s = read_diagnostics();
        assert!(!s.is_empty());
    }
}
