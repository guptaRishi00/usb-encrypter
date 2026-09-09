//! The unlocked-vault session and automatic locking.
//!
//! There is at most one unlocked vault at a time. It lives here, behind a
//! mutex, in the Rust process -- never in the web view. The frontend holds file
//! ids and names; it never holds a key, and it cannot read a byte of the vault
//! except by asking for it.
//!
//! Automatic locking is enforced on this side too. A timer in JavaScript can be
//! stopped by a hung renderer or by anyone with the developer tools open; the
//! background thread that calls [`VaultSession::enforce_auto_lock`] cannot.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{Result, VaultError};
use crate::vault::container::OpenVault;
use crate::vault::progress::CancelFlag;

pub struct VaultSession {
    vault: Mutex<Option<OpenVault>>,
    last_activity: Mutex<Instant>,
    auto_lock: Mutex<Option<Duration>>,
    cancel: CancelFlag,
}

impl Default for VaultSession {
    fn default() -> Self {
        Self::new()
    }
}

impl VaultSession {
    pub fn new() -> Self {
        Self {
            vault: Mutex::new(None),
            last_activity: Mutex::new(Instant::now()),
            auto_lock: Mutex::new(None),
            cancel: CancelFlag::new(),
        }
    }

    pub fn cancel_flag(&self) -> &CancelFlag {
        &self.cancel
    }

    pub fn is_unlocked(&self) -> bool {
        self.vault.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Record activity, so the inactivity clock restarts.
    pub fn touch(&self) {
        if let Ok(mut t) = self.last_activity.lock() {
            *t = Instant::now();
        }
    }

    /// `None` means never lock automatically.
    pub fn set_auto_lock(&self, after: Option<Duration>) {
        if let Ok(mut a) = self.auto_lock.lock() {
            *a = after;
        }
        self.touch();
    }

    pub fn auto_lock(&self) -> Option<Duration> {
        self.auto_lock.lock().ok().and_then(|a| *a)
    }

    pub fn set_vault(&self, vault: OpenVault) {
        if let Ok(mut g) = self.vault.lock() {
            // Replacing an existing vault drops it, which wipes its keys.
            *g = Some(vault);
        }
        self.touch();
    }

    /// Lock the vault. Returns whether anything was open.
    ///
    /// Dropping the [`OpenVault`] is the whole operation: the master key and
    /// every subkey are `Zeroize`/`Zeroizing` and are wiped as they go out of
    /// scope, and the file handle is closed with them.
    pub fn lock(&self) -> bool {
        let taken = self.vault.lock().ok().and_then(|mut g| g.take());
        let was_open = taken.is_some();
        drop(taken);
        if was_open {
            tracing::info!("vault locked");
        }
        was_open
    }

    /// Run `f` against the unlocked vault, or fail with [`VaultError::Locked`].
    pub fn with<T>(&self, f: impl FnOnce(&mut OpenVault) -> Result<T>) -> Result<T> {
        self.touch();
        let mut guard = self.vault.lock().map_err(|_| VaultError::Locked)?;
        let vault = guard.as_mut().ok_or(VaultError::Locked)?;
        let out = f(vault);
        drop(guard);
        self.touch();
        out
    }

    /// Take the vault out of the session, run `f` on it, and put back whatever
    /// `f` returns. Used by compaction, which has to close and reopen the file.
    pub fn replace_with(&self, f: impl FnOnce(OpenVault) -> Result<OpenVault>) -> Result<()> {
        self.touch();
        let taken = {
            let mut guard = self.vault.lock().map_err(|_| VaultError::Locked)?;
            guard.take().ok_or(VaultError::Locked)?
        };
        match f(taken) {
            Ok(new) => {
                self.set_vault(new);
                Ok(())
            }
            // On failure the vault stays locked rather than being restored in
            // an unknown state. The user re-enters the password; nothing is lost
            // because compaction only ever replaces the file atomically.
            Err(e) => Err(e),
        }
    }

    /// Lock if the configured inactivity period has elapsed. Returns true if
    /// this call is what locked it.
    pub fn enforce_auto_lock(&self) -> bool {
        let Some(limit) = self.auto_lock() else {
            return false;
        };
        if !self.is_unlocked() {
            return false;
        }
        let idle = self
            .last_activity
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or_default();
        if idle >= limit {
            tracing::info!(idle_secs = idle.as_secs(), "auto-lock triggered");
            return self.lock();
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_session_is_locked() {
        let s = VaultSession::new();
        assert!(!s.is_unlocked());
        assert!(matches!(s.with(|_| Ok(())), Err(VaultError::Locked)));
    }

    #[test]
    fn locking_an_already_locked_session_reports_nothing_to_do() {
        let s = VaultSession::new();
        assert!(!s.lock());
    }

    #[test]
    fn auto_lock_is_off_by_default() {
        let s = VaultSession::new();
        assert_eq!(s.auto_lock(), None);
        assert!(!s.enforce_auto_lock());
    }

    #[test]
    fn auto_lock_setting_round_trips() {
        let s = VaultSession::new();
        s.set_auto_lock(Some(Duration::from_secs(600)));
        assert_eq!(s.auto_lock(), Some(Duration::from_secs(600)));
        s.set_auto_lock(None);
        assert_eq!(s.auto_lock(), None);
    }

    #[test]
    fn auto_lock_does_nothing_when_no_vault_is_open() {
        let s = VaultSession::new();
        s.set_auto_lock(Some(Duration::from_millis(0)));
        assert!(!s.enforce_auto_lock(), "nothing to lock");
    }
}
