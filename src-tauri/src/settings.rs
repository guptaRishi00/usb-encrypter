//! User preferences and the recent-vaults list.
//!
//! This is the only file VaultDrive writes outside a vault, and it deliberately
//! holds nothing secret: a theme name, an auto-lock interval, and the paths of
//! vaults the user has opened before, so the home screen can list them.
//!
//! There is no field for a password, a key, or anything derived from one. The
//! struct is exhaustive and serialised with `deny_unknown_fields`, so a future
//! edit cannot quietly add one without this file changing.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Result, VaultError};

pub const AUTO_LOCK_CHOICES_MINUTES: [u64; 5] = [0, 5, 10, 30, 60];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecentVault {
    pub path: String,
    pub name: String,
    /// Seconds since the Unix epoch.
    pub last_opened: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Settings {
    /// `"system"`, `"light"` or `"dark"`.
    pub theme: String,
    /// Minutes of inactivity before the vault locks itself. Zero means never.
    pub auto_lock_minutes: u64,
    pub recent: Vec<RecentVault>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".into(),
            // Ten minutes by default: long enough not to annoy, short enough
            // that a walked-away-from laptop does not sit unlocked all day.
            auto_lock_minutes: 10,
            recent: Vec::new(),
        }
    }
}

impl Settings {
    fn file(dir: &Path) -> PathBuf {
        dir.join("settings.json")
    }

    /// Load settings, falling back to defaults for anything unreadable.
    ///
    /// A corrupt settings file must never stop the application from starting,
    /// and must never be a reason to prompt for anything.
    pub fn load(dir: &Path) -> Self {
        fs::read_to_string(Self::file(dir))
            .ok()
            .and_then(|s| serde_json::from_str::<Self>(&s).ok())
            .map(|mut s| {
                s.normalise();
                s
            })
            .unwrap_or_default()
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        fs::create_dir_all(dir).map_err(|e| VaultError::from_io(&e, dir))?;
        let path = Self::file(dir);
        let json = serde_json::to_string_pretty(self)
            .map_err(|_| VaultError::Io("Could not save settings.".into()))?;
        fs::write(&path, json).map_err(|e| VaultError::from_io(&e, &path))
    }

    fn normalise(&mut self) {
        if !matches!(self.theme.as_str(), "system" | "light" | "dark") {
            self.theme = "system".into();
        }
        if !AUTO_LOCK_CHOICES_MINUTES.contains(&self.auto_lock_minutes) {
            self.auto_lock_minutes = 10;
        }
        self.recent.truncate(12);
    }

    /// Move `path` to the front of the recent list.
    pub fn remember(&mut self, path: &str, name: &str, when: i64) {
        self.recent.retain(|r| !path_eq(&r.path, path));
        self.recent.insert(
            0,
            RecentVault { path: path.to_string(), name: name.to_string(), last_opened: when },
        );
        self.recent.truncate(12);
    }

    pub fn forget(&mut self, path: &str) {
        self.recent.retain(|r| !path_eq(&r.path, path));
    }

    pub fn auto_lock_duration(&self) -> Option<std::time::Duration> {
        if self.auto_lock_minutes == 0 {
            None
        } else {
            Some(std::time::Duration::from_secs(self.auto_lock_minutes * 60))
        }
    }
}

/// Windows paths are case-insensitive; elsewhere they are not.
fn path_eq(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let s = Settings::default();
        assert_eq!(s.theme, "system");
        assert_eq!(s.auto_lock_minutes, 10);
        assert!(s.recent.is_empty());
    }

    #[test]
    fn settings_round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        s.theme = "dark".into();
        s.auto_lock_minutes = 30;
        s.remember("D:/MyVault.vault", "My Vault", 1000);
        s.save(dir.path()).unwrap();

        let back = Settings::load(dir.path());
        assert_eq!(back, s);
    }

    #[test]
    fn the_saved_file_contains_nothing_secret() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = Settings::default();
        s.remember("D:/MyVault.vault", "My Vault", 1000);
        s.save(dir.path()).unwrap();

        let raw = fs::read_to_string(dir.path().join("settings.json")).unwrap().to_lowercase();
        for forbidden in ["password", "passphrase", "key", "secret", "salt", "nonce", "token"] {
            assert!(!raw.contains(forbidden), "settings.json mentions '{forbidden}'");
        }
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        // If a future change ever tries to persist a secret, this fails loudly
        // instead of silently accepting it.
        let json = r#"{"theme":"dark","autoLockMinutes":10,"recent":[],"password":"hunter2"}"#;
        assert!(serde_json::from_str::<Settings>(json).is_err());
    }

    #[test]
    fn a_corrupt_settings_file_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("settings.json"), b"{ this is not json").unwrap();
        assert_eq!(Settings::load(dir.path()), Settings::default());
    }

    #[test]
    fn out_of_range_values_are_normalised_on_load() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("settings.json"),
            r#"{"theme":"neon","autoLockMinutes":7,"recent":[]}"#,
        )
        .unwrap();
        let s = Settings::load(dir.path());
        assert_eq!(s.theme, "system");
        assert_eq!(s.auto_lock_minutes, 10);
    }

    #[test]
    fn remembering_the_same_vault_twice_keeps_one_entry_at_the_front() {
        let mut s = Settings::default();
        s.remember("D:/a.vault", "A", 1);
        s.remember("D:/b.vault", "B", 2);
        s.remember("D:/a.vault", "A", 3);
        assert_eq!(s.recent.len(), 2);
        assert_eq!(s.recent[0].path, "D:/a.vault");
        assert_eq!(s.recent[0].last_opened, 3);
    }

    #[test]
    fn the_recent_list_is_capped() {
        let mut s = Settings::default();
        for i in 0..50 {
            s.remember(&format!("D:/v{i}.vault"), "v", i);
        }
        assert_eq!(s.recent.len(), 12);
    }

    #[test]
    fn forgetting_removes_an_entry() {
        let mut s = Settings::default();
        s.remember("D:/a.vault", "A", 1);
        s.forget("D:/a.vault");
        assert!(s.recent.is_empty());
    }

    #[test]
    fn never_maps_to_no_auto_lock() {
        let mut s = Settings::default();
        s.auto_lock_minutes = 0;
        assert_eq!(s.auto_lock_duration(), None);
        s.auto_lock_minutes = 5;
        assert_eq!(s.auto_lock_duration(), Some(std::time::Duration::from_secs(300)));
    }
}
