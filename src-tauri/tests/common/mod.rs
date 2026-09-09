//! Shared helpers for the integration suites.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use vaultdrive_lib::crypto::KdfParams;
use vaultdrive_lib::error::Result;
use vaultdrive_lib::vault::{
    create_vault_from_folder, CreateReport, NoProgress, OpenVault, VaultIndex,
};

/// Argon2id parameters used by the tests.
///
/// Eight kibibytes and a single pass, so a suite that creates a hundred vaults
/// finishes in seconds. The application always uses
/// `KdfParams::interactive()`; nothing here changes that.
pub fn fast_kdf() -> KdfParams {
    KdfParams::insecure_fast_for_tests()
}

pub struct Fixture {
    pub dir: tempfile::TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        Self { dir: tempfile::tempdir().expect("temp dir") }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// Build a source folder from `(relative path, contents)` pairs.
    pub fn source(&self, name: &str, files: &[(&str, &[u8])]) -> PathBuf {
        let root = self.path(name);
        fs::create_dir_all(&root).unwrap();
        for (rel, data) in files {
            let p = root.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(&p, data).unwrap();
        }
        root
    }

    pub fn create(
        &self,
        source: &Path,
        vault_file: &str,
        password: &str,
    ) -> Result<CreateReport> {
        create_vault_from_folder(
            source,
            &self.path(vault_file),
            password.as_bytes(),
            "Test Vault",
            fast_kdf(),
            &NoProgress,
        )
    }

    pub fn unlock(&self, vault_file: &str, password: &str) -> Result<OpenVault> {
        OpenVault::unlock(&self.path(vault_file), password.as_bytes())
    }
}

/// Every stored file as `path -> contents`, decrypted.
pub fn dump(vault: &mut OpenVault) -> std::collections::BTreeMap<String, Vec<u8>> {
    let files: Vec<(u64, String)> = vault
        .index()
        .nodes
        .iter()
        .filter(|n| !n.is_dir())
        .map(|n| (n.id, vault.index().path_of(n.id).unwrap()))
        .collect();
    let mut out = std::collections::BTreeMap::new();
    for (id, path) in files {
        out.insert(path, vault.read_file_to_vec(id, usize::MAX).unwrap());
    }
    out
}

/// Every folder path in the vault.
pub fn folders(index: &VaultIndex) -> std::collections::BTreeSet<String> {
    index
        .nodes
        .iter()
        .filter(|n| n.is_dir() && n.id != vaultdrive_lib::vault::ROOT_ID)
        .map(|n| index.path_of(n.id).unwrap())
        .collect()
}

/// Find an entry by its slash-separated path inside the vault.
pub fn id_of(index: &VaultIndex, path: &str) -> Option<u64> {
    index
        .nodes
        .iter()
        .find(|n| index.path_of(n.id).ok().as_deref() == Some(path))
        .map(|n| n.id)
}

/// Read a whole vault file into memory. Only used to inspect ciphertext.
pub fn raw(path: &Path) -> Vec<u8> {
    fs::read(path).unwrap()
}
