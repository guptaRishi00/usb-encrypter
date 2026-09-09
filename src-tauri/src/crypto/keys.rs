//! Master key and subkey derivation.
//!
//! A vault has one random 32-byte master key, generated at creation time and
//! stored only in the AEAD-wrapped `KEYWRAP` block. Everything else is an
//! HKDF-SHA256 subkey of it, so no single key is reused across two different
//! purposes.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::random::fill_random;

/// Purpose labels fed to HKDF as `info`. Changing one of these strings changes
/// every key derived from it, so they are part of the on-disk format.
const INFO_INDEX: &[u8] = b"vaultdrive:v1:index";
const INFO_SUPERBLOCK: &[u8] = b"vaultdrive:v1:superblock";
const INFO_CONTENT: &[u8] = b"vaultdrive:v1:content";

/// A 32-byte key that wipes itself on drop.
pub type Key32 = Zeroizing<[u8; 32]>;

/// The vault's root secret. Never written to disk unencrypted, never logged,
/// never returned to the frontend.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey(pub(crate) [u8; 32]);

impl std::fmt::Debug for MasterKey {
    /// Deliberately opaque so a stray `{:?}` in a log line cannot leak the key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl MasterKey {
    /// Generate a fresh master key from the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut k = [0u8; 32];
        fill_random(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    fn subkey(&self, salt: &[u8; 32], info: &[u8]) -> Key32 {
        let hk = Hkdf::<Sha256>::new(Some(salt), &self.0);
        let mut out: Key32 = Zeroizing::new([0u8; 32]);
        // HKDF-Expand with a 32-byte output can only fail for absurd lengths.
        hk.expand(info, out.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }

    /// Key protecting the encrypted directory index.
    pub fn index_key(&self, salt: &[u8; 32]) -> Key32 {
        self.subkey(salt, INFO_INDEX)
    }

    /// Key protecting the two superblock slots.
    pub fn superblock_key(&self, salt: &[u8; 32]) -> Key32 {
        self.subkey(salt, INFO_SUPERBLOCK)
    }

    /// Key protecting file contents.
    pub fn content_key(&self, salt: &[u8; 32]) -> Key32 {
        self.subkey(salt, INFO_CONTENT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subkeys_differ_from_each_other_and_from_the_master() {
        let mk = MasterKey::from_bytes([9u8; 32]);
        let salt = [3u8; 32];
        let i = mk.index_key(&salt);
        let s = mk.superblock_key(&salt);
        let c = mk.content_key(&salt);
        assert_ne!(i.as_ref(), s.as_ref());
        assert_ne!(i.as_ref(), c.as_ref());
        assert_ne!(s.as_ref(), c.as_ref());
        assert_ne!(i.as_ref(), mk.expose());
    }

    #[test]
    fn subkeys_are_deterministic() {
        let mk = MasterKey::from_bytes([9u8; 32]);
        let salt = [3u8; 32];
        assert_eq!(mk.index_key(&salt).as_ref(), mk.index_key(&salt).as_ref());
    }

    #[test]
    fn the_same_master_under_a_different_salt_gives_different_subkeys() {
        let mk = MasterKey::from_bytes([9u8; 32]);
        assert_ne!(
            mk.content_key(&[1u8; 32]).as_ref(),
            mk.content_key(&[2u8; 32]).as_ref()
        );
    }

    #[test]
    fn debug_never_prints_key_material() {
        let mk = MasterKey::from_bytes([0xABu8; 32]);
        let rendered = format!("{mk:?}");
        assert_eq!(rendered, "MasterKey(<redacted>)");
        assert!(!rendered.contains("171") && !rendered.to_lowercase().contains("ab"));
    }

    #[test]
    fn generated_keys_are_not_all_zero_and_not_repeated() {
        let a = MasterKey::generate();
        let b = MasterKey::generate();
        assert_ne!(a.expose(), &[0u8; 32]);
        assert_ne!(a.expose(), b.expose());
    }
}
