//! On-disk layout of a `.vault` container.
//!
//! ```text
//! offset  size  contents
//! ------  ----  --------------------------------------------------------------
//!      0     8  MAGIC = "VAULTDRV"
//!      8     2  format version (u16 LE)
//!     10     1  cipher id  (1 = XChaCha20-Poly1305)
//!     11     1  kdf id     (1 = Argon2id)
//!     12     4  Argon2id memory cost, KiB (u32 LE)
//!     16     4  Argon2id passes           (u32 LE)
//!     20     4  Argon2id lanes            (u32 LE)
//!     24    32  salt (random per vault)
//!     56     8  reserved, zero
//! ---- 64: end of HEADER. These 64 bytes are the AAD for every AEAD below. ----
//!     64    72  KEYWRAP: nonce24 || enc(master key) || tag16, key = Argon2id(pw)
//!    136    88  SUPERBLOCK slot A
//!    224    88  SUPERBLOCK slot B
//! ---- 312: start of the data region ----------------------------------------
//!    ...        per-file STREAM(XChaCha20-Poly1305) chunk sequences
//!    ...        the encrypted directory index, located by the live superblock
//! ```
//!
//! Nothing outside the 64-byte header is readable without the password. The
//! header itself carries no secrets: an algorithm id, three cost parameters and
//! a random salt. It reveals that the file *is* a vault, and nothing about what
//! is inside it -- not the file count, not the names, not the sizes.
//!
//! ## Why two superblocks
//!
//! A superblock records where the live index is. Editing the vault (rename,
//! delete, import) appends new bytes and then needs to publish a new index
//! location. Rewriting a multi-gigabyte container for a rename is not
//! acceptable, and overwriting a single in-place record is not crash-safe.
//!
//! So there are two fixed slots, each carrying a generation counter and its own
//! authentication tag. A commit writes the *older* slot and flushes. Opening a
//! vault picks the highest generation that authenticates. A crash mid-write
//! leaves the other slot intact and the vault opens at the previous generation,
//! losing the interrupted edit but never the vault.

use crate::crypto::aead::{open as aead_open, seal as aead_seal, NONCE_LEN, TAG_LEN};
use crate::crypto::KdfParams;
use crate::error::{Result, VaultError};

pub const MAGIC: &[u8; 8] = b"VAULTDRV";
pub const FORMAT_VERSION: u16 = 1;

pub const CIPHER_XCHACHA20POLY1305: u8 = 1;
pub const KDF_ARGON2ID: u8 = 1;

pub const HEADER_LEN: usize = 64;
pub const KEYWRAP_OFFSET: u64 = 64;
pub const KEYWRAP_LEN: usize = NONCE_LEN + 32 + TAG_LEN; // 72

pub const SUPERBLOCK_PLAINTEXT_LEN: usize = 48;
pub const SUPERBLOCK_SLOT_LEN: usize = NONCE_LEN + SUPERBLOCK_PLAINTEXT_LEN + TAG_LEN; // 88
pub const SUPERBLOCK_A_OFFSET: u64 = 136;
pub const SUPERBLOCK_B_OFFSET: u64 = SUPERBLOCK_A_OFFSET + SUPERBLOCK_SLOT_LEN as u64; // 224

/// First byte of the data region; also the minimum size of a valid vault.
pub const DATA_START: u64 = SUPERBLOCK_B_OFFSET + SUPERBLOCK_SLOT_LEN as u64; // 312

const AAD_KEYWRAP: &[u8] = b"vaultdrive:v1:keywrap";
const AAD_SUPERBLOCK: &[u8] = b"vaultdrive:v1:superblock";
const AAD_INDEX: &[u8] = b"vaultdrive:v1:index";
const AAD_FILE: &[u8] = b"vaultdrive:v1:file";

/// The plaintext 64-byte header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub cipher: u8,
    pub kdf: u8,
    pub kdf_params: KdfParams,
    pub salt: [u8; 32],
}

impl Header {
    pub fn new(salt: [u8; 32], kdf_params: KdfParams) -> Self {
        Self {
            version: FORMAT_VERSION,
            cipher: CIPHER_XCHACHA20POLY1305,
            kdf: KDF_ARGON2ID,
            kdf_params,
            salt,
        }
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(MAGIC);
        b[8..10].copy_from_slice(&self.version.to_le_bytes());
        b[10] = self.cipher;
        b[11] = self.kdf;
        b[12..16].copy_from_slice(&self.kdf_params.m_cost_kib.to_le_bytes());
        b[16..20].copy_from_slice(&self.kdf_params.t_cost.to_le_bytes());
        b[20..24].copy_from_slice(&self.kdf_params.p_cost.to_le_bytes());
        b[24..56].copy_from_slice(&self.salt);
        // b[56..64] stays zero (reserved)
        b
    }

    /// Parse and sanity-check a header.
    ///
    /// This runs *before* the password is known, so it must be robust against a
    /// hostile file: it validates the magic, refuses a future format version,
    /// refuses unknown algorithm ids, and refuses key-derivation costs that
    /// would exhaust memory. It does not and cannot verify authenticity -- that
    /// happens when the keywrap is opened, which binds these same bytes as AAD.
    pub fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < HEADER_LEN {
            return Err(VaultError::NotAVault);
        }
        if &b[0..8] != MAGIC {
            return Err(VaultError::NotAVault);
        }
        let version = u16::from_le_bytes([b[8], b[9]]);
        if version == 0 || version > FORMAT_VERSION {
            return Err(VaultError::VersionMismatch {
                found: version,
                supported: FORMAT_VERSION,
            });
        }
        let cipher = b[10];
        let kdf = b[11];
        if cipher != CIPHER_XCHACHA20POLY1305 {
            return Err(VaultError::UnsupportedCipher);
        }
        if kdf != KDF_ARGON2ID {
            return Err(VaultError::UnsupportedKdfParameters);
        }

        let kdf_params = KdfParams {
            m_cost_kib: u32::from_le_bytes(b[12..16].try_into().unwrap()),
            t_cost: u32::from_le_bytes(b[16..20].try_into().unwrap()),
            p_cost: u32::from_le_bytes(b[20..24].try_into().unwrap()),
        };
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&b[24..56]);

        Ok(Self { version, cipher, kdf, kdf_params, salt })
    }
}

/// Build the associated data for the wrapped master key.
pub fn keywrap_aad(header: &[u8; HEADER_LEN]) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + AAD_KEYWRAP.len());
    v.extend_from_slice(header);
    v.extend_from_slice(AAD_KEYWRAP);
    v
}

/// Associated data for a superblock slot. The slot number is bound so slot A
/// cannot be copied over slot B to fake a generation.
pub fn superblock_aad(header: &[u8; HEADER_LEN], slot: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + AAD_SUPERBLOCK.len() + 1);
    v.extend_from_slice(header);
    v.extend_from_slice(AAD_SUPERBLOCK);
    v.push(slot);
    v
}

/// Associated data for the directory index. Binding the generation means an
/// older index blob still present in the file will not authenticate against a
/// newer superblock.
pub fn index_aad(header: &[u8; HEADER_LEN], generation: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + AAD_INDEX.len() + 8);
    v.extend_from_slice(header);
    v.extend_from_slice(AAD_INDEX);
    v.extend_from_slice(&generation.to_le_bytes());
    v
}

/// Associated data for every chunk of one file's contents. Binding the file id
/// means a chunk stream cannot be relabelled as a different file, and binding
/// the header means it cannot be moved into another vault.
pub fn file_aad(header: &[u8; HEADER_LEN], file_id: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(HEADER_LEN + AAD_FILE.len() + 8);
    v.extend_from_slice(header);
    v.extend_from_slice(AAD_FILE);
    v.extend_from_slice(&file_id.to_le_bytes());
    v
}

/// The commit record. Encrypted, so even the file count is not observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Superblock {
    /// Monotonically increasing. The live superblock is the highest generation
    /// that authenticates.
    pub generation: u64,
    /// Absolute offset of the encrypted index blob.
    pub index_offset: u64,
    /// Length of the encrypted index blob, including nonce and tag.
    pub index_len: u64,
    /// First free byte of the data region; where the next append starts.
    pub blob_end: u64,
    /// Bytes belonging to deleted or superseded content, reclaimable by
    /// compaction. Purely informational; never trusted for correctness.
    pub dead_bytes: u64,
}

impl Superblock {
    fn encode(&self) -> [u8; SUPERBLOCK_PLAINTEXT_LEN] {
        let mut b = [0u8; SUPERBLOCK_PLAINTEXT_LEN];
        b[0..8].copy_from_slice(&self.generation.to_le_bytes());
        b[8..16].copy_from_slice(&self.index_offset.to_le_bytes());
        b[16..24].copy_from_slice(&self.index_len.to_le_bytes());
        b[24..32].copy_from_slice(&self.blob_end.to_le_bytes());
        b[32..40].copy_from_slice(&self.dead_bytes.to_le_bytes());
        // b[40..48] reserved
        b
    }

    fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < SUPERBLOCK_PLAINTEXT_LEN {
            return Err(VaultError::Integrity);
        }
        Ok(Self {
            generation: u64::from_le_bytes(b[0..8].try_into().unwrap()),
            index_offset: u64::from_le_bytes(b[8..16].try_into().unwrap()),
            index_len: u64::from_le_bytes(b[16..24].try_into().unwrap()),
            blob_end: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            dead_bytes: u64::from_le_bytes(b[32..40].try_into().unwrap()),
        })
    }

    pub fn seal(&self, key: &[u8; 32], header: &[u8; HEADER_LEN], slot: u8) -> Result<Vec<u8>> {
        let sealed = aead_seal(key, &self.encode(), &superblock_aad(header, slot))?;
        debug_assert_eq!(sealed.len(), SUPERBLOCK_SLOT_LEN);
        Ok(sealed)
    }

    pub fn open(
        key: &[u8; 32],
        header: &[u8; HEADER_LEN],
        slot: u8,
        bytes: &[u8],
    ) -> Result<Self> {
        let pt = aead_open(key, bytes, &superblock_aad(header, slot))?;
        Self::decode(&pt)
    }

    /// Structural sanity check against the real file length.
    ///
    /// The superblock is authenticated, so these values are not attacker-chosen
    /// once the password is right. They can still be wrong if the file was
    /// truncated after being written, which is exactly what this catches --
    /// before any seek runs off the end.
    pub fn validate(&self, file_len: u64) -> Result<()> {
        let end = self
            .index_offset
            .checked_add(self.index_len)
            .ok_or(VaultError::Integrity)?;
        if self.index_offset < DATA_START
            || self.index_len < (NONCE_LEN + TAG_LEN) as u64
            || end > file_len
            || self.blob_end < DATA_START
            || self.blob_end > file_len
        {
            return Err(VaultError::Truncated);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header::new([0x5Au8; 32], KdfParams::insecure_fast_for_tests())
    }

    #[test]
    fn header_round_trips() {
        let h = sample_header();
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn offsets_are_what_the_documentation_claims() {
        assert_eq!(HEADER_LEN, 64);
        assert_eq!(KEYWRAP_LEN, 72);
        assert_eq!(SUPERBLOCK_SLOT_LEN, 88);
        assert_eq!(SUPERBLOCK_A_OFFSET, 136);
        assert_eq!(SUPERBLOCK_B_OFFSET, 224);
        assert_eq!(DATA_START, 312);
    }

    #[test]
    fn a_random_file_is_not_a_vault() {
        assert!(matches!(
            Header::decode(&[0u8; 64]),
            Err(VaultError::NotAVault)
        ));
    }

    #[test]
    fn a_short_file_is_not_a_vault() {
        assert!(matches!(Header::decode(b"VAULT"), Err(VaultError::NotAVault)));
    }

    #[test]
    fn a_future_version_is_refused_by_name() {
        let mut b = sample_header().encode();
        b[8..10].copy_from_slice(&99u16.to_le_bytes());
        match Header::decode(&b) {
            Err(VaultError::VersionMismatch { found, supported }) => {
                assert_eq!(found, 99);
                assert_eq!(supported, FORMAT_VERSION);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn an_unknown_cipher_is_refused() {
        let mut b = sample_header().encode();
        b[10] = 42;
        assert!(matches!(Header::decode(&b), Err(VaultError::UnsupportedCipher)));
    }

    #[test]
    fn superblock_round_trips_and_rejects_the_wrong_slot() {
        let key = [2u8; 32];
        let header = sample_header().encode();
        let sb = Superblock {
            generation: 7,
            index_offset: 1000,
            index_len: 200,
            blob_end: 1000,
            dead_bytes: 5,
        };
        let bytes = sb.seal(&key, &header, 0).unwrap();
        assert_eq!(Superblock::open(&key, &header, 0, &bytes).unwrap(), sb);
        assert!(Superblock::open(&key, &header, 1, &bytes).is_err());
    }

    #[test]
    fn superblock_does_not_authenticate_under_a_different_header() {
        let key = [2u8; 32];
        let h1 = sample_header().encode();
        let h2 = Header::new([0xFFu8; 32], KdfParams::insecure_fast_for_tests()).encode();
        let sb = Superblock { generation: 1, index_offset: 400, index_len: 100, blob_end: 400, dead_bytes: 0 };
        let bytes = sb.seal(&key, &h1, 0).unwrap();
        assert!(Superblock::open(&key, &h2, 0, &bytes).is_err());
    }

    #[test]
    fn superblock_validate_catches_truncation() {
        let sb = Superblock { generation: 1, index_offset: 1000, index_len: 500, blob_end: 1000, dead_bytes: 0 };
        assert!(sb.validate(2000).is_ok());
        assert!(sb.validate(1400).is_err(), "index runs past EOF");
        assert!(sb.validate(100).is_err());
    }

    #[test]
    fn superblock_validate_rejects_offsets_inside_the_header() {
        let sb = Superblock { generation: 1, index_offset: 10, index_len: 500, blob_end: 400, dead_bytes: 0 };
        assert!(sb.validate(100_000).is_err());
    }

    #[test]
    fn superblock_validate_survives_an_overflowing_offset() {
        let sb = Superblock {
            generation: 1,
            index_offset: u64::MAX,
            index_len: u64::MAX,
            blob_end: 400,
            dead_bytes: 0,
        };
        assert!(sb.validate(100_000).is_err());
    }

    #[test]
    fn each_aad_purpose_is_distinct() {
        let h = sample_header().encode();
        let all = [
            keywrap_aad(&h),
            superblock_aad(&h, 0),
            index_aad(&h, 0),
            file_aad(&h, 0),
        ];
        for i in 0..all.len() {
            for j in (i + 1)..all.len() {
                assert_ne!(all[i], all[j]);
            }
        }
    }

    #[test]
    fn index_aad_changes_with_the_generation() {
        let h = sample_header().encode();
        assert_ne!(index_aad(&h, 1), index_aad(&h, 2));
    }

    #[test]
    fn file_aad_changes_with_the_file_id() {
        let h = sample_header().encode();
        assert_ne!(file_aad(&h, 1), file_aad(&h, 2));
    }
}
