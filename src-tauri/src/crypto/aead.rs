//! Authenticated encryption helpers.
//!
//! One cipher: XChaCha20-Poly1305, from the RustCrypto `chacha20poly1305`
//! crate. Two shapes:
//!
//! * `seal` / `open` for small one-shot blobs (the wrapped master key, the
//!   superblocks, the directory index).
//! * `ChunkEncryptor` / `ChunkDecryptor` for file contents, built on the
//!   `aead::stream` STREAM construction so a large file is encrypted in
//!   fixed-size chunks that cannot be reordered, duplicated, dropped or
//!   truncated without failing authentication.
//!
//! Every call takes explicit associated data. Callers always bind at least the
//! 64-byte vault header, so a segment lifted out of one vault will not
//! authenticate inside another.

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;

use crate::crypto::random::random_array;
use crate::error::{Result, VaultError};

/// XChaCha20-Poly1305 nonce length for one-shot use.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag length.
pub const TAG_LEN: usize = 16;
/// STREAM reserves the last 5 nonce bytes for its counter and last-block flag.
pub const STREAM_NONCE_LEN: usize = NONCE_LEN - 5;

/// Plaintext bytes per file-content chunk (1 MiB).
///
/// Large enough that the 16-byte tag overhead is negligible (0.0015%), small
/// enough that encryption never needs more than a couple of megabytes of RAM
/// regardless of file size.
pub const CHUNK_SIZE: usize = 1024 * 1024;
/// Ciphertext bytes per full chunk.
pub const CHUNK_CIPHERTEXT_SIZE: usize = CHUNK_SIZE + TAG_LEN;

/// Encrypt `plaintext` into `nonce || ciphertext || tag`.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
    let nonce: [u8; NONCE_LEN] = random_array();
    let ct = cipher.encrypt(
        GenericArray::from_slice(&nonce),
        Payload { msg: plaintext, aad },
    )?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Inverse of [`seal`]. Any failure -- wrong key, altered ciphertext, altered
/// AAD, short input -- returns [`VaultError::Authentication`].
pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(VaultError::Authentication);
    }
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
    cipher
        .decrypt(GenericArray::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| VaultError::Authentication)
}

/// Total ciphertext length for a plaintext of `n` bytes under the chunked
/// scheme. A zero-byte file still costs one tag, because it still gets one
/// authenticated (empty) final chunk.
pub fn chunked_ciphertext_len(n: u64) -> u64 {
    let full = n / CHUNK_SIZE as u64;
    let rem = n % CHUNK_SIZE as u64;
    if rem == 0 && full > 0 {
        full * CHUNK_CIPHERTEXT_SIZE as u64
    } else {
        full * CHUNK_CIPHERTEXT_SIZE as u64 + rem + TAG_LEN as u64
    }
}

/// Streaming encryptor for one file's contents.
pub struct ChunkEncryptor {
    inner: Option<EncryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
}

impl ChunkEncryptor {
    /// `nonce` must be freshly random per file; it is stored in the index.
    pub fn new(key: &[u8; 32], nonce: &[u8; STREAM_NONCE_LEN], aad: Vec<u8>) -> Self {
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        Self {
            inner: Some(EncryptorBE32::from_aead(
                cipher,
                GenericArray::from_slice(nonce),
            )),
            aad,
        }
    }

    /// Encrypt one non-final chunk. `plaintext` must be exactly [`CHUNK_SIZE`].
    pub fn next(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let enc = self.inner.as_mut().ok_or(VaultError::Integrity)?;
        Ok(enc.encrypt_next(Payload { msg: plaintext, aad: &self.aad })?)
    }

    /// Encrypt the final chunk and consume the encryptor. Must always be
    /// called, even for an empty file, or the stream is not terminated and
    /// decryption will correctly refuse it as truncated.
    pub fn last(mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let enc = self.inner.take().ok_or(VaultError::Integrity)?;
        Ok(enc.encrypt_last(Payload { msg: plaintext, aad: &self.aad })?)
    }
}

/// Streaming decryptor for one file's contents.
pub struct ChunkDecryptor {
    inner: Option<DecryptorBE32<XChaCha20Poly1305>>,
    aad: Vec<u8>,
}

impl ChunkDecryptor {
    pub fn new(key: &[u8; 32], nonce: &[u8; STREAM_NONCE_LEN], aad: Vec<u8>) -> Self {
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(key));
        Self {
            inner: Some(DecryptorBE32::from_aead(
                cipher,
                GenericArray::from_slice(nonce),
            )),
            aad,
        }
    }

    pub fn next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let dec = self.inner.as_mut().ok_or(VaultError::Integrity)?;
        dec.decrypt_next(Payload { msg: ciphertext, aad: &self.aad })
            .map_err(|_| VaultError::Integrity)
    }

    pub fn last(mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let dec = self.inner.take().ok_or(VaultError::Integrity)?;
        dec.decrypt_last(Payload { msg: ciphertext, aad: &self.aad })
            .map_err(|_| VaultError::Integrity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = [4u8; 32];
        let sealed = seal(&key, b"hello vault", b"header").unwrap();
        assert_eq!(open(&key, &sealed, b"header").unwrap(), b"hello vault");
    }

    #[test]
    fn seal_is_randomised_per_call() {
        let key = [4u8; 32];
        let a = seal(&key, b"same", b"aad").unwrap();
        let b = seal(&key, b"same", b"aad").unwrap();
        assert_ne!(a, b, "a fixed nonce would be a catastrophic reuse bug");
    }

    #[test]
    fn wrong_key_fails() {
        let sealed = seal(&[4u8; 32], b"secret", b"aad").unwrap();
        assert!(open(&[5u8; 32], &sealed, b"aad").is_err());
    }

    #[test]
    fn wrong_aad_fails() {
        let key = [4u8; 32];
        let sealed = seal(&key, b"secret", b"header-a").unwrap();
        assert!(open(&key, &sealed, b"header-b").is_err());
    }

    #[test]
    fn any_flipped_bit_fails() {
        let key = [4u8; 32];
        let sealed = seal(&key, b"secret message here", b"aad").unwrap();
        for i in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[i] ^= 0x01;
            assert!(open(&key, &bad, b"aad").is_err(), "byte {i} was not authenticated");
        }
    }

    #[test]
    fn truncated_blob_fails_without_panicking() {
        let key = [4u8; 32];
        let sealed = seal(&key, b"secret", b"aad").unwrap();
        for cut in 0..sealed.len() {
            assert!(open(&key, &sealed[..cut], b"aad").is_err());
        }
    }

    fn chunked_round_trip(data: &[u8]) {
        let key = [7u8; 32];
        let nonce = [1u8; STREAM_NONCE_LEN];
        let aad = b"file-aad".to_vec();

        let mut enc = ChunkEncryptor::new(&key, &nonce, aad.clone());
        let mut wire = Vec::new();
        let mut chunks = data.chunks(CHUNK_SIZE).peekable();
        if data.is_empty() {
            wire.extend(enc.last(&[]).unwrap());
        } else {
            while let Some(c) = chunks.next() {
                if chunks.peek().is_none() {
                    wire.extend(enc.last(c).unwrap());
                    break;
                }
                wire.extend(enc.next(c).unwrap());
            }
        }

        assert_eq!(wire.len() as u64, chunked_ciphertext_len(data.len() as u64));

        let mut dec = ChunkDecryptor::new(&key, &nonce, aad);
        let mut out = Vec::new();
        let mut cursor = 0usize;
        loop {
            let remaining = wire.len() - cursor;
            if remaining <= CHUNK_CIPHERTEXT_SIZE {
                out.extend(dec.last(&wire[cursor..]).unwrap());
                break;
            }
            out.extend(dec.next(&wire[cursor..cursor + CHUNK_CIPHERTEXT_SIZE]).unwrap());
            cursor += CHUNK_CIPHERTEXT_SIZE;
        }
        assert_eq!(out, data);
    }

    #[test]
    fn chunked_empty_file() {
        chunked_round_trip(b"");
    }

    #[test]
    fn chunked_small_file() {
        chunked_round_trip(b"a short note");
    }

    #[test]
    fn chunked_exactly_one_chunk() {
        chunked_round_trip(&vec![0xA5u8; CHUNK_SIZE]);
    }

    #[test]
    fn chunked_multi_chunk_binary() {
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 12345)).map(|i| (i % 251) as u8).collect();
        chunked_round_trip(&data);
    }

    #[test]
    fn dropping_the_final_chunk_fails() {
        let key = [7u8; 32];
        let nonce = [1u8; STREAM_NONCE_LEN];
        let data = vec![0x11u8; CHUNK_SIZE + 100];

        let mut enc = ChunkEncryptor::new(&key, &nonce, b"aad".to_vec());
        let first = enc.next(&data[..CHUNK_SIZE]).unwrap();
        let _last = enc.last(&data[CHUNK_SIZE..]).unwrap();

        // Try to pass the non-final chunk off as the whole file.
        let dec = ChunkDecryptor::new(&key, &nonce, b"aad".to_vec());
        assert!(dec.last(&first).is_err());
    }

    #[test]
    fn swapping_two_chunks_fails() {
        let key = [7u8; 32];
        let nonce = [1u8; STREAM_NONCE_LEN];
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2)).map(|i| (i % 97) as u8).collect();

        let mut enc = ChunkEncryptor::new(&key, &nonce, b"aad".to_vec());
        let c0 = enc.next(&data[..CHUNK_SIZE]).unwrap();
        let c1 = enc.last(&data[CHUNK_SIZE..]).unwrap();

        let mut dec = ChunkDecryptor::new(&key, &nonce, b"aad".to_vec());
        // Feeding chunk 1 where chunk 0 belongs must fail: the counter differs.
        assert!(dec.next(&c1).is_err());
        drop(c0);
    }

    #[test]
    fn ciphertext_length_formula_matches_reality() {
        assert_eq!(chunked_ciphertext_len(0), TAG_LEN as u64);
        assert_eq!(chunked_ciphertext_len(1), 1 + TAG_LEN as u64);
        assert_eq!(chunked_ciphertext_len(CHUNK_SIZE as u64), CHUNK_CIPHERTEXT_SIZE as u64);
        assert_eq!(
            chunked_ciphertext_len(CHUNK_SIZE as u64 + 1),
            CHUNK_CIPHERTEXT_SIZE as u64 + 1 + TAG_LEN as u64
        );
    }
}
