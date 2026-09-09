//! Reading, writing and editing a `.vault` container.
//!
//! An [`OpenVault`] is the unlocked state: an open file handle plus the derived
//! subkeys and the decrypted directory index. Locking drops it, which wipes the
//! keys (they are `Zeroizing`) and closes the handle.
//!
//! Edits never rewrite the whole container. Content is appended, then a new
//! index is appended after it, then one of the two superblock slots is
//! overwritten. That last 88-byte write is the commit point; everything before
//! it is invisible to a reader still following the old superblock.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::aead::{
    chunked_ciphertext_len, open as aead_open, seal as aead_seal, ChunkDecryptor, ChunkEncryptor,
    CHUNK_CIPHERTEXT_SIZE, CHUNK_SIZE, STREAM_NONCE_LEN,
};
use crate::crypto::keys::Key32;
use crate::crypto::random::random_array;
use crate::crypto::{derive_kek, KdfParams, MasterKey};
use crate::error::{Result, VaultError};
use crate::filesystem::atomic::{sync_file, TempVaultFile};
use crate::vault::format::{
    file_aad, index_aad, keywrap_aad, Header, Superblock, DATA_START, HEADER_LEN, KEYWRAP_LEN,
    KEYWRAP_OFFSET, SUPERBLOCK_A_OFFSET, SUPERBLOCK_B_OFFSET, SUPERBLOCK_SLOT_LEN,
};
use crate::vault::index::{validate_name, VaultIndex, ROOT_ID};
use crate::vault::progress::{ProgressSink, ProgressSnapshot};

/// Largest file VaultDrive will decrypt into memory for in-app preview.
pub const PREVIEW_LIMIT: usize = 32 * 1024 * 1024;

fn slot_offset(slot: u8) -> u64 {
    if slot == 0 { SUPERBLOCK_A_OFFSET } else { SUPERBLOCK_B_OFFSET }
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Chunked file writing
// ---------------------------------------------------------------------------

/// One file's ciphertext stream, being written.
///
/// Callers push arbitrary-sized slices; this buffers them into exact
/// [`CHUNK_SIZE`] blocks so the STREAM chunk boundaries are identical no matter
/// how the source delivered the bytes. A block is only emitted once at least
/// one more byte is known to follow, which is what lets `finish` always emit a
/// properly terminated final chunk.
struct FileStream {
    id: u64,
    nonce: [u8; STREAM_NONCE_LEN],
    offset: u64,
    enc: Option<ChunkEncryptor>,
    buf: Vec<u8>,
    ct_len: u64,
    pt_len: u64,
}

impl FileStream {
    fn begin(
        file: &mut File,
        path: &Path,
        key: &[u8; 32],
        id: u64,
        offset: u64,
        aad: Vec<u8>,
    ) -> Result<Self> {
        let nonce: [u8; STREAM_NONCE_LEN] = random_array();
        file.seek(SeekFrom::Start(offset)).map_err(|e| VaultError::from_io(&e, path))?;
        Ok(Self {
            id,
            nonce,
            offset,
            enc: Some(ChunkEncryptor::new(key, &nonce, aad)),
            // Grown on demand rather than pre-sized to a chunk. The buffer is
            // wiped on drop, and wiping is a volatile byte-by-byte write, so a
            // buffer reserved to a megabyte would cost a megabyte of wiping for
            // every file in the vault however small it is.
            buf: Vec::new(),
            ct_len: 0,
            pt_len: 0,
        })
    }

    fn push(&mut self, file: &mut File, path: &Path, data: &[u8]) -> Result<()> {
        self.pt_len += data.len() as u64;
        self.buf.extend_from_slice(data);
        while self.buf.len() > CHUNK_SIZE {
            let enc = self.enc.as_mut().ok_or(VaultError::Integrity)?;
            let ct = enc.next(&self.buf[..CHUNK_SIZE])?;
            file.write_all(&ct).map_err(|e| VaultError::from_io(&e, path))?;
            self.ct_len += ct.len() as u64;
            self.buf.drain(..CHUNK_SIZE);
        }
        Ok(())
    }

    /// Emit the final chunk. Always called, even for an empty file, because an
    /// unterminated stream is indistinguishable from a truncated one.
    fn finish(mut self, file: &mut File, path: &Path) -> Result<FileStreamResult> {
        let enc = self.enc.take().ok_or(VaultError::Integrity)?;
        let ct = enc.last(&self.buf)?;
        file.write_all(&ct).map_err(|e| VaultError::from_io(&e, path))?;
        self.ct_len += ct.len() as u64;
        // `self` is dropped on the way out of this function, and `Drop` wipes
        // the buffer. Doing it here as well would wipe the same megabyte twice.

        Ok(FileStreamResult {
            id: self.id,
            nonce: self.nonce.to_vec(),
            offset: self.offset,
            ct_len: self.ct_len,
            pt_len: self.pt_len,
        })
    }
}

impl Drop for FileStream {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

struct FileStreamResult {
    id: u64,
    nonce: Vec<u8>,
    offset: u64,
    ct_len: u64,
    pt_len: u64,
}

/// Copy `expected_size` bytes from `reader` into an open [`FileStream`].
///
/// Fails with `SourceChanged` if the reader supplies a different number of
/// bytes, so a file that grew or shrank mid-encryption is reported rather than
/// stored with a size that lies.
fn pump_reader<R: Read>(
    stream: &mut FileStream,
    file: &mut File,
    path: &Path,
    reader: &mut R,
    expected_size: u64,
    display_name: &str,
    progress: &dyn ProgressSink,
    on_bytes: &mut dyn FnMut(u64),
) -> Result<()> {
    // Sized to the file, capped at one chunk. This buffer is wiped when it goes
    // out of scope, so pre-sizing it to a megabyte would make every small file
    // pay for a megabyte of wiping it never used.
    let mut buf = Zeroizing::new(vec![0u8; expected_size.min(CHUNK_SIZE as u64) as usize]);
    let mut remaining = expected_size;

    while remaining > 0 {
        if progress.is_cancelled() {
            return Err(VaultError::Cancelled);
        }
        let take = remaining.min(CHUNK_SIZE as u64) as usize;
        reader
            .read_exact(&mut buf[..take])
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    VaultError::SourceChanged { name: display_name.to_string() }
                }
                _ => VaultError::from_io(&e, Path::new(display_name)),
            })?;
        stream.push(file, path, &buf[..take])?;
        remaining -= take as u64;
        on_bytes(take as u64);
    }

    let mut probe = [0u8; 1];
    if matches!(reader.read(&mut probe), Ok(n) if n > 0) {
        return Err(VaultError::SourceChanged { name: display_name.to_string() });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenVault
// ---------------------------------------------------------------------------

/// An unlocked vault.
///
/// Dropping this is what "lock" means: the master key and subkeys are wiped by
/// their `Zeroize` implementations and the file handle is closed.
pub struct OpenVault {
    file: File,
    path: PathBuf,
    header_bytes: [u8; HEADER_LEN],
    header: Header,
    master: MasterKey,
    index_key: Key32,
    superblock_key: Key32,
    content_key: Key32,
    superblock: Superblock,
    live_slot: u8,
    read_only: bool,
    index: VaultIndex,
}

impl std::fmt::Debug for OpenVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No keys, no names, no path: this type is easy to log by accident.
        f.debug_struct("OpenVault")
            .field("generation", &self.superblock.generation)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

impl OpenVault {
    pub fn index(&self) -> &VaultIndex {
        &self.index
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }
    pub fn kdf_params(&self) -> KdfParams {
        self.header.kdf_params
    }
    pub fn generation(&self) -> u64 {
        self.superblock.generation
    }
    pub fn dead_bytes(&self) -> u64 {
        self.superblock.dead_bytes
    }

    // ---------------------------------------------------------------- unlock

    /// Unlock a vault with a password.
    ///
    /// The password is used once, to derive the key-encryption key, and is
    /// never stored. Every failure after the header parse -- wrong password,
    /// altered header, altered keywrap -- returns the same
    /// [`VaultError::Authentication`], so nothing here is a password oracle.
    pub fn unlock(path: &Path, password: &[u8]) -> Result<Self> {
        // Prefer read/write so edits work, but a vault on write-protected media
        // should still open for browsing and export.
        let (mut file, read_only) = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => (f, false),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (
                File::open(path).map_err(|e| VaultError::from_io(&e, path))?,
                true,
            ),
            Err(e) => return Err(VaultError::from_io(&e, path)),
        };

        let file_len = file.metadata().map_err(|e| VaultError::from_io(&e, path))?.len();
        if file_len < DATA_START {
            return Err(if file_len < HEADER_LEN as u64 {
                VaultError::NotAVault
            } else {
                VaultError::Truncated
            });
        }

        let mut header_bytes = [0u8; HEADER_LEN];
        file.seek(SeekFrom::Start(0)).map_err(|e| VaultError::from_io(&e, path))?;
        file.read_exact(&mut header_bytes).map_err(|e| VaultError::from_io(&e, path))?;
        let header = Header::decode(&header_bytes)?;

        let mut keywrap = [0u8; KEYWRAP_LEN];
        file.seek(SeekFrom::Start(KEYWRAP_OFFSET)).map_err(|e| VaultError::from_io(&e, path))?;
        file.read_exact(&mut keywrap).map_err(|e| VaultError::from_io(&e, path))?;

        // The only expensive step, and the only one that touches the password.
        let kek = derive_kek(password, &header.salt, header.kdf_params)?;
        let master_bytes = Zeroizing::new(aead_open(&kek, &keywrap, &keywrap_aad(&header_bytes))?);
        drop(kek);
        if master_bytes.len() != 32 {
            return Err(VaultError::Authentication);
        }
        let mut mk = [0u8; 32];
        mk.copy_from_slice(&master_bytes);
        let master = MasterKey::from_bytes(mk);

        let me = Self::assemble(file, path, header, header_bytes, master, read_only, file_len)?;
        tracing::info!(
            generation = me.superblock.generation,
            entries = me.index.nodes.len(),
            "vault unlocked"
        );
        Ok(me)
    }

    /// Shared tail of `unlock` and `adopt`: pick the live superblock and decrypt
    /// the index.
    fn assemble(
        mut file: File,
        path: &Path,
        header: Header,
        header_bytes: [u8; HEADER_LEN],
        master: MasterKey,
        read_only: bool,
        file_len: u64,
    ) -> Result<Self> {
        let index_key = master.index_key(&header.salt);
        let superblock_key = master.superblock_key(&header.salt);
        let content_key = master.content_key(&header.salt);

        // Newest superblock that authenticates wins. A slot that fails is not
        // an error by itself: a torn commit leaves exactly that.
        let mut best: Option<(u8, Superblock)> = None;
        for slot in [0u8, 1u8] {
            let mut buf = [0u8; SUPERBLOCK_SLOT_LEN];
            file.seek(SeekFrom::Start(slot_offset(slot)))
                .map_err(|e| VaultError::from_io(&e, path))?;
            if file.read_exact(&mut buf).is_err() {
                continue;
            }
            if let Ok(sb) = Superblock::open(&superblock_key, &header_bytes, slot, &buf) {
                if sb.validate(file_len).is_ok()
                    && best.map_or(true, |(_, b)| sb.generation > b.generation)
                {
                    best = Some((slot, sb));
                }
            }
        }
        // Both slots unreadable with a key that just successfully unwrapped the
        // master key means the body is damaged, not that the password is wrong.
        let (live_slot, superblock) = best.ok_or(VaultError::Integrity)?;

        let mut blob = vec![0u8; superblock.index_len as usize];
        file.seek(SeekFrom::Start(superblock.index_offset))
            .map_err(|e| VaultError::from_io(&e, path))?;
        file.read_exact(&mut blob).map_err(|_| VaultError::Truncated)?;
        let json = Zeroizing::new(
            aead_open(&index_key, &blob, &index_aad(&header_bytes, superblock.generation))
                .map_err(|_| VaultError::Integrity)?,
        );
        let index = VaultIndex::from_json(&json)?;

        Ok(Self {
            file,
            path: path.to_path_buf(),
            header_bytes,
            header,
            master,
            index_key,
            superblock_key,
            content_key,
            superblock,
            live_slot,
            read_only,
            index,
        })
    }

    /// Re-open a container using a master key already in memory. No password.
    fn adopt(path: &Path, header: Header, master: &MasterKey) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| VaultError::from_io(&e, path))?;
        let file_len = file.metadata().map_err(|e| VaultError::from_io(&e, path))?.len();
        let header_bytes = header.encode();
        Self::assemble(
            file,
            path,
            header,
            header_bytes,
            MasterKey::from_bytes(*master.expose()),
            false,
            file_len,
        )
    }

    /// Read a vault's public header without a password.
    pub fn peek_header(path: &Path) -> Result<Header> {
        let mut file = File::open(path).map_err(|e| VaultError::from_io(&e, path))?;
        let mut header_bytes = [0u8; HEADER_LEN];
        file.read_exact(&mut header_bytes).map_err(|_| VaultError::NotAVault)?;
        Header::decode(&header_bytes)
    }

    // ----------------------------------------------------------------- commit

    fn require_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(VaultError::PermissionDenied {
                name: self
                    .path
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "this vault".into()),
            });
        }
        Ok(())
    }

    /// Publish the in-memory index as a new generation.
    ///
    /// The order is the whole crash-safety argument: append the index, flush it
    /// to the device, overwrite the *other* superblock slot, flush again. Until
    /// that second flush the vault still opens at the previous generation.
    fn commit(&mut self, extra_dead: u64) -> Result<()> {
        self.require_writable()?;

        let generation = self.superblock.generation.checked_add(1).ok_or(VaultError::Integrity)?;
        let json = Zeroizing::new(self.index.to_json()?);
        let blob = aead_seal(&self.index_key, &json, &index_aad(&self.header_bytes, generation))?;

        let index_offset = self.superblock.blob_end;
        self.file.seek(SeekFrom::Start(index_offset)).map_err(|e| VaultError::from_io(&e, &self.path))?;
        self.file.write_all(&blob).map_err(|e| VaultError::from_io(&e, &self.path))?;
        self.file.flush().map_err(|e| VaultError::from_io(&e, &self.path))?;
        sync_file(&self.file, &self.path)?;

        let next = Superblock {
            generation,
            index_offset,
            index_len: blob.len() as u64,
            // Content appended after this point must land beyond the live
            // index, or a crash would leave the superblock pointing at
            // overwritten bytes.
            blob_end: index_offset + blob.len() as u64,
            dead_bytes: self
                .superblock
                .dead_bytes
                .saturating_add(self.superblock.index_len)
                .saturating_add(extra_dead),
        };

        let target_slot = 1 - self.live_slot;
        let sealed = next.seal(&self.superblock_key, &self.header_bytes, target_slot)?;
        self.file
            .seek(SeekFrom::Start(slot_offset(target_slot)))
            .map_err(|e| VaultError::from_io(&e, &self.path))?;
        self.file.write_all(&sealed).map_err(|e| VaultError::from_io(&e, &self.path))?;
        self.file.flush().map_err(|e| VaultError::from_io(&e, &self.path))?;
        sync_file(&self.file, &self.path)?;

        self.superblock = next;
        self.live_slot = target_slot;
        tracing::debug!(generation, "vault commit");
        Ok(())
    }

    // ------------------------------------------------------------- read paths

    /// Decrypt one file, handing each plaintext chunk to `sink`.
    ///
    /// Never materialises the whole file: a four-gigabyte video costs about one
    /// megabyte of memory to export.
    pub fn read_file<F>(&mut self, id: u64, mut sink: F) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        let node = self.index.get(id)?.clone();
        if node.is_dir() {
            return Err(VaultError::InvalidInput("That is a folder, not a file.".into()));
        }
        if node.nonce.len() != STREAM_NONCE_LEN || node.enc_len != chunked_ciphertext_len(node.size)
        {
            return Err(VaultError::Integrity);
        }

        let mut nonce = [0u8; STREAM_NONCE_LEN];
        nonce.copy_from_slice(&node.nonce);
        let mut dec =
            ChunkDecryptor::new(&self.content_key, &nonce, file_aad(&self.header_bytes, node.id));

        self.file
            .seek(SeekFrom::Start(node.offset))
            .map_err(|e| VaultError::from_io(&e, &self.path))?;

        let mut remaining = node.enc_len;
        // Only as large as this file actually needs, for the same reason the
        // write path sizes its buffer to the file.
        let mut buf = vec![0u8; remaining.min(CHUNK_CIPHERTEXT_SIZE as u64) as usize];
        loop {
            let take = remaining.min(CHUNK_CIPHERTEXT_SIZE as u64) as usize;
            self.file.read_exact(&mut buf[..take]).map_err(|_| VaultError::Truncated)?;
            if remaining <= CHUNK_CIPHERTEXT_SIZE as u64 {
                let pt = Zeroizing::new(dec.last(&buf[..take])?);
                sink(&pt)?;
                break;
            }
            let pt = Zeroizing::new(dec.next(&buf[..take])?);
            sink(&pt)?;
            remaining -= take as u64;
        }
        Ok(())
    }

    /// Decrypt one file into memory. Refuses anything above `limit`, so a
    /// preview can never be asked to load a multi-gigabyte video.
    pub fn read_file_to_vec(&mut self, id: u64, limit: usize) -> Result<Vec<u8>> {
        let size = self.index.get(id)?.size;
        if size as usize > limit {
            return Err(VaultError::InvalidInput(
                "That file is too large to open inside VaultDrive. Export it instead.".into(),
            ));
        }
        let mut out = Vec::with_capacity(size as usize);
        self.read_file(id, |chunk| {
            out.extend_from_slice(chunk);
            Ok(())
        })?;
        Ok(out)
    }

    /// Decrypt every file and discard the plaintext, purely to confirm that
    /// every authentication tag in the container still verifies.
    pub fn verify_all(&mut self, progress: &dyn ProgressSink) -> Result<()> {
        let files: Vec<(u64, u64, String)> = self
            .index
            .nodes
            .iter()
            .filter(|n| !n.is_dir())
            .map(|n| (n.id, n.size, n.name.clone()))
            .collect();
        let total_files = files.len() as u64;
        let total_bytes: u64 = files.iter().map(|(_, s, _)| *s).sum();

        let mut files_done = 0u64;
        let mut bytes_done = 0u64;
        for (id, _, name) in files {
            if progress.is_cancelled() {
                return Err(VaultError::Cancelled);
            }
            let mut local = 0u64;
            self.read_file(id, |chunk| {
                local += chunk.len() as u64;
                Ok(())
            })?;
            bytes_done += local;
            files_done += 1;
            progress.report(
                ProgressSnapshot { files_done, total_files, bytes_done, total_bytes },
                &name,
            );
        }
        Ok(())
    }

    // ------------------------------------------------------------ write paths

    /// Append one file's contents from a reader and register it in the index.
    /// Does not commit; the caller decides when to publish.
    fn append_from_reader<R: Read>(
        &mut self,
        parent: u64,
        name: &str,
        reader: &mut R,
        expected_size: u64,
        mtime: Option<i64>,
        progress: &dyn ProgressSink,
        on_bytes: &mut dyn FnMut(u64),
    ) -> Result<u64> {
        self.require_writable()?;
        validate_name(name)?;
        if self.index.find_child(parent, name).is_some() {
            return Err(VaultError::AlreadyExists { name: name.to_string() });
        }

        let id = self.index.reserve_file_id();
        let offset = self.superblock.blob_end;
        let aad = file_aad(&self.header_bytes, id);
        let key = *self.content_key;

        let mut stream = FileStream::begin(&mut self.file, &self.path, &key, id, offset, aad)?;
        let path = self.path.clone();
        pump_reader(
            &mut stream,
            &mut self.file,
            &path,
            reader,
            expected_size,
            name,
            progress,
            on_bytes,
        )?;
        let done = stream.finish(&mut self.file, &path)?;

        if done.pt_len != expected_size {
            return Err(VaultError::SourceChanged { name: name.to_string() });
        }
        self.index.add_file(
            done.id,
            parent,
            name,
            done.pt_len,
            done.offset,
            done.ct_len,
            done.nonce,
            mtime,
        )?;
        self.superblock.blob_end = done.offset + done.ct_len;
        Ok(done.id)
    }

    /// Import one file from disk into the vault and commit.
    pub fn import_file(
        &mut self,
        parent: u64,
        source: &Path,
        progress: &dyn ProgressSink,
    ) -> Result<u64> {
        let meta = std::fs::metadata(source).map_err(|e| VaultError::from_io(&e, source))?;
        if !meta.is_file() {
            return Err(VaultError::UnsupportedEntry {
                name: source
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            });
        }
        let name = source
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| VaultError::InvalidInput("That file has no name.".into()))?;
        let mtime = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64);

        let mut f = File::open(source).map_err(|e| VaultError::from_io(&e, source))?;
        let id = self.append_from_reader(
            parent,
            &name,
            &mut f,
            meta.len(),
            mtime,
            progress,
            &mut |_| {},
        )?;
        self.commit(0)?;
        Ok(id)
    }

    /// Import a whole folder tree into the vault and commit once at the end.
    pub fn import_folder(
        &mut self,
        parent: u64,
        source: &Path,
        progress: &dyn ProgressSink,
    ) -> Result<u64> {
        let (entries, summary) = crate::filesystem::scan_folder(source)?;
        let base = source
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| VaultError::InvalidInput("That folder has no name.".into()))?;

        let root = self.index.add_dir(parent, &base, None)?;
        let mut map: HashMap<Vec<String>, u64> = HashMap::new();
        map.insert(Vec::new(), root);

        let total_files = summary.files;
        let total_bytes = summary.total_bytes;
        let mut files_done = 0u64;
        let mut bytes_done = 0u64;

        for e in entries {
            if progress.is_cancelled() {
                return Err(VaultError::Cancelled);
            }
            let parent_key = e.relative[..e.relative.len() - 1].to_vec();
            let parent_id = *map.get(&parent_key).ok_or(VaultError::Integrity)?;
            let name = e.relative.last().cloned().unwrap_or_default();

            if e.is_dir {
                let id = self.index.add_dir(parent_id, &name, e.mtime)?;
                map.insert(e.relative.clone(), id);
            } else {
                let mut f = File::open(&e.path).map_err(|err| VaultError::from_io(&err, &e.path))?;
                self.append_from_reader(
                    parent_id,
                    &name,
                    &mut f,
                    e.size,
                    e.mtime,
                    progress,
                    &mut |n| bytes_done += n,
                )?;
                files_done += 1;
                progress.report(
                    ProgressSnapshot { files_done, total_files, bytes_done, total_bytes },
                    &name,
                );
            }
        }

        self.commit(0)?;
        Ok(root)
    }

    /// Write a file or folder out of the vault into `dest_dir`.
    ///
    /// Every name is re-validated on the way out. The index is authenticated,
    /// but its contents were chosen by whoever built the vault, so a vault
    /// someone shared with you could carry a name designed to escape
    /// `dest_dir`.
    pub fn export(
        &mut self,
        id: u64,
        dest_dir: &Path,
        progress: &dyn ProgressSink,
    ) -> Result<PathBuf> {
        let node = self.index.get(id)?.clone();
        let ids = if node.is_dir() { self.index.subtree(id) } else { vec![id] };

        let total_bytes: u64 = self
            .index
            .nodes
            .iter()
            .filter(|n| ids.contains(&n.id) && !n.is_dir())
            .map(|n| n.size)
            .sum();
        crate::filesystem::ensure_space(dest_dir, total_bytes)?;

        let root_out = dest_dir.join(validate_name(&node.name)?);

        // Folders first, shallowest first, so files always have a home.
        let mut dirs: Vec<u64> = ids
            .iter()
            .copied()
            .filter(|i| self.index.get(*i).map(|n| n.is_dir()).unwrap_or(false))
            .collect();
        dirs.sort_by_key(|i| self.index.path_of(*i).map(|p| p.matches('/').count()).unwrap_or(0));

        if node.is_dir() {
            std::fs::create_dir_all(&root_out).map_err(|e| VaultError::from_io(&e, &root_out))?;
        } else if let Some(parent) = root_out.parent() {
            std::fs::create_dir_all(parent).map_err(|e| VaultError::from_io(&e, parent))?;
        }
        for d in dirs {
            let path = self.safe_output_path(d, id, &root_out)?;
            std::fs::create_dir_all(&path).map_err(|e| VaultError::from_io(&e, &path))?;
        }

        let file_ids: Vec<(u64, String, Option<i64>)> = self
            .index
            .nodes
            .iter()
            .filter(|n| ids.contains(&n.id) && !n.is_dir())
            .map(|n| (n.id, n.name.clone(), n.mtime))
            .collect();
        let total_files = file_ids.len() as u64;

        let mut files_done = 0u64;
        let mut bytes_done = 0u64;
        for (fid, name, mtime) in file_ids {
            if progress.is_cancelled() {
                return Err(VaultError::Cancelled);
            }
            let out_path = self.safe_output_path(fid, id, &root_out)?;
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| VaultError::from_io(&e, parent))?;
            }

            // Decrypt into a sibling part-file and rename, so an interrupted
            // export never leaves a truncated file that looks complete.
            let tmp = PathBuf::from(format!("{}.vdpart", out_path.display()));
            {
                let mut out = File::create(&tmp).map_err(|e| VaultError::from_io(&e, &tmp))?;
                let mut local = 0u64;
                let written = self.read_file(fid, |chunk| {
                    out.write_all(chunk).map_err(|e| VaultError::from_io(&e, &tmp))?;
                    local += chunk.len() as u64;
                    Ok(())
                });
                match written {
                    Ok(()) => {
                        out.flush().map_err(|e| VaultError::from_io(&e, &tmp))?;
                        // Restore the modification time the file had when it
                        // was stored. Best effort: some filesystems refuse it,
                        // and a restored file with today's date is a far
                        // smaller problem than a failed export. Folders are
                        // left alone, because writing files into a folder
                        // updates its timestamp again anyway.
                        if let Some(secs) = mtime.filter(|s| *s >= 0) {
                            let when = std::time::UNIX_EPOCH
                                + std::time::Duration::from_secs(secs as u64);
                            let _ = out.set_modified(when);
                        }
                        bytes_done += local;
                    }
                    Err(e) => {
                        drop(out);
                        let _ = std::fs::remove_file(&tmp);
                        return Err(e);
                    }
                }
            }
            std::fs::rename(&tmp, &out_path).map_err(|e| VaultError::from_io(&e, &out_path))?;

            files_done += 1;
            progress.report(
                ProgressSnapshot { files_done, total_files, bytes_done, total_bytes },
                &name,
            );
        }

        tracing::info!(files = files_done, bytes = bytes_done, "export complete");
        Ok(root_out)
    }

    /// Build the on-disk path for `id` relative to the export root, refusing
    /// anything that would land outside it.
    fn safe_output_path(&self, id: u64, export_root_id: u64, root_out: &Path) -> Result<PathBuf> {
        let mut parts = Vec::new();
        let mut cur = id;
        let mut hops = 0usize;
        while cur != export_root_id && cur != ROOT_ID {
            let n = self.index.get(cur)?;
            parts.push(validate_name(&n.name)?);
            cur = n.parent;
            hops += 1;
            if hops > self.index.nodes.len() {
                return Err(VaultError::Integrity);
            }
        }
        parts.reverse();

        let mut out = root_out.to_path_buf();
        for p in parts {
            out.push(p);
        }
        // Belt and braces after the per-component checks.
        if !out.starts_with(root_out) {
            return Err(VaultError::Integrity);
        }
        Ok(out)
    }

    // ------------------------------------------------------------ index edits

    pub fn create_folder(&mut self, parent: u64, name: &str) -> Result<u64> {
        self.require_writable()?;
        let id = self.index.add_dir(parent, name, Some(now_secs()))?;
        self.commit(0)?;
        Ok(id)
    }

    pub fn rename(&mut self, id: u64, new_name: &str) -> Result<()> {
        self.require_writable()?;
        self.index.rename(id, new_name)?;
        self.commit(0)
    }

    pub fn move_entry(&mut self, id: u64, new_parent: u64) -> Result<()> {
        self.require_writable()?;
        self.index.move_node(id, new_parent)?;
        self.commit(0)
    }

    /// Remove an entry from the index.
    ///
    /// The ciphertext stays in the container as unreachable dead space until
    /// the vault is compacted. It is still encrypted, and nothing points at it,
    /// but it is still on the medium -- which is why [`OpenVault::compact`]
    /// exists and why the UI says so rather than implying a shred.
    pub fn delete(&mut self, id: u64) -> Result<()> {
        self.require_writable()?;
        let freed = self.index.remove_subtree(id)?;
        self.commit(freed)
    }

    /// Rewrite the container without dead space, atomically.
    ///
    /// Same password, same salt, same master key: the keywrap is copied
    /// verbatim. A new file is built beside the old one and renamed over it, so
    /// an interrupted compaction loses nothing.
    pub fn compact(self, progress: &dyn ProgressSink) -> Result<Self> {
        self.require_writable()?;

        let path = self.path.clone();
        let header = self.header;
        let master = MasterKey::from_bytes(*self.master.expose());
        let mut me = self;

        let mut builder = VaultBuilder::begin_reusing_key(
            &path,
            header,
            &master,
            &me.index.vault_name,
            me.index.created_at,
        )?;

        let all = me.index.subtree(ROOT_ID);
        let mut old_to_new: HashMap<u64, u64> = HashMap::new();
        old_to_new.insert(ROOT_ID, ROOT_ID);

        let mut dirs = Vec::new();
        let mut files = Vec::new();
        for id in all {
            if id == ROOT_ID {
                continue;
            }
            if me.index.get(id)?.is_dir() {
                dirs.push(id)
            } else {
                files.push(id)
            }
        }
        dirs.sort_by_key(|i| me.index.path_of(*i).map(|p| p.matches('/').count()).unwrap_or(0));

        for id in dirs {
            let n = me.index.get(id)?.clone();
            let new_parent = *old_to_new.get(&n.parent).ok_or(VaultError::Integrity)?;
            let new_id = builder.add_dir(new_parent, &n.name, n.mtime)?;
            old_to_new.insert(id, new_id);
        }

        let total_files = files.len() as u64;
        let total_bytes: u64 = files.iter().filter_map(|i| me.index.get(*i).ok()).map(|n| n.size).sum();
        let mut files_done = 0u64;
        let mut bytes_done = 0u64;

        for id in files {
            if progress.is_cancelled() {
                return Err(VaultError::Cancelled);
            }
            let n = me.index.get(id)?.clone();
            let new_parent = *old_to_new.get(&n.parent).ok_or(VaultError::Integrity)?;

            // Chunk straight from the old container into the new one. No
            // plaintext copy of the file exists anywhere at any point.
            let mut handle = builder.start_file(new_parent, &n.name, n.mtime)?;
            me.read_file(id, |chunk| builder.push_file_bytes(&mut handle, chunk))?;
            builder.finish_file(handle)?;

            bytes_done += n.size;
            files_done += 1;
            progress.report(
                ProgressSnapshot { files_done, total_files, bytes_done, total_bytes },
                &n.name,
            );
        }

        let reclaimed = me.superblock.dead_bytes;
        let temp = builder.finish_to_temp()?;

        // Close our handle on the old container before the atomic replace.
        drop(me);
        let rebuilt = temp.commit()?;
        tracing::info!(reclaimed, "vault compacted");

        Self::adopt(&rebuilt, header, &master)
    }
}

// ---------------------------------------------------------------------------
// VaultBuilder
// ---------------------------------------------------------------------------

/// A file being added to a vault under construction.
pub struct PendingFile {
    stream: FileStream,
    parent: u64,
    name: String,
    mtime: Option<i64>,
}

/// Builds a brand-new container in a temporary file and renames it into place.
pub struct VaultBuilder {
    temp: TempVaultFile,
    header_bytes: [u8; HEADER_LEN],
    index_key: Key32,
    superblock_key: Key32,
    content_key: Key32,
    index: VaultIndex,
    blob_end: u64,
}

impl VaultBuilder {
    /// Start a new vault protected by `password`.
    pub fn begin(
        final_path: &Path,
        password: &[u8],
        vault_name: &str,
        kdf_params: KdfParams,
    ) -> Result<Self> {
        let salt: [u8; 32] = random_array();
        let header = Header::new(salt, kdf_params);
        let master = MasterKey::generate();
        let header_bytes = header.encode();

        let kek = derive_kek(password, &salt, kdf_params)?;
        let keywrap = aead_seal(&kek, master.expose(), &keywrap_aad(&header_bytes))?;
        drop(kek);

        Self::begin_inner(final_path, header, header_bytes, &master, keywrap, vault_name, now_secs())
    }

    /// Start a replacement container for an existing vault, reusing its header
    /// and its already-wrapped master key. Only compaction uses this, and it is
    /// why compaction does not need the password.
    fn begin_reusing_key(
        final_path: &Path,
        header: Header,
        master: &MasterKey,
        vault_name: &str,
        created_at: i64,
    ) -> Result<Self> {
        // The keywrap is copied byte for byte: same header, same salt, same
        // master key, so the same password still opens the rebuilt container.
        // The master key itself has to be handed in, because recovering it from
        // the keywrap would require the password we deliberately do not hold.
        let mut src = File::open(final_path).map_err(|e| VaultError::from_io(&e, final_path))?;
        let mut keywrap = vec![0u8; KEYWRAP_LEN];
        src.seek(SeekFrom::Start(KEYWRAP_OFFSET)).map_err(|e| VaultError::from_io(&e, final_path))?;
        src.read_exact(&mut keywrap).map_err(|e| VaultError::from_io(&e, final_path))?;
        drop(src);

        let header_bytes = header.encode();
        Self::begin_inner(final_path, header, header_bytes, master, keywrap, vault_name, created_at)
    }

    fn begin_inner(
        final_path: &Path,
        header: Header,
        header_bytes: [u8; HEADER_LEN],
        master: &MasterKey,
        keywrap: Vec<u8>,
        vault_name: &str,
        created_at: i64,
    ) -> Result<Self> {
        let index_key = master.index_key(&header.salt);
        let superblock_key = master.superblock_key(&header.salt);
        let content_key = master.content_key(&header.salt);

        let mut temp = TempVaultFile::create(final_path)?;
        {
            let f = temp.file();
            f.write_all(&header_bytes).map_err(|e| VaultError::from_io(&e, final_path))?;
            f.write_all(&keywrap).map_err(|e| VaultError::from_io(&e, final_path))?;
            // Both superblock slots start as zeros, which authenticate as
            // nothing. Until the real one is written by `finish`, the file is
            // not a usable vault -- which is exactly the intent.
            f.write_all(&[0u8; SUPERBLOCK_SLOT_LEN * 2])
                .map_err(|e| VaultError::from_io(&e, final_path))?;
        }

        Ok(Self {
            temp,
            header_bytes,
            index_key,
            superblock_key,
            content_key,
            index: VaultIndex::new(vault_name, created_at),
            blob_end: DATA_START,
        })
    }

    pub fn add_dir(&mut self, parent: u64, name: &str, mtime: Option<i64>) -> Result<u64> {
        self.index.add_dir(parent, name, mtime)
    }

    pub fn index(&self) -> &VaultIndex {
        &self.index
    }

    /// Open a new file stream. Pair with [`VaultBuilder::push_file_bytes`] and
    /// [`VaultBuilder::finish_file`].
    pub fn start_file(&mut self, parent: u64, name: &str, mtime: Option<i64>) -> Result<PendingFile> {
        validate_name(name)?;
        if self.index.find_child(parent, name).is_some() {
            return Err(VaultError::AlreadyExists { name: name.to_string() });
        }
        let id = self.index.reserve_file_id();
        let offset = self.blob_end;
        let aad = file_aad(&self.header_bytes, id);
        let key = *self.content_key;
        let path = self.temp.path().to_path_buf();
        let stream = FileStream::begin(self.temp.file(), &path, &key, id, offset, aad)?;
        Ok(PendingFile { stream, parent, name: name.to_string(), mtime })
    }

    pub fn push_file_bytes(&mut self, pending: &mut PendingFile, data: &[u8]) -> Result<()> {
        let path = self.temp.path().to_path_buf();
        pending.stream.push(self.temp.file(), &path, data)
    }

    pub fn finish_file(&mut self, pending: PendingFile) -> Result<u64> {
        let path = self.temp.path().to_path_buf();
        let PendingFile { stream, parent, name, mtime } = pending;
        let done = stream.finish(self.temp.file(), &path)?;
        self.index.add_file(
            done.id,
            parent,
            &name,
            done.pt_len,
            done.offset,
            done.ct_len,
            done.nonce,
            mtime,
        )?;
        self.blob_end = done.offset + done.ct_len;
        Ok(done.id)
    }

    /// Add a file from a reader whose length is already known.
    #[allow(clippy::too_many_arguments)]
    pub fn add_file<R: Read>(
        &mut self,
        parent: u64,
        name: &str,
        reader: &mut R,
        expected_size: u64,
        mtime: Option<i64>,
        progress: &dyn ProgressSink,
        on_bytes: &mut dyn FnMut(u64),
    ) -> Result<u64> {
        let mut pending = self.start_file(parent, name, mtime)?;
        let path = self.temp.path().to_path_buf();
        pump_reader(
            &mut pending.stream,
            self.temp.file(),
            &path,
            reader,
            expected_size,
            name,
            progress,
            on_bytes,
        )?;
        if pending.stream.pt_len != expected_size {
            return Err(VaultError::SourceChanged { name: name.to_string() });
        }
        self.finish_file(pending)
    }

    /// Write the index and the first superblock, leaving the temporary file
    /// ready to be renamed into place.
    fn finish_to_temp(mut self) -> Result<TempVaultFile> {
        let json = Zeroizing::new(self.index.to_json()?);
        let blob = aead_seal(&self.index_key, &json, &index_aad(&self.header_bytes, 1))?;

        let index_offset = self.blob_end;
        let path = self.temp.path().to_path_buf();
        {
            let f = self.temp.file();
            f.seek(SeekFrom::Start(index_offset)).map_err(|e| VaultError::from_io(&e, &path))?;
            f.write_all(&blob).map_err(|e| VaultError::from_io(&e, &path))?;
        }

        let sb = Superblock {
            generation: 1,
            index_offset,
            index_len: blob.len() as u64,
            blob_end: index_offset + blob.len() as u64,
            dead_bytes: 0,
        };
        let sealed = sb.seal(&self.superblock_key, &self.header_bytes, 0)?;
        {
            let f = self.temp.file();
            f.seek(SeekFrom::Start(SUPERBLOCK_A_OFFSET)).map_err(|e| VaultError::from_io(&e, &path))?;
            f.write_all(&sealed).map_err(|e| VaultError::from_io(&e, &path))?;
        }
        Ok(self.temp)
    }

    /// Finish and atomically move the vault to its destination.
    pub fn finish(self) -> Result<PathBuf> {
        self.finish_to_temp()?.commit()
    }
}
