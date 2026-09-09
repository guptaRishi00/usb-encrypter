//! Filesystem failure modes: unplugged drives, full disks, read-only media,
//! locked files, cancellation.

mod common;

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use common::Fixture;
use vaultdrive_lib::error::VaultError;
use vaultdrive_lib::vault::{
    create_vault_from_folder, NoProgress, OpenVault, ProgressSink, ProgressSnapshot, VaultBuilder,
};

/// A sink that cancels once it has seen `after` files.
struct CancelAfter {
    after: u64,
    seen: AtomicU64,
}

impl ProgressSink for CancelAfter {
    fn report(&self, snapshot: ProgressSnapshot, _n: &str) {
        self.seen.store(snapshot.files_done, Ordering::SeqCst);
    }
    fn is_cancelled(&self) -> bool {
        self.seen.load(Ordering::SeqCst) >= self.after
    }
}

fn temp_files_in(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().contains("vdtmp"))
        .collect()
}

#[test]
fn a_destination_on_a_missing_drive_fails_without_writing_anything() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x")]);
    // A drive letter that is not mounted stands in for a removed USB stick.
    let dest = Path::new("Q:\\definitely-not-mounted\\V.vault");

    let err = create_vault_from_folder(
        &src,
        dest,
        b"pw",
        "V",
        common::fast_kdf(),
        &NoProgress,
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            VaultError::DeviceUnavailable
                | VaultError::PermissionDenied { .. }
                | VaultError::Io(_)
                | VaultError::SourceChanged { .. }
        ),
        "got {err:?}"
    );
    assert!(src.join("a.txt").exists(), "the source must be untouched");
}

#[test]
fn cancelling_a_creation_leaves_no_vault_and_no_temporary_files() {
    let fx = Fixture::new();
    let root = fx.path("many");
    fs::create_dir_all(&root).unwrap();
    for i in 0..40 {
        fs::write(root.join(format!("f{i}.bin")), vec![(i % 251) as u8; 20_000]).unwrap();
    }

    let dest = fx.path("Cancelled.vault");
    let err = create_vault_from_folder(
        &root,
        &dest,
        b"pw",
        "V",
        common::fast_kdf(),
        &CancelAfter { after: 3, seen: AtomicU64::new(0) },
    )
    .unwrap_err();

    assert!(matches!(err, VaultError::Cancelled));
    assert!(!dest.exists(), "a cancelled creation must not leave a vault");
    assert!(temp_files_in(fx.dir.path()).is_empty(), "temporary files were left behind");
    assert_eq!(fs::read_dir(&root).unwrap().count(), 40, "the source must be untouched");
}

#[test]
fn a_failed_creation_never_replaces_an_existing_vault() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"original")]);
    fx.create(&src, "V.vault", "pw").unwrap();
    let before = fs::read(fx.path("V.vault")).unwrap();

    // A second creation at the same path is refused outright.
    let src2 = fx.source("s2", &[("b.txt", b"different")]);
    let err = fx.create(&src2, "V.vault", "pw2").unwrap_err();
    assert!(matches!(err, VaultError::AlreadyExists { .. }));

    assert_eq!(fs::read(fx.path("V.vault")).unwrap(), before);
    let mut v = fx.unlock("V.vault", "pw").unwrap();
    let id = common::id_of(v.index(), "a.txt").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), b"original");
}

/// A reader that promises more bytes than it delivers: a file being truncated
/// by another program while the vault is being written.
struct ShortReader {
    data: Vec<u8>,
    pos: usize,
}

impl Read for ShortReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = out.len().min(self.data.len() - self.pos);
        out[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

#[test]
fn a_file_that_shrinks_while_being_read_is_reported_not_stored_short() {
    let fx = Fixture::new();
    let dest = fx.path("Short.vault");
    let mut builder =
        VaultBuilder::begin(&dest, b"pw", "V", common::fast_kdf()).unwrap();

    let mut reader = ShortReader { data: vec![1u8; 500], pos: 0 };
    let err = builder
        .add_file(
            vaultdrive_lib::vault::ROOT_ID,
            "shrinking.bin",
            &mut reader,
            5000, // the metadata said 5000 bytes; only 500 arrive
            None,
            &NoProgress,
            &mut |_| {},
        )
        .unwrap_err();

    assert!(matches!(err, VaultError::SourceChanged { .. }), "got {err:?}");
    drop(builder);
    assert!(!dest.exists());
}

#[test]
fn a_file_that_grows_while_being_read_is_reported() {
    let fx = Fixture::new();
    let dest = fx.path("Grown.vault");
    let mut builder = VaultBuilder::begin(&dest, b"pw", "V", common::fast_kdf()).unwrap();

    let mut reader = ShortReader { data: vec![1u8; 5000], pos: 0 };
    let err = builder
        .add_file(
            vaultdrive_lib::vault::ROOT_ID,
            "growing.bin",
            &mut reader,
            500, // the metadata said 500 bytes; 5000 are available
            None,
            &NoProgress,
            &mut |_| {},
        )
        .unwrap_err();

    assert!(matches!(err, VaultError::SourceChanged { .. }), "got {err:?}");
}

#[test]
fn a_read_only_vault_opens_for_browsing_but_refuses_edits() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"content")]);
    fx.create(&src, "RO.vault", "pw").unwrap();

    let path = fx.path("RO.vault");
    let mut perms = fs::metadata(&path).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(&path, perms).unwrap();

    let mut v = OpenVault::unlock(&path, b"pw").unwrap();
    assert!(v.is_read_only(), "a write-protected vault should open in read-only mode");

    let id = common::id_of(v.index(), "a.txt").unwrap();
    assert_eq!(v.read_file_to_vec(id, usize::MAX).unwrap(), b"content");

    let err = v.create_folder(vaultdrive_lib::vault::ROOT_ID, "New").unwrap_err();
    assert!(matches!(err, VaultError::PermissionDenied { .. }), "got {err:?}");

    // Leave the file deletable for the temp-dir cleanup.
    let mut perms = fs::metadata(&path).unwrap().permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    perms.set_readonly(false);
    fs::set_permissions(&path, perms).unwrap();
}

#[test]
fn a_locked_file_is_reported_as_locked_not_as_a_generic_failure() {
    // ERROR_SHARING_VIOLATION, what Windows returns when another program holds
    // a file open exclusively.
    let err = io::Error::from_raw_os_error(32);
    let mapped = VaultError::from_io(&err, Path::new("C:\\Users\\me\\report.docx"));
    assert!(matches!(mapped, VaultError::FileLocked { .. }), "got {mapped:?}");
    assert!(mapped.to_string().contains("report.docx"));
    assert!(
        !mapped.to_string().contains("C:\\Users"),
        "an error message must not carry the full path"
    );
}

#[test]
fn a_removed_device_is_reported_as_a_removed_device() {
    for code in [21, 55, 1617] {
        let err = io::Error::from_raw_os_error(code);
        let mapped = VaultError::from_io(&err, Path::new("E:\\vault\\My.vault"));
        assert!(
            matches!(mapped, VaultError::DeviceUnavailable),
            "os error {code} mapped to {mapped:?}"
        );
        assert!(mapped.to_string().contains("unplugged"));
    }
}

#[test]
fn a_full_disk_is_reported_as_a_full_disk() {
    for code in [39, 112] {
        let err = io::Error::from_raw_os_error(code);
        let mapped = VaultError::from_io(&err, Path::new("E:\\My.vault"));
        assert!(
            matches!(mapped, VaultError::InsufficientSpace { .. }),
            "os error {code} mapped to {mapped:?}"
        );
    }
}

#[test]
fn permission_denied_names_the_item_but_not_its_folder() {
    let err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
    let mapped = VaultError::from_io(&err, Path::new("C:\\Private\\Payroll\\secret.xlsx"));
    let text = mapped.to_string();
    assert!(text.contains("secret.xlsx"));
    assert!(!text.contains("Payroll"));
}

#[test]
fn an_impossible_amount_of_data_is_refused_before_the_write_starts() {
    let fx = Fixture::new();
    if vaultdrive_lib::filesystem::available_space_for(fx.dir.path()).is_none() {
        return; // the platform will not tell us; the write is allowed to try
    }
    let err = vaultdrive_lib::filesystem::ensure_space(fx.dir.path(), u64::MAX / 2).unwrap_err();
    assert!(matches!(err, VaultError::InsufficientSpace { .. }));
}

#[test]
fn symbolic_links_are_skipped_with_a_reason_rather_than_followed() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("real.txt", b"real")]);
    let outside = fx.path("outside.txt");
    fs::write(&outside, b"must not be swallowed").unwrap();

    // Creating a symlink needs Developer Mode or elevation on Windows; if it is
    // not permitted here there is nothing to assert.
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(&outside, src.join("link.txt")).is_ok();
    #[cfg(not(windows))]
    let made = std::os::unix::fs::symlink(&outside, src.join("link.txt")).is_ok();

    let report = fx.create(&src, "V.vault", "pw").unwrap();
    assert_eq!(report.files, 1, "only the real file should be stored");
    if made {
        assert!(
            report.skipped.iter().any(|s| s.contains("link.txt")),
            "the skipped link must be reported: {:?}",
            report.skipped
        );
    }
}

#[test]
fn an_interrupted_export_leaves_no_half_written_file_in_place() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    let out = fx.path("out");
    fs::create_dir_all(&out).unwrap();
    let mut v = fx.unlock("V.vault", "pw").unwrap();

    let err = v
        .export(
            vaultdrive_lib::vault::ROOT_ID,
            &out,
            &CancelAfter { after: 1, seen: AtomicU64::new(0) },
        )
        .unwrap_err();
    assert!(matches!(err, VaultError::Cancelled));

    let parts: Vec<_> = walkdir::WalkDir::new(&out)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name().to_string_lossy().ends_with(".vdpart"))
        .collect();
    assert!(parts.is_empty(), "a cancelled export left part files: {parts:?}");
}

#[test]
fn removing_the_source_folder_is_a_separate_explicit_step() {
    let fx = Fixture::new();
    let src = fx.source("s", &[("a.txt", b"x"), ("sub/b.txt", b"y")]);
    fx.create(&src, "V.vault", "pw").unwrap();

    // Creating a vault never touches the original.
    assert!(src.join("a.txt").exists());
    assert!(src.join("sub/b.txt").exists());

    let report = vaultdrive_lib::filesystem::secure_delete::remove_source_tree(&src).unwrap();
    assert_eq!(report.files_removed, 2);
    assert!(!src.exists());
}
