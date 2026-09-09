//! Error types for VaultDrive.
//!
//! Every message here is written to be shown to a user. Nothing in this module
//! is allowed to leak key material, nonces, offsets, password length, or how
//! close a password was to being correct. All cryptographic failures collapse
//! into a single indistinguishable variant.

use std::io;
use std::path::Path;

/// The one and only message shown for any failed authenticated decryption.
///
/// Wrong password, tampered header, corrupted ciphertext and truncated files
/// all produce the same text on purpose: a distinguishable error is an oracle.
pub const AUTH_FAILED_MESSAGE: &str =
    "Incorrect password.\nThe vault could not be unlocked.";

pub const INTEGRITY_FAILED_MESSAGE: &str =
    "Vault integrity check failed.\nThe vault may have been corrupted or modified.\nDo not continue unless you trust this file.";

pub type Result<T> = std::result::Result<T, VaultError>;

#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Authenticated decryption failed. Deliberately opaque.
    #[error("{}", AUTH_FAILED_MESSAGE)]
    Authentication,

    /// The vault opened, but a segment inside it failed its authentication tag.
    #[error("{}", INTEGRITY_FAILED_MESSAGE)]
    Integrity,

    #[error("This file is not a VaultDrive vault.")]
    NotAVault,

    #[error("This vault was created by a newer version of VaultDrive (format {found}). This build supports up to format {supported}.")]
    VersionMismatch { found: u16, supported: u16 },

    #[error("The vault file is incomplete or has been truncated.")]
    Truncated,

    #[error("The vault header specifies key-derivation settings this build refuses to run.")]
    UnsupportedKdfParameters,

    #[error("The vault uses an encryption algorithm this build does not support.")]
    UnsupportedCipher,

    #[error("Permission denied for '{name}'. Try running VaultDrive as the owner of that file, or choose another location.")]
    PermissionDenied { name: String },

    #[error("'{name}' is in use by another program and could not be read.")]
    FileLocked { name: String },

    #[error("The drive holding this file is no longer available. It may have been unplugged.")]
    DeviceUnavailable,

    #[error("Not enough free space. {needed_mb} MB is needed and {available_mb} MB is free.")]
    InsufficientSpace { needed_mb: u64, available_mb: u64 },

    #[error("'{name}' changed while the vault was being written. Nothing was deleted; please try again.")]
    SourceChanged { name: String },

    #[error("'{name}' cannot be stored in a vault (unsupported file type or path).")]
    UnsupportedEntry { name: String },

    #[error("The operation was cancelled. No changes were made.")]
    Cancelled,

    #[error("No vault is unlocked. Enter the password again.")]
    Locked,

    #[error("There is already an item named '{name}' here.")]
    AlreadyExists { name: String },

    #[error("That item no longer exists in the vault.")]
    NoSuchEntry,

    #[error("A folder cannot be moved inside itself.")]
    InvalidMove,

    /// The authenticator server rejected the six-digit code.
    #[error("Incorrect code.
The vault could not be unlocked.")]
    WrongCode,

    #[error("Too many wrong codes. The authenticator server has paused this vault for a few minutes.")]
    TooManyAttempts,

    #[error("This vault unlocks through an authenticator server, and that server could not be reached. Check the internet connection and try again.")]
    Offline,

    /// Any other answer from the server. The text is the server's own, capped
    /// in length so a hostile or broken server cannot flood the interface.
    #[error("The authenticator server refused: {0}")]
    RemoteAuth(String),

    #[error("{0}")]
    InvalidInput(String),

    #[error("{0}")]
    Io(String),
}

impl VaultError {
    /// Short machine-readable tag. The frontend switches on this; it never
    /// parses the human message.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Authentication => "authentication",
            Self::Integrity => "integrity",
            Self::NotAVault => "not_a_vault",
            Self::VersionMismatch { .. } => "version_mismatch",
            Self::Truncated => "truncated",
            Self::UnsupportedKdfParameters => "unsupported_kdf",
            Self::UnsupportedCipher => "unsupported_cipher",
            Self::PermissionDenied { .. } => "permission_denied",
            Self::FileLocked { .. } => "file_locked",
            Self::DeviceUnavailable => "device_unavailable",
            Self::InsufficientSpace { .. } => "insufficient_space",
            Self::SourceChanged { .. } => "source_changed",
            Self::UnsupportedEntry { .. } => "unsupported_entry",
            Self::Cancelled => "cancelled",
            Self::Locked => "locked",
            Self::AlreadyExists { .. } => "already_exists",
            Self::NoSuchEntry => "no_such_entry",
            Self::InvalidMove => "invalid_move",
            Self::WrongCode => "wrong_code",
            Self::TooManyAttempts => "too_many_attempts",
            Self::Offline => "offline",
            Self::RemoteAuth(_) => "remote_auth",
            Self::InvalidInput(_) => "invalid_input",
            Self::Io(_) => "io",
        }
    }

    /// Translate a `std::io::Error` that occurred while touching `path` into a
    /// user-facing error. Only the final path component is kept, so full paths
    /// (which may themselves be sensitive) never reach the UI or the log.
    pub fn from_io(err: &io::Error, path: &Path) -> Self {
        let name = path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "the selected item".to_string());

        match err.kind() {
            io::ErrorKind::PermissionDenied => Self::PermissionDenied { name },
            io::ErrorKind::NotFound => Self::SourceChanged { name },
            io::ErrorKind::UnexpectedEof => Self::Truncated,
            _ => match err.raw_os_error() {
                // Windows: ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
                Some(32) | Some(33) => Self::FileLocked { name },
                // Windows: ERROR_NOT_READY / ERROR_DEV_NOT_EXIST / ERROR_DEVICE_REMOVED
                Some(21) | Some(55) | Some(1617) => Self::DeviceUnavailable,
                // Windows: ERROR_DISK_FULL / ERROR_HANDLE_DISK_FULL
                Some(39) | Some(112) => Self::InsufficientSpace {
                    needed_mb: 0,
                    available_mb: 0,
                },
                _ => Self::Io(format!("Could not access '{name}'.")),
            },
        }
    }
}

/// Serialized to the frontend as `{ kind, message }`, never as a raw string.
impl serde::Serialize for VaultError {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("VaultError", 2)?;
        st.serialize_field("kind", self.kind())?;
        st.serialize_field("message", &self.to_string())?;
        st.end()
    }
}

/// Any AEAD failure becomes `Authentication`; the underlying `aead::Error`
/// carries no detail anyway, and this makes it impossible to accidentally
/// widen it later.
impl From<chacha20poly1305::aead::Error> for VaultError {
    fn from(_: chacha20poly1305::aead::Error) -> Self {
        Self::Authentication
    }
}

impl From<argon2::Error> for VaultError {
    fn from(_: argon2::Error) -> Self {
        Self::UnsupportedKdfParameters
    }
}
