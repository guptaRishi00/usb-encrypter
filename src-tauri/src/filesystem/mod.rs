//! Platform filesystem access, behind one interface.
//!
//! Nothing above this module calls `std::fs` directly for anything
//! safety-critical: vault writes go through [`atomic`], source enumeration
//! through [`scan`], device questions through [`drives`], and destroying
//! originals through [`secure_delete`]. That is what keeps the Windows, macOS
//! and Linux behaviour in one place.

pub mod atomic;
pub mod drives;
pub mod scan;
pub mod secure_delete;

pub use drives::{available_space_for, ensure_space, list_drives, DriveInfo};
pub use scan::{scan_folder, ScanSummary, ScannedEntry};
